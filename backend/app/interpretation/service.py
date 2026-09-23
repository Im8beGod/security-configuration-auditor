from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.audit.service import validate_snapshot_evidence
from app.db.models import (
    Artifact,
    ArtifactEvidenceType,
    Audit,
    Device,
    FactState,
    FactValidationStatus,
    InterpretationConfidence,
    InterpretationMethod,
    SecurityFact,
    Snapshot,
    SnapshotStatus,
    UnresolvedBlock,
    KnowledgePackRecord,
    KnowledgePackVersionRecord,
    MappingVersion,
    MappingStatus,
)
from app.ingestion.storage import ArtifactStorage, ArtifactStorageError
from app.interpretation.exceptions import (
    InterpretationInfrastructureError,
    InterpretationNotFoundError,
    InterpretationValidationError,
)
from app.interpretation.extractors import EXTRACTORS, ExtractionOutcome
from app.interpretation.knowledge_pack import (
    DeclarativeMapping,
    KnowledgePack,
    KnowledgePackRegistry,
    NegationBehavior,
    NodeMatcher,
    validate_knowledge_pack,
)
from app.interpretation.models import (
    ArtifactInterpretationDiagnostic,
    AuditInterpretationResult,
    InterpretationContext,
    InterpretationDiagnostic,
    InterpretationMetrics,
    InterpretationResult,
)
from app.interpretation.scopes import SCOPE_RESOLVER_TYPES, SCOPE_RESOLVERS
from app.knowledge_packs.cisco_iosxe_17 import (
    CISCO_IOS_XE_17_KNOWLEDGE_PACK,
    CISCO_IOS_XE_17_KNOWLEDGE_PACK_V1,
    CISCO_IOS_XE_17_KNOWLEDGE_PACK_V1_1,
    CISCO_IOS_XE_17_KNOWLEDGE_PACK_V1_2,
)
from app.knowledge_packs.fortios_7 import (
    FORTIOS_7_KNOWLEDGE_PACK,
    FORTIOS_7_KNOWLEDGE_PACK_V1,
    FORTIOS_7_KNOWLEDGE_PACK_V1_1,
    FORTIOS_7_KNOWLEDGE_PACK_V1_2,
)
from app.knowledge_packs.juniper_junos_18 import (
    JUNIPER_JUNOS_18_KNOWLEDGE_PACK,
    JUNIPER_JUNOS_18_KNOWLEDGE_PACK_V1,
    JUNIPER_JUNOS_18_KNOWLEDGE_PACK_V1_1,
)
from app.knowledge_packs.arista_eos_4 import ARISTA_EOS_4_KNOWLEDGE_PACK, ARISTA_EOS_4_KNOWLEDGE_PACK_V1
from app.knowledge_packs.generic_cli import GENERIC_CLI_KNOWLEDGE_PACK, GENERIC_JSON_KNOWLEDGE_PACK, GENERIC_XML_KNOWLEDGE_PACK
from app.parsing import ConfigNode, ConfigNodeKind, ParseStatus, StructuralIR, parse_artifact
from app.parsing.readers.xml_tree import XmlStructuralIR, XmlNode
from app.parsing.readers.json_tree import JsonStructuralIR, JsonNode
from app.parsing.exceptions import (
    ArtifactNotParseableError,
    ParsingInfrastructureError,
    StructuralReaderNotFoundError,
)
from app.profile_resolution import PROFILE_REGISTRY
from app.profile_resolution.registry import ProfileManifest
from app.profile_resolution.runtime import profile_for
from app.security_model import (
    EvidenceRef,
    FieldRegistryValidationError,
    ScopeRef,
    SecurityFactDraft,
    TypedValue,
    TypedValueType,
    get_field,
    validate_field_value_scope,
)
from app.training.dsl import MappingDefinition, ValidationNode, extract as extract_training, matches as matches_training, matches_json, matches_xml, xml_match_has_unsupported_qualifier


KNOWLEDGE_PACK_REGISTRY = KnowledgePackRegistry(
    (
        CISCO_IOS_XE_17_KNOWLEDGE_PACK_V1,
        CISCO_IOS_XE_17_KNOWLEDGE_PACK_V1_1,
        CISCO_IOS_XE_17_KNOWLEDGE_PACK_V1_2,
        CISCO_IOS_XE_17_KNOWLEDGE_PACK,
        FORTIOS_7_KNOWLEDGE_PACK_V1,
        FORTIOS_7_KNOWLEDGE_PACK_V1_1,
        FORTIOS_7_KNOWLEDGE_PACK_V1_2,
        FORTIOS_7_KNOWLEDGE_PACK,
        JUNIPER_JUNOS_18_KNOWLEDGE_PACK_V1,
        JUNIPER_JUNOS_18_KNOWLEDGE_PACK_V1_1,
        JUNIPER_JUNOS_18_KNOWLEDGE_PACK,
        ARISTA_EOS_4_KNOWLEDGE_PACK_V1,
        ARISTA_EOS_4_KNOWLEDGE_PACK,
        GENERIC_CLI_KNOWLEDGE_PACK,
        GENERIC_XML_KNOWLEDGE_PACK,
        GENERIC_JSON_KNOWLEDGE_PACK,
    ),
    active_by_profile={
        CISCO_IOS_XE_17_KNOWLEDGE_PACK.profile_version_id:
            CISCO_IOS_XE_17_KNOWLEDGE_PACK.knowledge_pack_version_id,
        FORTIOS_7_KNOWLEDGE_PACK.profile_version_id:
            FORTIOS_7_KNOWLEDGE_PACK.knowledge_pack_version_id,
        JUNIPER_JUNOS_18_KNOWLEDGE_PACK.profile_version_id:
            JUNIPER_JUNOS_18_KNOWLEDGE_PACK.knowledge_pack_version_id,
        ARISTA_EOS_4_KNOWLEDGE_PACK.profile_version_id:
            ARISTA_EOS_4_KNOWLEDGE_PACK.knowledge_pack_version_id,
        GENERIC_CLI_KNOWLEDGE_PACK.profile_version_id:
            GENERIC_CLI_KNOWLEDGE_PACK.knowledge_pack_version_id,
        GENERIC_XML_KNOWLEDGE_PACK.profile_version_id:
            GENERIC_XML_KNOWLEDGE_PACK.knowledge_pack_version_id,
        GENERIC_JSON_KNOWLEDGE_PACK.profile_version_id:
            GENERIC_JSON_KNOWLEDGE_PACK.knowledge_pack_version_id,
    },
)


def load_validated_knowledge_pack(profile_version_id: str) -> KnowledgePack:
    profile = PROFILE_REGISTRY.get(profile_version_id)
    pack = KNOWLEDGE_PACK_REGISTRY.active_for_profile(profile_version_id)
    if (
        profile is None
        or pack is None
        or profile.knowledge_pack_name != f"{pack.name}@{pack.version}"
    ):
        raise InterpretationValidationError(
            "knowledge_pack_unavailable", "No compatible knowledge pack is available"
        )
    try:
        return validate_knowledge_pack(
            pack,
            expected_profile_id=profile.profile_id,
            expected_profile_version_id=profile.profile_version_id,
            allowed_extractors=frozenset(EXTRACTORS),
            scope_resolver_types=SCOPE_RESOLVER_TYPES,
        )
    except ValueError:
        raise InterpretationValidationError(
            "knowledge_pack_invalid", "Knowledge pack validation failed"
        ) from None


def load_validated_knowledge_pack_by_version(
    knowledge_pack_version_id: UUID,
) -> KnowledgePack:
    """Load an immutable historical pack by its exact pinned identity."""
    pack = KNOWLEDGE_PACK_REGISTRY.get(knowledge_pack_version_id)
    if pack is None:
        raise InterpretationValidationError(
            "knowledge_pack_unavailable", "No compatible knowledge pack is available"
        )
    profile = PROFILE_REGISTRY.get(pack.profile_version_id)
    if profile is None:
        raise InterpretationValidationError(
            "knowledge_pack_unavailable", "No compatible knowledge pack is available"
        )
    try:
        return validate_knowledge_pack(
            pack,
            expected_profile_id=profile.profile_id,
            expected_profile_version_id=profile.profile_version_id,
            allowed_extractors=frozenset(EXTRACTORS),
            scope_resolver_types=SCOPE_RESOLVER_TYPES,
        )
    except ValueError:
        raise InterpretationValidationError(
            "knowledge_pack_invalid", "Knowledge pack validation failed"
        ) from None


def runtime_baseline_knowledge_pack(profile: ProfileManifest) -> KnowledgePack:
    identity = uuid5(NAMESPACE_URL, f"runtime-profile:{profile.profile_version_id}")
    return KnowledgePack(identity, identity, "Runtime declarative baseline", "1.0.0", "1.0.0", profile.profile_id, profile.profile_version_id, ())


def load_published_knowledge_pack(
    db: Session, organization_id: UUID, knowledge_pack_version_id: UUID, profile_version_id: str,
    *, profile: ProfileManifest | None = None,
) -> KnowledgePack:
    """Load an immutable, administrator-published Step 11 pack through the bounded DSL."""
    version = db.scalar(select(KnowledgePackVersionRecord).where(
        KnowledgePackVersionRecord.knowledge_pack_version_id == knowledge_pack_version_id,
        KnowledgePackVersionRecord.organization_id == organization_id,
    ))
    if version is None:
        return load_validated_knowledge_pack_by_version(knowledge_pack_version_id)
    record = db.get(KnowledgePackRecord, version.knowledge_pack_id)
    profile = profile or profile_for(db, organization_id, profile_version_id)
    if record is None or profile is None or not version.mapping_version_ids:
        raise InterpretationValidationError("knowledge_pack_unavailable", "No compatible knowledge pack is available")
    try:
        ids = [UUID(value) for value in version.mapping_version_ids]
    except (TypeError, ValueError):
        raise InterpretationValidationError("knowledge_pack_invalid", "Knowledge pack validation failed") from None
    rows = list(db.scalars(select(MappingVersion).where(
        MappingVersion.mapping_version_id.in_(ids), MappingVersion.organization_id == organization_id
    )))
    if len(rows) != len(ids):
        raise InterpretationValidationError("knowledge_pack_invalid", "Knowledge pack validation failed")
    # Step 11 publications add reviewed mappings to the profile's sealed baseline;
    # they never silently discard existing canonical interpretation coverage.
    baseline = load_validated_knowledge_pack(profile_version_id) if PROFILE_REGISTRY.get(profile_version_id) else runtime_baseline_knowledge_pack(profile)
    mappings = (*baseline.mappings, *tuple(_training_mapping(row, profile_version_id) for row in sorted(rows, key=lambda row: str(row.mapping_version_id))))
    pack = KnowledgePack(record.knowledge_pack_id, version.knowledge_pack_version_id, record.name,
        str(version.version), version.schema_version, profile.profile_id, profile_version_id, mappings)
    try:
        return validate_knowledge_pack(pack, expected_profile_id=profile.profile_id,
            expected_profile_version_id=profile_version_id, allowed_extractors=frozenset(EXTRACTORS), scope_resolver_types=SCOPE_RESOLVER_TYPES)
    except ValueError:
        raise InterpretationValidationError("knowledge_pack_invalid", "Knowledge pack validation failed") from None


def load_active_published_knowledge_pack(
    db: Session, organization_id: UUID, profile_version_id: str, *, profile: ProfileManifest | None = None,
) -> KnowledgePack | None:
    """Load the newest compatible published pack for a fresh audit."""
    profile = profile or profile_for(db, organization_id, profile_version_id)
    if profile is None:
        return None
    versions = list(db.scalars(select(KnowledgePackVersionRecord).where(
        KnowledgePackVersionRecord.organization_id == organization_id,
    ).order_by(
        KnowledgePackVersionRecord.published_at.desc(),
        KnowledgePackVersionRecord.version.desc(),
        KnowledgePackVersionRecord.knowledge_pack_version_id.desc(),
    )))
    latest_by_pack: dict[UUID, KnowledgePackVersionRecord] = {}
    for version in versions:
        latest_by_pack.setdefault(version.knowledge_pack_id, version)
    candidates: list[KnowledgePackVersionRecord] = []
    for version in latest_by_pack.values():
        if not version.mapping_version_ids:
            continue
        try:
            mapping_ids = [UUID(value) for value in version.mapping_version_ids]
        except (TypeError, ValueError):
            continue
        mappings = list(db.scalars(select(MappingVersion).where(
            MappingVersion.mapping_version_id.in_(mapping_ids),
            MappingVersion.organization_id == organization_id,
        )))
        if len(mappings) != len(mapping_ids) or any(
            mapping.status != MappingStatus.PUBLISHED
            or mapping.approved_by is None
            or mapping.published_at is None
            or profile_version_id not in mapping.profile_applicability.get("profile_version_ids", [])
            for mapping in mappings
        ):
            continue
        candidates.append(version)
    if not candidates:
        return None
    if len(candidates) > 1:
        return None
    selected = max(
        candidates,
        key=lambda item: (
            item.published_at,
            item.version,
            str(item.knowledge_pack_version_id),
        ),
    )
    return load_published_knowledge_pack(
        db, organization_id, selected.knowledge_pack_version_id, profile_version_id, profile=profile
    )


def _training_mapping(row: MappingVersion, profile_version_id: str) -> DeclarativeMapping:
    definition = MappingDefinition.model_validate({
        "profile_applicability": row.profile_applicability, "structural_match": row.structural_match,
        "target_field_id": row.target_field_id, "value_extraction": row.value_extraction,
        "unit_conversion": row.unit_conversion, "scope_resolution": row.scope_resolution,
        "negation_behavior": row.negation_behavior, "removal_behavior": row.removal_behavior,
        "default_behavior": row.default_behavior, "examples": row.examples,
    })
    if profile_version_id not in definition.profile_applicability.profile_version_ids or definition.scope_resolution.strategy not in SCOPE_RESOLVERS:
        raise InterpretationValidationError("knowledge_pack_incompatible", "Knowledge Pack is incompatible with this audit")
    behavior = NegationBehavior(definition.negation_behavior.operation) if definition.negation_behavior.operation in {item.value for item in NegationBehavior} else NegationBehavior.UNSUPPORTED
    return DeclarativeMapping(row.mapping_id, row.mapping_version_id, row.target_field_id,
        NodeMatcher(command=definition.structural_match.command, parent_command=definition.structural_match.parent_command),
        "training_dsl", definition.scope_resolution.strategy,
        frozenset({TypedValueType(definition.value_extraction.output_type)}), behavior,
        training_definition=definition.model_dump(mode="json"))


def interpret_structural_ir(
    ir: StructuralIR,
    context: InterpretationContext,
    *,
    profile_version_id: str,
    knowledge_pack: KnowledgePack | None = None,
    profile: ProfileManifest | None = None,
) -> InterpretationResult:
    profile = profile or PROFILE_REGISTRY.get(profile_version_id)
    if profile is None or ir.reader_id != profile.structural_reader_name:
        raise InterpretationValidationError(
            "profile_ir_incompatible", "Resolved profile is incompatible with Structural IR"
        )
    if (
        ir.source.snapshot_id != context.snapshot_id
        or any(node.artifact_id != ir.source.artifact_id for node in ir.nodes)
    ):
        raise InterpretationValidationError(
            "ir_provenance_invalid", "Structural IR provenance is inconsistent"
        )
    pack = knowledge_pack or load_validated_knowledge_pack(profile_version_id)
    try:
        validate_knowledge_pack(
            pack,
            expected_profile_id=profile.profile_id,
            expected_profile_version_id=profile.profile_version_id,
            allowed_extractors=frozenset(EXTRACTORS),
            scope_resolver_types=SCOPE_RESOLVER_TYPES,
        )
    except ValueError:
        raise InterpretationValidationError(
            "knowledge_pack_invalid", "Knowledge pack validation failed"
        ) from None

    statements = [node for node in ir.nodes if node.kind == ConfigNodeKind.STATEMENT]
    evidence_nodes = [
        node for node in ir.nodes
        if node.kind in {ConfigNodeKind.STATEMENT, ConfigNodeKind.OPAQUE}
    ]
    facts: list[SecurityFactDraft] = []
    diagnostics: list[InterpretationDiagnostic] = []
    diagnostic_keys: set[tuple[str, str | None, UUID | None]] = set()
    matched_node_ids: set[str] = set()
    consumed_context_node_ids: set[str] = set()

    for node in statements:
        for mapping in pack.mappings:
            if not _matches(mapping, node, ir):
                continue
            if node.negated:
                fact = _build_negated_fact(
                    context=context,
                    ir=ir,
                    pack=pack,
                    mapping=mapping,
                    node=node,
                )
                if fact is None:
                    _add_diagnostic(
                        diagnostics, diagnostic_keys,
                        "unsupported_negation", node.node_id, mapping.mapping_id,
                    )
                else:
                    facts.append(fact)
                    matched_node_ids.add(node.node_id)
                continue
            if node.parse_status != ParseStatus.PARSED:
                _add_diagnostic(
                    diagnostics, diagnostic_keys,
                    "uncertain_structural_node", node.node_id, mapping.mapping_id,
                )
                continue
            extraction = _extract_mapping(mapping, node, ir)
            if extraction.value is None:
                if extraction.diagnostic_code is not None:
                    _add_diagnostic(
                        diagnostics, diagnostic_keys,
                        extraction.diagnostic_code, node.node_id, mapping.mapping_id,
                    )
                continue
            scope_outcome = SCOPE_RESOLVERS[mapping.scope_resolver](node, ir)
            if scope_outcome.scope is None:
                _add_diagnostic(
                    diagnostics, diagnostic_keys,
                    scope_outcome.diagnostic_code or "scope_unresolved",
                    node.node_id,
                    mapping.mapping_id,
                )
                continue
            try:
                validate_field_value_scope(
                    mapping.field_id, extraction.value, scope_outcome.scope
                )
            except FieldRegistryValidationError:
                raise InterpretationValidationError(
                    "mapping_output_invalid", "Validated mapping produced invalid output"
                ) from None

            source_nodes = [node]
            if scope_outcome.context_node is not None:
                source_nodes.append(scope_outcome.context_node)
            fact = _build_fact(
                context=context,
                ir=ir,
                pack=pack,
                mapping=mapping,
                value=extraction.value,
                scope=scope_outcome.scope,
                source_nodes=source_nodes,
            )
            facts.append(fact)
            matched_node_ids.add(node.node_id)
            if scope_outcome.context_node is not None:
                # A structural scope/container consumed to establish this fact
                # is evidence context, not independent unresolved syntax.
                consumed_context_node_ids.add(scope_outcome.context_node.node_id)

    metrics = InterpretationMetrics(
        nodes_considered=len(evidence_nodes),
        nodes_matched=len(matched_node_ids),
        mappings_applied=len(facts),
        facts_produced=len(facts),
        unmatched_nodes=len(evidence_nodes) - len(matched_node_ids),
        unsupported_cases=len(diagnostics),
    )
    return InterpretationResult(
        facts=tuple(facts), diagnostics=tuple(diagnostics), metrics=metrics,
        unresolved_node_ids=tuple(
            node.node_id for node in evidence_nodes
            if node.node_id not in matched_node_ids | consumed_context_node_ids
        ),
    )


def interpret_xml_structural_ir(
    ir: XmlStructuralIR,
    context: InterpretationContext,
    *,
    profile_version_id: str,
    knowledge_pack: KnowledgePack | None = None,
    profile: ProfileManifest | None = None,
) -> InterpretationResult:
    """Interpret XML using the same declarative mapping contract as CLI evidence."""
    profile = profile or PROFILE_REGISTRY.get(profile_version_id)
    if profile is None or ir.reader_id != profile.structural_reader_name:
        raise InterpretationValidationError("profile_ir_incompatible", "Resolved profile is incompatible with XML IR")
    if ir.source.snapshot_id != context.snapshot_id or any(node.source.artifact_id != ir.source.artifact_id for node in ir.nodes):
        raise InterpretationValidationError("ir_provenance_invalid", "XML IR provenance is inconsistent")
    pack = knowledge_pack or load_validated_knowledge_pack(profile_version_id)
    validate_knowledge_pack(pack, expected_profile_id=profile.profile_id, expected_profile_version_id=profile.profile_version_id, allowed_extractors=frozenset(EXTRACTORS), scope_resolver_types=SCOPE_RESOLVER_TYPES)
    facts: list[SecurityFactDraft] = []
    diagnostics: list[InterpretationDiagnostic] = []
    matched: set[str] = set()
    for mapping in pack.mappings:
        definition_payload = mapping.training_definition
        if not definition_payload or definition_payload.get("structural_match", {}).get("operation") != "xml_path":
            continue
        definition = MappingDefinition.model_validate(definition_payload)
        for node, captures in matches_xml(definition, ir):
            if xml_match_has_unsupported_qualifier(definition, ir, node):
                diagnostics.append(InterpretationDiagnostic("xml_scope_unsupported", node.node_id, mapping.mapping_id))
                continue
            try:
                value = extract_training(definition, captures)
                value_type = TypedValueType(definition.value_extraction.output_type)
                typed = TypedValue(value_type, value, unit="seconds" if value_type is TypedValueType.DURATION else None)
                scope = ScopeRef(type=definition.scope_resolution.strategy, key="device", attributes={})
                validate_field_value_scope(definition.target_field_id, typed, scope)
            except (KeyError, TypeError, ValueError, FieldRegistryValidationError):
                diagnostics.append(InterpretationDiagnostic("xml_mapping_output_invalid", node.node_id, mapping.mapping_id))
                continue
            facts.append(_build_xml_fact(context=context, ir=ir, pack=pack, mapping=mapping, value=typed, scope=scope, node=node))
            matched.add(node.node_id)
    parent_ids = {node.parent_id for node in ir.nodes if node.parent_id is not None}
    leaves = tuple(node for node in ir.nodes if node.node_id not in parent_ids)
    statements = len(leaves)
    return InterpretationResult(
        facts=tuple(facts), diagnostics=tuple(diagnostics),
        metrics=InterpretationMetrics(statements, len(matched), len(facts), len(facts), statements - len(matched), len(diagnostics)),
        unresolved_node_ids=tuple(node.node_id for node in leaves if node.node_id not in matched),
    )


def interpret_json_structural_ir(
    ir: JsonStructuralIR,
    context: InterpretationContext,
    *,
    profile_version_id: str,
    knowledge_pack: KnowledgePack | None = None,
    profile: ProfileManifest | None = None,
) -> InterpretationResult:
    """Interpret exact bounded JSON paths using administrator-published mappings."""
    profile = profile or PROFILE_REGISTRY.get(profile_version_id)
    if profile is None or ir.reader_id != profile.structural_reader_name:
        raise InterpretationValidationError("profile_ir_incompatible", "Resolved profile is incompatible with JSON IR")
    if ir.source.snapshot_id != context.snapshot_id or any(node.source.artifact_id != ir.source.artifact_id for node in ir.nodes):
        raise InterpretationValidationError("ir_provenance_invalid", "JSON IR provenance is inconsistent")
    pack = knowledge_pack or load_validated_knowledge_pack(profile_version_id)
    validate_knowledge_pack(pack, expected_profile_id=profile.profile_id, expected_profile_version_id=profile.profile_version_id, allowed_extractors=frozenset(EXTRACTORS), scope_resolver_types=SCOPE_RESOLVER_TYPES)
    leaves = tuple(node for node in ir.nodes if not isinstance(node.value, (dict, list)))
    if ir.truncated:
        return InterpretationResult(
            facts=(),
            diagnostics=tuple(InterpretationDiagnostic("json_evidence_incomplete", node.node_id) for node in leaves),
            metrics=InterpretationMetrics(len(leaves), 0, 0, 0, len(leaves), len(leaves)),
            unresolved_node_ids=tuple(node.node_id for node in leaves),
        )
    facts: list[SecurityFactDraft] = []
    diagnostics: list[InterpretationDiagnostic] = []
    matched: set[str] = set()
    for mapping in pack.mappings:
        definition_payload = mapping.training_definition
        if not definition_payload or definition_payload.get("structural_match", {}).get("operation") != "json_path":
            continue
        definition = MappingDefinition.model_validate(definition_payload)
        for node, captures in matches_json(definition, ir):
            try:
                value = extract_training(definition, captures)
                value_type = TypedValueType(definition.value_extraction.output_type)
                typed = TypedValue(value_type, value, unit="seconds" if value_type is TypedValueType.DURATION else None)
                scope = ScopeRef(type=definition.scope_resolution.strategy, key="device", attributes={})
                validate_field_value_scope(definition.target_field_id, typed, scope)
            except (KeyError, TypeError, ValueError, FieldRegistryValidationError):
                diagnostics.append(InterpretationDiagnostic("json_mapping_output_invalid", node.node_id, mapping.mapping_id))
                continue
            facts.append(_build_json_fact(context=context, ir=ir, pack=pack, mapping=mapping, value=typed, scope=scope, node=node))
            matched.add(node.node_id)
    return InterpretationResult(
        facts=tuple(facts), diagnostics=tuple(diagnostics),
        metrics=InterpretationMetrics(len(leaves), len(matched), len(facts), len(facts), len(leaves) - len(matched), len(diagnostics)),
        unresolved_node_ids=tuple(node.node_id for node in leaves if node.node_id not in matched),
    )


def _build_json_fact(*, context: InterpretationContext, ir: JsonStructuralIR, pack: KnowledgePack, mapping: DeclarativeMapping, value: TypedValue, scope: ScopeRef, node: JsonNode) -> SecurityFactDraft:
    evidence = EvidenceRef(
        artifact_id=node.source.artifact_id, start_line=None, end_line=None,
        source_path=node.source.source_label, ir_node_id=node.node_id,
        evidence_type=ArtifactEvidenceType.STRUCTURED_EXPORT,
        structured_path=node.path,
        structured_order=node.order,
    )
    identity = json.dumps({"audit_id": str(context.audit_id), "mapping_version_id": str(mapping.mapping_version_id), "source_ir_node_ids": (node.node_id,), "field_id": mapping.field_id, "scope": scope.to_dict(), "entity": None, "value": value.to_dict()}, sort_keys=True, separators=(",", ":"))
    return SecurityFactDraft(
        fact_id=uuid5(pack.knowledge_pack_version_id, identity), audit_id=context.audit_id,
        device_id=context.device_id, snapshot_id=context.snapshot_id, field_id=mapping.field_id,
        value=value, entity=None, scope=scope, state=FactState.EXPLICIT,
        evidence_refs=(evidence,), source_ir_node_ids=(node.node_id,),
        extraction_method=InterpretationMethod.DECLARATIVE_MAPPING, mapping_id=mapping.mapping_id,
        mapping_version_id=mapping.mapping_version_id, knowledge_pack_version_id=pack.knowledge_pack_version_id,
        validation_status=FactValidationStatus.VALIDATED, dependencies=(),
        interpretation_confidence=InterpretationConfidence.HIGH,
    )


def _build_xml_fact(*, context: InterpretationContext, ir: XmlStructuralIR, pack: KnowledgePack, mapping: DeclarativeMapping, value: TypedValue, scope: ScopeRef, node: XmlNode) -> SecurityFactDraft:
    evidence = EvidenceRef(
        artifact_id=node.source.artifact_id, start_line=node.order, end_line=node.order,
        source_path=node.source.source_label, ir_node_id=node.node_id,
        evidence_type=ArtifactEvidenceType.STRUCTURED_EXPORT,
    )
    identity = json.dumps({"audit_id": str(context.audit_id), "mapping_version_id": str(mapping.mapping_version_id), "source_ir_node_ids": (node.node_id,), "field_id": mapping.field_id, "scope": scope.to_dict(), "entity": None, "value": value.to_dict()}, sort_keys=True, separators=(",", ":"))
    return SecurityFactDraft(
        fact_id=uuid5(pack.knowledge_pack_version_id, identity), audit_id=context.audit_id,
        device_id=context.device_id, snapshot_id=context.snapshot_id, field_id=mapping.field_id,
        value=value, entity=None, scope=scope, state=FactState.EXPLICIT,
        evidence_refs=(evidence,), source_ir_node_ids=(node.node_id,),
        extraction_method=InterpretationMethod.DECLARATIVE_MAPPING, mapping_id=mapping.mapping_id,
        mapping_version_id=mapping.mapping_version_id, knowledge_pack_version_id=pack.knowledge_pack_version_id,
        validation_status=FactValidationStatus.VALIDATED, dependencies=(),
        interpretation_confidence=InterpretationConfidence.HIGH,
    )


def interpret_audit(
    db: Session,
    storage: ArtifactStorage,
    audit_id: UUID,
    organization_id: UUID,
    *,
    before_interpret: Callable[[], None] | None = None,
    knowledge_pack: KnowledgePack | None = None,
) -> AuditInterpretationResult:
    audit = db.scalar(select(Audit).where(
        Audit.audit_id == audit_id,
        Audit.organization_id == organization_id,
    ))
    if audit is None:
        raise InterpretationNotFoundError("audit_not_found", "Audit not found")
    snapshot = db.scalar(select(Snapshot).where(
        Snapshot.snapshot_id == audit.snapshot_id
    ))
    device = db.scalar(select(Device).where(
        Device.device_id == audit.device_id
    ))
    if snapshot is None or device is None or (
        snapshot.organization_id != audit.organization_id
        or snapshot.device_id != audit.device_id
        or device.organization_id != audit.organization_id
    ):
        raise InterpretationValidationError(
            "audit_resource_inconsistent", "Audit resources are inconsistent"
        )
    if snapshot.status not in {SnapshotStatus.READY, SnapshotStatus.LOCKED}:
        raise InterpretationValidationError(
            "snapshot_not_interpretable", "Audit Snapshot is not available for interpretation"
        )

    profile_id = audit.profile_resolution.get("profile_id")
    profile_version_id = audit.profile_resolution.get("profile_version_id")
    profile = profile_for(db, organization_id, profile_version_id)
    if (
        profile is None
        or profile.profile_id != profile_id
        or audit.profile_resolution.get("resolution_status") != "resolved"
    ):
        raise InterpretationValidationError(
            "audit_profile_incompatible", "Audit has no compatible resolved profile"
        )
    pinned_pack_id = audit.version_refs.get("knowledge_pack_version_id")
    if knowledge_pack is not None:
        pack = knowledge_pack
    elif pinned_pack_id is None:
        pack = load_validated_knowledge_pack(profile_version_id) if PROFILE_REGISTRY.get(profile_version_id) else runtime_baseline_knowledge_pack(profile)
    else:
        try:
            pack = load_published_knowledge_pack(db, organization_id, UUID(pinned_pack_id), profile_version_id, profile=profile)
        except (TypeError, ValueError):
            raise InterpretationValidationError(
                "knowledge_pack_version_conflict", "Audit knowledge-pack version is incompatible"
            ) from None
        if pack.profile_version_id != profile_version_id:
            raise InterpretationValidationError(
                "knowledge_pack_version_conflict", "Audit knowledge-pack version is incompatible"
            )
    artifacts = validate_snapshot_evidence(db, snapshot)
    profile_manifest = profile
    evidence_artifacts = sorted(
        (
            artifact for artifact in artifacts
            if profile_manifest is not None
            and artifact.evidence_type in profile_manifest.structural_evidence_types
        ),
        key=lambda artifact: str(artifact.artifact_id),
    )
    if not evidence_artifacts:
        raise InterpretationValidationError(
            "structural_evidence_missing",
            "Snapshot has no evidence compatible with the selected profile",
        )

    expected_profile_resolution = dict(audit.profile_resolution)
    identity_artifact_ids = {
        item["artifact_id"]
        for values in expected_profile_resolution.get("identity_provenance", {}).values()
        for item in values
        if isinstance(item, dict) and isinstance(item.get("artifact_id"), str)
    }
    unsupported_artifacts: list[tuple[Artifact, str]] = []
    selected_artifact_ids = {artifact.artifact_id for artifact in evidence_artifacts}
    for artifact in artifacts:
        configuration_like = artifact.evidence_type in {
            ArtifactEvidenceType.CONFIGURATION,
            ArtifactEvidenceType.STRUCTURED_EXPORT,
        } or (
            artifact.evidence_type is ArtifactEvidenceType.UNKNOWN_EVIDENCE
            and str(artifact.artifact_id) not in identity_artifact_ids
        )
        if artifact.evidence_type is ArtifactEvidenceType.STRUCTURED_EXPORT:
            filename = artifact.original_filename.lower()
            configuration_like = any(
                marker in filename for marker in ("config", "running", "startup")
            )
        if not configuration_like or artifact.artifact_id in selected_artifact_ids:
            continue
        try:
            preview = storage.read_prefix(artifact.storage_reference, 2048).decode(
                artifact.encoding or "utf-8", errors="replace"
            )
        except (ArtifactStorageError, LookupError):
            preview = artifact.original_filename
        unsupported_artifacts.append((artifact, preview[:2048]))
    expected_evidence = tuple(
        (artifact.artifact_id, artifact.sha256) for artifact in artifacts
    )
    context = InterpretationContext(
        audit_id=audit.audit_id,
        device_id=audit.device_id,
        snapshot_id=audit.snapshot_id,
    )
    for artifact in evidence_artifacts:
        db.expunge(artifact)
    db.rollback()

    parsed_irs: list[StructuralIR | XmlStructuralIR | JsonStructuralIR] = []
    artifact_diagnostics: list[ArtifactInterpretationDiagnostic] = [
        ArtifactInterpretationDiagnostic(
            artifact.artifact_id, "unsupported_configuration_evidence"
        )
        for artifact, _preview in unsupported_artifacts
    ]
    for artifact in evidence_artifacts:
        try:
            parsed_irs.append(parse_artifact(
                storage,
                artifact,
                profile_version_id=profile_version_id,
                organization_id=organization_id,
                profile=profile,
            ))
        except ArtifactNotParseableError as exc:
            artifact_diagnostics.append(ArtifactInterpretationDiagnostic(
                artifact.artifact_id, exc.code
            ))
        except (ParsingInfrastructureError, StructuralReaderNotFoundError):
            raise InterpretationInfrastructureError(
                "structural_parsing_failed",
                "Configuration evidence could not be parsed",
            ) from None

    if before_interpret is not None:
        before_interpret()

    artifact_results: list[InterpretationResult] = []
    drafts: list[SecurityFactDraft] = []
    for ir in parsed_irs:
        if isinstance(ir, XmlStructuralIR):
            result = interpret_xml_structural_ir(ir, context, profile_version_id=profile_version_id, knowledge_pack=pack, profile=profile)
        elif isinstance(ir, JsonStructuralIR):
            result = interpret_json_structural_ir(ir, context, profile_version_id=profile_version_id, knowledge_pack=pack, profile=profile)
        else:
            result = interpret_structural_ir(ir, context, profile_version_id=profile_version_id, knowledge_pack=pack, profile=profile)
        artifact_results.append(result)
        drafts.extend(result.facts)

    fact_ids = [draft.fact_id for draft in drafts]
    try:
        persisted_audit = db.scalar(select(Audit).where(
            Audit.audit_id == audit_id,
            Audit.organization_id == organization_id,
        ).with_for_update())
        if persisted_audit is None:
            raise InterpretationNotFoundError("audit_not_found", "Audit not found")
        persisted_snapshot = db.scalar(select(Snapshot).where(
            Snapshot.snapshot_id == context.snapshot_id
        ).with_for_update())
        persisted_device = db.scalar(select(Device).where(
            Device.device_id == context.device_id
        ).with_for_update())
        if persisted_snapshot is None or persisted_device is None or (
            persisted_audit.snapshot_id != context.snapshot_id
            or persisted_audit.device_id != context.device_id
            or persisted_snapshot.organization_id != organization_id
            or persisted_snapshot.device_id != context.device_id
            or persisted_device.organization_id != organization_id
            or dict(persisted_audit.profile_resolution) != expected_profile_resolution
        ):
            raise InterpretationValidationError(
                "audit_resource_changed", "Audit resources changed during interpretation"
            )
        current_artifacts = validate_snapshot_evidence(
            db, persisted_snapshot, lock=True
        )
        if tuple(
            (artifact.artifact_id, artifact.sha256) for artifact in current_artifacts
        ) != expected_evidence:
            raise InterpretationValidationError(
                "snapshot_evidence_changed",
                "Snapshot evidence changed during interpretation",
            )
        pinned_pack = persisted_audit.version_refs.get(
            "knowledge_pack_version_id"
        )
        pinned_profile = persisted_audit.version_refs.get(
            "device_profile_version_id"
        )
        if pinned_profile is not None and pinned_profile != profile_version_id:
            raise InterpretationValidationError(
                "profile_version_conflict",
                "Audit device-profile version is incompatible",
            )
        if pinned_pack is not None and pinned_pack != str(
            pack.knowledge_pack_version_id
        ):
            raise InterpretationValidationError(
                "knowledge_pack_version_conflict",
                "Audit knowledge-pack version is incompatible",
            )

        existing_ids = set(db.scalars(select(SecurityFact.fact_id).where(
            SecurityFact.audit_id == audit_id,
            SecurityFact.fact_id.in_(fact_ids),
        ))) if fact_ids else set()
        for draft in drafts:
            if draft.fact_id not in existing_ids:
                db.add(_to_orm(draft))
        _persist_unresolved_blocks(
            db,
            organization_id=organization_id,
            context=context,
            profile_id=profile_id,
            profile_version_id=profile_version_id,
            profile=profile,
            parsed_irs=parsed_irs,
            results=artifact_results,
            knowledge_pack=pack,
            unsupported_artifacts=unsupported_artifacts,
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise InterpretationInfrastructureError(
            "security_fact_persistence_failed", "SecurityFacts could not be persisted"
        ) from None

    try:
        facts = tuple(db.scalars(select(SecurityFact).where(
            SecurityFact.audit_id == audit_id,
            SecurityFact.fact_id.in_(fact_ids),
        ).order_by(SecurityFact.fact_id))) if fact_ids else ()
    except SQLAlchemyError:
        db.rollback()
        raise InterpretationInfrastructureError(
            "security_fact_readback_failed", "SecurityFacts could not be read"
        ) from None
    return AuditInterpretationResult(
        facts=facts,
        artifact_results=tuple(artifact_results),
        artifact_diagnostics=tuple(artifact_diagnostics),
    )


def list_audit_security_facts(
    db: Session, audit_id: UUID, organization_id: UUID
) -> list[SecurityFact]:
    return list(db.scalars(
        select(SecurityFact)
        .join(Audit, Audit.audit_id == SecurityFact.audit_id)
        .where(
            SecurityFact.audit_id == audit_id,
            Audit.organization_id == organization_id,
        )
        .order_by(SecurityFact.fact_id)
    ))


def _matches(mapping: DeclarativeMapping, node: ConfigNode, ir: StructuralIR) -> bool:
    if mapping.training_definition is not None:
        definition = MappingDefinition.model_validate(mapping.training_definition)
        return matches_training(
            definition, _training_validation_node(node, ir, mapping.scope_resolver)
        )[0]
    matcher = mapping.matcher
    if node.command != matcher.command or not _has_prefix(
        node.arguments, matcher.arguments_prefix
    ):
        return False
    if matcher.parent_command is None:
        return True
    if node.parent_id is None:
        return False
    try:
        parent = ir.node(node.parent_id)
    except KeyError:
        return False
    if parent.command != matcher.parent_command or not _has_prefix(
        parent.arguments, matcher.parent_arguments_prefix
    ):
        return False
    if matcher.ancestor_command is None:
        return True
    ancestor_id = parent.parent_id
    while ancestor_id is not None:
        ancestor = ir.node(ancestor_id)
        if ancestor.command == matcher.ancestor_command:
            return _has_prefix(ancestor.arguments, matcher.ancestor_arguments_prefix)
        ancestor_id = ancestor.parent_id
    return False


def _has_prefix(arguments: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    return tuple(item.lower() for item in arguments[:len(prefix)]) == tuple(
        item.lower() for item in prefix
    )


def _extract_mapping(mapping: DeclarativeMapping, node: ConfigNode, ir: StructuralIR):
    if mapping.training_definition is None:
        return EXTRACTORS[mapping.extractor](node)
    definition = MappingDefinition.model_validate(mapping.training_definition)
    matched, captures = matches_training(
        definition, _training_validation_node(node, ir, mapping.scope_resolver)
    )
    if not matched:
        return ExtractionOutcome(None, "training_mapping_mismatch")
    value = extract_training(definition, captures)
    return ExtractionOutcome(TypedValue(TypedValueType(definition.value_extraction.output_type), value))


def _training_validation_node(
    node: ConfigNode, ir: StructuralIR, scope_type: str
) -> ValidationNode:
    parent = ir.node(node.parent_id) if node.parent_id else None
    ancestors: list[str] = []
    ancestor = parent
    while ancestor is not None and len(ancestors) < 8:
        if ancestor.command:
            ancestors.append(ancestor.command)
        ancestor = ir.node(ancestor.parent_id) if ancestor.parent_id else None
    return ValidationNode.model_validate({
        "command": node.command,
        "arguments": list(node.arguments),
        "parent_command": parent.command if parent else None,
        "ancestor_commands": ancestors,
        "scope_type": scope_type,
        "negated": node.negated,
    })


def _build_fact(
    *,
    context: InterpretationContext,
    ir: StructuralIR,
    pack: KnowledgePack,
    mapping: DeclarativeMapping,
    value,
    scope,
    source_nodes: list[ConfigNode],
    state: FactState = FactState.EXPLICIT,
    validation_status: FactValidationStatus = FactValidationStatus.VALIDATED,
    interpretation_confidence: InterpretationConfidence = InterpretationConfidence.HIGH,
    mapping_version_id: UUID | None = None,
) -> SecurityFactDraft:
    source_ir_node_ids = tuple(node.node_id for node in source_nodes)
    evidence_refs = tuple(EvidenceRef(
        artifact_id=node.artifact_id,
        start_line=node.source_start,
        end_line=node.source_end,
        source_path=node.source_label,
        ir_node_id=node.node_id,
        evidence_type=ArtifactEvidenceType.CONFIGURATION,
    ) for node in source_nodes)
    identity = json.dumps({
        "audit_id": str(context.audit_id),
        "mapping_version_id": str(mapping_version_id or mapping.mapping_version_id),
        "source_ir_node_ids": source_ir_node_ids,
        "field_id": mapping.field_id,
        "scope": scope.to_dict(),
        "entity": None,
        "value": value.to_dict(),
    }, sort_keys=True, separators=(",", ":"))
    fact_id = uuid5(pack.knowledge_pack_version_id, identity)
    return SecurityFactDraft(
        fact_id=fact_id,
        audit_id=context.audit_id,
        device_id=context.device_id,
        snapshot_id=context.snapshot_id,
        field_id=mapping.field_id,
        value=value,
        entity=None,
        scope=scope,
        state=state,
        evidence_refs=evidence_refs,
        source_ir_node_ids=source_ir_node_ids,
        extraction_method=InterpretationMethod.DECLARATIVE_MAPPING,
        mapping_id=mapping.mapping_id,
        mapping_version_id=mapping_version_id or mapping.mapping_version_id,
        knowledge_pack_version_id=pack.knowledge_pack_version_id,
        validation_status=validation_status,
        dependencies=(),
        interpretation_confidence=interpretation_confidence,
    )


def _build_negated_fact(
    *,
    context: InterpretationContext,
    ir: StructuralIR,
    pack: KnowledgePack,
    mapping: DeclarativeMapping,
    node: ConfigNode,
) -> SecurityFactDraft | None:
    """Preserve only versioned, bounded negation operations for later resolution."""
    behavior = mapping.negation_behavior
    if behavior is NegationBehavior.UNSUPPORTED:
        return None
    if node.parse_status != ParseStatus.PARSED:
        return None
    scope_outcome = SCOPE_RESOLVERS[mapping.scope_resolver](node, ir)
    if scope_outcome.scope is None:
        return None
    source_nodes = [node]
    if scope_outcome.context_node is not None:
        source_nodes.append(scope_outcome.context_node)

    if behavior is NegationBehavior.RESET_TO_DEFAULT:
        if tuple(item.lower() for item in node.arguments) != tuple(
            item.lower() for item in mapping.matcher.arguments_prefix
        ):
            return None
        field = get_field(mapping.field_id)
        if scope_outcome.scope.type not in field.allowed_scope_types:
            return None
        return _build_fact(
            context=context,
            ir=ir,
            pack=pack,
            mapping=mapping,
            value=TypedValue(TypedValueType.NULL, None),
            scope=scope_outcome.scope,
            source_nodes=source_nodes,
            state=FactState.UNKNOWN,
            validation_status=FactValidationStatus.UNRESOLVED,
            interpretation_confidence=InterpretationConfidence.UNRESOLVED,
            mapping_version_id=mapping.reset_mapping_version_id,
        )

    if behavior is NegationBehavior.REMOVE_VALUE:
        extraction = _extract_mapping(mapping, node, ir)
        if extraction.value is None:
            return None
        try:
            validate_field_value_scope(
                mapping.field_id, extraction.value, scope_outcome.scope
            )
        except FieldRegistryValidationError:
            return None
        return _build_fact(
            context=context,
            ir=ir,
            pack=pack,
            mapping=mapping,
            value=extraction.value,
            scope=scope_outcome.scope,
            source_nodes=source_nodes,
            mapping_version_id=mapping.removal_mapping_version_id,
        )
    if behavior is NegationBehavior.INVERT_BOOLEAN:
        extraction = _extract_mapping(mapping, node, ir)
        if extraction.value is None or extraction.value.type is not TypedValueType.BOOLEAN:
            return None
        return _build_fact(
            context=context, ir=ir, pack=pack, mapping=mapping,
            value=TypedValue(
                TypedValueType.BOOLEAN, not extraction.value.value,
                original_value=extraction.value.original_value,
            ),
            scope=scope_outcome.scope, source_nodes=source_nodes,
        )
    return None


def _to_orm(draft: SecurityFactDraft) -> SecurityFact:
    return SecurityFact(
        fact_id=draft.fact_id,
        audit_id=draft.audit_id,
        device_id=draft.device_id,
        snapshot_id=draft.snapshot_id,
        field_id=draft.field_id,
        value=draft.value.to_dict(),
        entity=draft.entity,
        scope=draft.scope.to_dict(),
        state=draft.state,
        evidence_refs=[item.to_dict() for item in draft.evidence_refs],
        source_ir_node_ids=list(draft.source_ir_node_ids),
        extraction_method=draft.extraction_method,
        mapping_id=draft.mapping_id,
        mapping_version_id=draft.mapping_version_id,
        knowledge_pack_version_id=draft.knowledge_pack_version_id,
        validation_status=draft.validation_status,
        dependencies=[str(item) for item in draft.dependencies],
        interpretation_confidence=draft.interpretation_confidence,
        schema_version=draft.schema_version,
    )


def _persist_unresolved_blocks(
    db: Session,
    *,
    organization_id: UUID,
    context: InterpretationContext,
    profile_id: str,
    profile_version_id: str,
    parsed_irs: list[StructuralIR | XmlStructuralIR | JsonStructuralIR],
    results: list[InterpretationResult],
    knowledge_pack: KnowledgePack,
    unsupported_artifacts: list[tuple[Artifact, str]],
    profile: ProfileManifest | None = None,
) -> None:
    from app.compliance.rule_registry import RULE_PACK_BY_PROFILE

    rule_pack = RULE_PACK_BY_PROFILE.get(profile_version_id)
    rules = () if rule_pack is None else rule_pack.rules
    all_field_ids = sorted({
        field_id for rule in rules for field_id in rule.required_effective_states
    })
    if not all_field_ids and profile is not None:
        all_field_ids = sorted(
            field_id for field_id in profile.coverage_manifest.get("canonical_fields", ())
            if isinstance(field_id, str)
        )
    all_rule_ids = sorted(rule.rule_id for rule in rules)
    mapping_fields = {
        mapping.mapping_id: mapping.field_id for mapping in knowledge_pack.mappings
    }
    for ir, result in zip(parsed_irs, results, strict=True):
        diagnostics: dict[str, list[InterpretationDiagnostic]] = {}
        for diagnostic in result.diagnostics:
            if diagnostic.node_id:
                diagnostics.setdefault(diagnostic.node_id, []).append(diagnostic)
        nodes = {node.node_id: node for node in ir.nodes}
        for node_id in result.unresolved_node_ids:
            node = nodes[node_id]
            # Manifest-declared identity syntax cannot affect canonical
            # compliance fields and is not unresolved configuration evidence.
            if (
                isinstance(ir, StructuralIR)
                and node.kind is ConfigNodeKind.STATEMENT
                and node.command in (
                    profile.coverage_manifest.get("identity_only_commands", ())
                    if profile is not None else ()
                )
            ):
                continue
            parent = nodes.get(node.parent_id) if node.parent_id else None
            artifact_id = node.artifact_id if isinstance(ir, StructuralIR) else node.source.artifact_id
            source_label = node.source_label if isinstance(ir, StructuralIR) else node.source.source_label
            start_line = node.source_start if isinstance(ir, StructuralIR) else node.order if isinstance(ir, XmlStructuralIR) else None
            end_line = node.source_end if isinstance(ir, StructuralIR) else node.order if isinstance(ir, XmlStructuralIR) else None
            identity = f"{context.audit_id}:{artifact_id}:{node.node_id}"
            fingerprint = hashlib.sha256(identity.encode()).hexdigest()
            exists = db.scalar(select(UnresolvedBlock.unresolved_block_id).where(
                UnresolvedBlock.audit_id == context.audit_id,
                UnresolvedBlock.fingerprint == fingerprint,
            ))
            if exists is not None:
                continue
            node_diagnostics = diagnostics.get(node.node_id, [])
            candidate_field_ids = sorted({
                mapping_fields[item.mapping_id]
                for item in node_diagnostics
                if item.mapping_id in mapping_fields
            })
            affected_rule_ids = sorted({
                rule.rule_id for rule in rules
                if set(rule.required_effective_states) & set(candidate_field_ids)
            })
            # An unmatched configuration node has no safely determined canonical
            # relevance.  It must therefore block PASS for this profile rather
            # than leave an unassociated uncertainty behind.
            if not candidate_field_ids:
                candidate_field_ids = all_field_ids
                affected_rule_ids = all_rule_ids
            if profile_id in {"generic.cli", "generic.xml", "generic.json"}:
                candidate_field_ids = all_field_ids
                affected_rule_ids = all_rule_ids
            if (
                isinstance(ir, StructuralIR)
                and node.kind is ConfigNodeKind.OPAQUE
                and node.parse_status is not ParseStatus.OPAQUE
            ):
                candidate_field_ids = all_field_ids
                affected_rule_ids = all_rule_ids
            nearby = sorted(ir.nodes, key=lambda item: item.order)
            position = next(index for index, item in enumerate(nearby) if item.node_id == node.node_id)
            context_text = "\n".join(
                (
                    item.raw_text if isinstance(ir, StructuralIR)
                    else f"<{item.tag}>{item.text or ''}" if isinstance(ir, XmlStructuralIR)
                    else f"{list(item.path)} = {item.value!r}"
                )
                for item in nearby[max(0, position - 2):position + 3]
            )[:4096]
            if isinstance(ir, StructuralIR):
                raw_text = node.raw_text
                occurrence = {"artifact_id": str(node.artifact_id), "command": node.command, "arguments": list(node.arguments), "parent_command": parent.command if parent else None, "ancestor_commands": list(node.context_path), "negated": node.negated, "order": node.order}
            elif isinstance(ir, XmlStructuralIR):
                raw_text = f"<{node.tag}>{node.text or ''}"[:2048]
                occurrence = {"artifact_id": str(artifact_id), "xml_path": list(node.path), "tag": node.tag, "attributes": dict(node.attributes), "text": node.text, "order": node.order}
            else:
                raw_text = f"{list(node.path)} = {node.value!r}"[:2048]
                occurrence = {"artifact_id": str(artifact_id), "json_path": list(node.path), "value": node.value, "order": node.order}
            db.add(UnresolvedBlock(
                organization_id=organization_id,
                audit_id=context.audit_id,
                device_id=context.device_id,
                snapshot_id=context.snapshot_id,
                profile_id=profile_id,
                profile_version_id=profile_version_id,
                source_ir_node_ids=[node.node_id],
                evidence_refs=[{
                    "artifact_id": str(artifact_id),
                    "start_line": start_line,
                    "end_line": end_line,
                    "source_path": source_label,
                    "ir_node_id": node.node_id,
                    "structured_path": list(node.path) if isinstance(ir, JsonStructuralIR) else None,
                    "evidence_type": (
                        ArtifactEvidenceType.CONFIGURATION.value
                        if isinstance(ir, StructuralIR)
                        else ArtifactEvidenceType.STRUCTURED_EXPORT.value
                    ),
                }],
                raw_text=raw_text,
                surrounding_context=context_text,
                unknown_reason=(
                    node_diagnostics[0].code
                    if node_diagnostics else "unmapped_syntax"
                ),
                candidate_field_ids=candidate_field_ids,
                affected_rule_ids=affected_rule_ids,
                fingerprint=fingerprint,
                occurrence=occurrence,
            ))

    for artifact, raw_text in unsupported_artifacts:
        identity = f"{context.audit_id}:{artifact.artifact_id}:unsupported-artifact"
        fingerprint = hashlib.sha256(identity.encode()).hexdigest()
        exists = db.scalar(select(UnresolvedBlock.unresolved_block_id).where(
            UnresolvedBlock.audit_id == context.audit_id,
            UnresolvedBlock.fingerprint == fingerprint,
        ))
        if exists is not None:
            continue
        db.add(UnresolvedBlock(
            organization_id=organization_id,
            audit_id=context.audit_id,
            device_id=context.device_id,
            snapshot_id=context.snapshot_id,
            profile_id=profile_id,
            profile_version_id=profile_version_id,
            source_ir_node_ids=[],
            evidence_refs=[{
                "artifact_id": str(artifact.artifact_id),
                "source_path": artifact.original_filename,
                "evidence_type": artifact.evidence_type.value,
            }],
            raw_text=raw_text,
            surrounding_context="",
            unknown_reason="unsupported_configuration_evidence",
            candidate_field_ids=all_field_ids,
            affected_rule_ids=all_rule_ids,
            fingerprint=fingerprint,
            occurrence={
                "artifact_id": str(artifact.artifact_id),
                "filename": artifact.original_filename,
                "evidence_type": artifact.evidence_type.value,
                "sha256": artifact.sha256,
            },
        ))


def _add_diagnostic(
    diagnostics: list[InterpretationDiagnostic],
    keys: set[tuple[str, str | None, UUID | None]],
    code: str,
    node_id: str | None,
    mapping_id: UUID | None,
) -> None:
    key = (code, node_id, mapping_id)
    if key not in keys:
        keys.add(key)
        diagnostics.append(InterpretationDiagnostic(code, node_id, mapping_id))
