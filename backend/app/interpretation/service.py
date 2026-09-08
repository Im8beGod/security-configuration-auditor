from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from uuid import UUID, uuid5

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
from app.ingestion.storage import ArtifactStorage
from app.interpretation.exceptions import (
    InterpretationInfrastructureError,
    InterpretationNotFoundError,
    InterpretationValidationError,
)
from app.interpretation.extractors import EXTRACTORS, ExtractionOutcome
from app.interpretation.knowledge_pack import (
    DeclarativeMapping,
    KnowledgePack,
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
)
from app.knowledge_packs.fortios_7 import (
    FORTIOS_7_KNOWLEDGE_PACK,
    FORTIOS_7_KNOWLEDGE_PACK_V1,
)
from app.parsing import ConfigNode, ConfigNodeKind, ParseStatus, StructuralIR, parse_artifact
from app.parsing.readers.xml_tree import XmlStructuralIR, XmlNode
from app.parsing.exceptions import (
    ArtifactNotParseableError,
    ParsingInfrastructureError,
    StructuralReaderNotFoundError,
)
from app.profile_resolution import PROFILE_REGISTRY
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
from app.training.dsl import MappingDefinition, ValidationNode, extract as extract_training, matches as matches_training, matches_xml, xml_match_has_unsupported_qualifier


KNOWLEDGE_PACKS = {
    CISCO_IOS_XE_17_KNOWLEDGE_PACK.profile_version_id: CISCO_IOS_XE_17_KNOWLEDGE_PACK,
}
KNOWLEDGE_PACKS_BY_VERSION = {
    pack.knowledge_pack_version_id: pack
    for pack in (
        CISCO_IOS_XE_17_KNOWLEDGE_PACK_V1,
        CISCO_IOS_XE_17_KNOWLEDGE_PACK,
        FORTIOS_7_KNOWLEDGE_PACK_V1,
        FORTIOS_7_KNOWLEDGE_PACK,
    )
}


def _junos_pack():
    from app.knowledge_packs.juniper_junos_18 import JUNIPER_JUNOS_18_KNOWLEDGE_PACK
    return JUNIPER_JUNOS_18_KNOWLEDGE_PACK


def _fortios_pack():
    return FORTIOS_7_KNOWLEDGE_PACK


def load_validated_knowledge_pack(profile_version_id: str) -> KnowledgePack:
    profile = PROFILE_REGISTRY.get(profile_version_id)
    pack = KNOWLEDGE_PACKS.get(profile_version_id)
    if pack is None and profile_version_id == "juniper.junos.18@1.0.0":
        pack = _junos_pack()
    if pack is None and profile_version_id == "fortinet.fortios.7@1.0.0":
        pack = _fortios_pack()
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
    pack = KNOWLEDGE_PACKS_BY_VERSION.get(knowledge_pack_version_id)
    if pack is None and knowledge_pack_version_id == UUID("b3040000-0000-5000-8000-000000000018"):
        pack = _junos_pack()
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


def load_published_knowledge_pack(
    db: Session, organization_id: UUID, knowledge_pack_version_id: UUID, profile_version_id: str
) -> KnowledgePack:
    """Load an immutable, administrator-published Step 11 pack through the bounded DSL."""
    version = db.scalar(select(KnowledgePackVersionRecord).where(
        KnowledgePackVersionRecord.knowledge_pack_version_id == knowledge_pack_version_id,
        KnowledgePackVersionRecord.organization_id == organization_id,
    ))
    if version is None:
        return load_validated_knowledge_pack_by_version(knowledge_pack_version_id)
    record = db.get(KnowledgePackRecord, version.knowledge_pack_id)
    profile = PROFILE_REGISTRY.get(profile_version_id)
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
    baseline = load_validated_knowledge_pack(profile_version_id)
    mappings = (*baseline.mappings, *tuple(_training_mapping(row, profile_version_id) for row in sorted(rows, key=lambda row: str(row.mapping_version_id))))
    pack = KnowledgePack(record.knowledge_pack_id, version.knowledge_pack_version_id, record.name,
        str(version.version), version.schema_version, profile.profile_id, profile_version_id, mappings)
    try:
        return validate_knowledge_pack(pack, expected_profile_id=profile.profile_id,
            expected_profile_version_id=profile_version_id, allowed_extractors=frozenset(EXTRACTORS), scope_resolver_types=SCOPE_RESOLVER_TYPES)
    except ValueError:
        raise InterpretationValidationError("knowledge_pack_invalid", "Knowledge pack validation failed") from None


def load_active_published_knowledge_pack(
    db: Session, organization_id: UUID, profile_version_id: str
) -> KnowledgePack | None:
    """Load the newest compatible published pack for a fresh audit."""
    profile = PROFILE_REGISTRY.get(profile_version_id)
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
        db, organization_id, selected.knowledge_pack_version_id, profile_version_id
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
) -> InterpretationResult:
    profile = PROFILE_REGISTRY.get(profile_version_id)
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
    facts: list[SecurityFactDraft] = []
    diagnostics: list[InterpretationDiagnostic] = []
    diagnostic_keys: set[tuple[str, str | None, UUID | None]] = set()
    matched_node_ids: set[str] = set()

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

    metrics = InterpretationMetrics(
        nodes_considered=len(statements),
        nodes_matched=len(matched_node_ids),
        mappings_applied=len(facts),
        facts_produced=len(facts),
        unmatched_nodes=len(statements) - len(matched_node_ids),
        unsupported_cases=len(diagnostics),
    )
    return InterpretationResult(
        facts=tuple(facts), diagnostics=tuple(diagnostics), metrics=metrics,
        unresolved_node_ids=tuple(node.node_id for node in statements if node.node_id not in matched_node_ids),
    )


def interpret_xml_structural_ir(
    ir: XmlStructuralIR,
    context: InterpretationContext,
    *,
    profile_version_id: str,
    knowledge_pack: KnowledgePack | None = None,
) -> InterpretationResult:
    """Interpret XML using the same declarative mapping contract as CLI evidence."""
    profile = PROFILE_REGISTRY.get(profile_version_id)
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
                typed = TypedValue(TypedValueType(definition.value_extraction.output_type), value)
                scope = ScopeRef(type=definition.scope_resolution.strategy, key="device", attributes={})
                validate_field_value_scope(definition.target_field_id, typed, scope)
            except (KeyError, TypeError, ValueError, FieldRegistryValidationError):
                diagnostics.append(InterpretationDiagnostic("xml_mapping_output_invalid", node.node_id, mapping.mapping_id))
                continue
            facts.append(_build_xml_fact(context=context, ir=ir, pack=pack, mapping=mapping, value=typed, scope=scope, node=node))
            matched.add(node.node_id)
    statements = len(ir.nodes)
    return InterpretationResult(
        facts=tuple(facts), diagnostics=tuple(diagnostics),
        metrics=InterpretationMetrics(statements, len(matched), len(facts), len(facts), statements - len(matched), len(diagnostics)),
        unresolved_node_ids=tuple(node.node_id for node in ir.nodes if node.node_id not in matched),
    )


def _build_xml_fact(*, context: InterpretationContext, ir: XmlStructuralIR, pack: KnowledgePack, mapping: DeclarativeMapping, value: TypedValue, scope: ScopeRef, node: XmlNode) -> SecurityFactDraft:
    evidence = EvidenceRef(
        artifact_id=node.source.artifact_id, start_line=node.order, end_line=node.order,
        source_path=node.source.source_label, ir_node_id=node.node_id,
        evidence_type=ArtifactEvidenceType.CONFIGURATION,
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
    profile = PROFILE_REGISTRY.get(profile_version_id)
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
        pack = load_validated_knowledge_pack(profile_version_id)
    else:
        try:
            pack = load_published_knowledge_pack(db, organization_id, UUID(pinned_pack_id), profile_version_id)
        except (TypeError, ValueError):
            raise InterpretationValidationError(
                "knowledge_pack_version_conflict", "Audit knowledge-pack version is incompatible"
            ) from None
        if pack.profile_version_id != profile_version_id:
            raise InterpretationValidationError(
                "knowledge_pack_version_conflict", "Audit knowledge-pack version is incompatible"
            )
    artifacts = validate_snapshot_evidence(db, snapshot)
    profile_manifest = PROFILE_REGISTRY.get(profile_version_id)
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

    parsed_irs: list[StructuralIR | XmlStructuralIR] = []
    artifact_diagnostics: list[ArtifactInterpretationDiagnostic] = []
    for artifact in evidence_artifacts:
        try:
            parsed_irs.append(parse_artifact(
                storage,
                artifact,
                profile_version_id=profile_version_id,
                organization_id=organization_id,
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
            result = interpret_xml_structural_ir(ir, context, profile_version_id=profile_version_id, knowledge_pack=pack)
        else:
            result = interpret_structural_ir(ir, context, profile_version_id=profile_version_id, knowledge_pack=pack)
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
            parsed_irs=parsed_irs,
            results=artifact_results,
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
        parent = ir.node(node.parent_id) if node.parent_id else None
        definition = MappingDefinition.model_validate(mapping.training_definition)
        return matches_training(definition, ValidationNode.model_validate({
            "command": node.command, "arguments": list(node.arguments),
            "parent_command": parent.command if parent else None, "ancestor_commands": [],
            "scope_type": mapping.scope_resolver, "negated": node.negated,
        }))[0]
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
    parent = ir.node(node.parent_id) if node.parent_id else None
    definition = MappingDefinition.model_validate(mapping.training_definition)
    matched, captures = matches_training(definition, ValidationNode.model_validate({
        "command": node.command, "arguments": list(node.arguments),
        "parent_command": parent.command if parent else None, "ancestor_commands": [],
        "scope_type": mapping.scope_resolver, "negated": node.negated,
    }))
    if not matched:
        return ExtractionOutcome(None, "training_mapping_mismatch")
    value = extract_training(definition, captures)
    return ExtractionOutcome(TypedValue(TypedValueType(definition.value_extraction.output_type), value))


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
        extraction = EXTRACTORS[mapping.extractor](node)
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
    parsed_irs: list[StructuralIR | XmlStructuralIR],
    results: list[InterpretationResult],
) -> None:
    for ir, result in zip(parsed_irs, results, strict=True):
        diagnostics = {item.node_id: item.code for item in result.diagnostics if item.node_id}
        nodes = {node.node_id: node for node in ir.nodes}
        for node_id in result.unresolved_node_ids:
            node = nodes[node_id]
            parent = nodes.get(node.parent_id) if node.parent_id else None
            artifact_id = node.artifact_id if isinstance(ir, StructuralIR) else node.source.artifact_id
            source_label = node.source_label if isinstance(ir, StructuralIR) else node.source.source_label
            start_line = node.source_start if isinstance(ir, StructuralIR) else node.order
            end_line = node.source_end if isinstance(ir, StructuralIR) else node.order
            identity = f"{context.audit_id}:{artifact_id}:{node.node_id}"
            fingerprint = hashlib.sha256(identity.encode()).hexdigest()
            exists = db.scalar(select(UnresolvedBlock.unresolved_block_id).where(
                UnresolvedBlock.audit_id == context.audit_id,
                UnresolvedBlock.fingerprint == fingerprint,
            ))
            if exists is not None:
                continue
            nearby = sorted(ir.nodes, key=lambda item: item.order)
            position = next(index for index, item in enumerate(nearby) if item.node_id == node.node_id)
            context_text = "\n".join(
                (item.raw_text if isinstance(ir, StructuralIR) else f"<{item.tag}>{item.text or ''}")
                for item in nearby[max(0, position - 2):position + 3]
            )[:4096]
            if isinstance(ir, StructuralIR):
                raw_text = node.raw_text
                occurrence = {"artifact_id": str(node.artifact_id), "command": node.command, "arguments": list(node.arguments), "parent_command": parent.command if parent else None, "ancestor_commands": list(node.context_path), "negated": node.negated, "order": node.order}
            else:
                raw_text = f"<{node.tag}>{node.text or ''}"[:2048]
                occurrence = {"artifact_id": str(artifact_id), "xml_path": list(node.path), "tag": node.tag, "attributes": dict(node.attributes), "text": node.text, "order": node.order}
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
                    "evidence_type": ArtifactEvidenceType.CONFIGURATION.value,
                }],
                raw_text=raw_text,
                surrounding_context=context_text,
                unknown_reason=diagnostics.get(node.node_id, "unmapped_syntax"),
                candidate_field_ids=[],
                affected_rule_ids=[],
                fingerprint=fingerprint,
                occurrence=occurrence,
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
