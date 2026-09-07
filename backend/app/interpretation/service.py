from __future__ import annotations

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
)
from app.ingestion.storage import ArtifactStorage
from app.interpretation.exceptions import (
    InterpretationInfrastructureError,
    InterpretationNotFoundError,
    InterpretationValidationError,
)
from app.interpretation.extractors import EXTRACTORS
from app.interpretation.knowledge_pack import (
    DeclarativeMapping,
    KnowledgePack,
    NegationBehavior,
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
from app.parsing import ConfigNode, ConfigNodeKind, ParseStatus, StructuralIR, parse_artifact
from app.parsing.exceptions import (
    ArtifactNotParseableError,
    ParsingInfrastructureError,
    StructuralReaderNotFoundError,
)
from app.profile_resolution import PROFILE_REGISTRY
from app.security_model import (
    EvidenceRef,
    FieldRegistryValidationError,
    SecurityFactDraft,
    TypedValue,
    TypedValueType,
    get_field,
    validate_field_value_scope,
)


KNOWLEDGE_PACKS = {
    CISCO_IOS_XE_17_KNOWLEDGE_PACK.profile_version_id: CISCO_IOS_XE_17_KNOWLEDGE_PACK,
}
KNOWLEDGE_PACKS_BY_VERSION = {
    pack.knowledge_pack_version_id: pack
    for pack in (CISCO_IOS_XE_17_KNOWLEDGE_PACK_V1, CISCO_IOS_XE_17_KNOWLEDGE_PACK)
}


def load_validated_knowledge_pack(profile_version_id: str) -> KnowledgePack:
    profile = PROFILE_REGISTRY.get(profile_version_id)
    pack = KNOWLEDGE_PACKS.get(profile_version_id)
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
            extraction = EXTRACTORS[mapping.extractor](node)
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
        facts=tuple(facts), diagnostics=tuple(diagnostics), metrics=metrics
    )


def interpret_audit(
    db: Session,
    storage: ArtifactStorage,
    audit_id: UUID,
    organization_id: UUID,
    *,
    before_interpret: Callable[[], None] | None = None,
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
    if pinned_pack_id is None:
        pack = load_validated_knowledge_pack(profile_version_id)
    else:
        try:
            pack = load_validated_knowledge_pack_by_version(UUID(pinned_pack_id))
        except (TypeError, ValueError):
            raise InterpretationValidationError(
                "knowledge_pack_version_conflict", "Audit knowledge-pack version is incompatible"
            ) from None
        if pack.profile_version_id != profile_version_id:
            raise InterpretationValidationError(
                "knowledge_pack_version_conflict", "Audit knowledge-pack version is incompatible"
            )
    artifacts = validate_snapshot_evidence(db, snapshot)
    configuration_artifacts = sorted(
        (
            artifact for artifact in artifacts
            if artifact.evidence_type == ArtifactEvidenceType.CONFIGURATION
        ),
        key=lambda artifact: str(artifact.artifact_id),
    )
    if not configuration_artifacts:
        raise InterpretationValidationError(
            "configuration_evidence_missing", "Snapshot has no configuration evidence"
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
    for artifact in configuration_artifacts:
        db.expunge(artifact)
    db.rollback()

    parsed_irs: list[StructuralIR] = []
    artifact_diagnostics: list[ArtifactInterpretationDiagnostic] = []
    for artifact in configuration_artifacts:
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
        result = interpret_structural_ir(
            ir,
            context,
            profile_version_id=profile_version_id,
            knowledge_pack=pack,
        )
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
    return parent.command == matcher.parent_command and _has_prefix(
        parent.arguments, matcher.parent_arguments_prefix
    )


def _has_prefix(arguments: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    return tuple(item.lower() for item in arguments[:len(prefix)]) == tuple(
        item.lower() for item in prefix
    )


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
