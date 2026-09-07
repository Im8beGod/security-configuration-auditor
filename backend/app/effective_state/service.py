from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Audit, Device, SecurityFact, Snapshot, KnowledgePackVersionRecord, MappingStatus, MappingVersion
from app.db.models.effective_state import EffectiveState
from app.effective_state.exceptions import (
    EffectiveStateNotFoundError,
    EffectiveStateValidationError,
)
from app.effective_state.models import (
    EffectiveStateDraft,
    canonical_scope_key,
    scope_from_dict,
    typed_value_from_dict,
    validate_effective_state_draft,
)
from app.effective_state.policy import (
    FactOperation, MappingOperationPolicy, get_field_policy,
    get_mapping_operation_policy,
    validate_policy_metadata,
)
from app.training.dsl import MappingDefinition
from app.effective_state.resolver import resolve_security_facts
from app.profile_resolution import PROFILE_REGISTRY
from app.security_model import TypedValueType, validate_field_value_scope


def validate_resolver_facts(
    db: Session,
    *,
    audit_id: UUID,
    organization_id: UUID,
    facts: tuple[SecurityFact, ...],
) -> Audit:
    """Validate that only persisted facts in one pinned Audit can be resolved."""
    validate_policy_metadata()
    audit = db.scalar(select(Audit).where(
        Audit.audit_id == audit_id, Audit.organization_id == organization_id
    ))
    if audit is None:
        raise EffectiveStateNotFoundError("Audit was not found")
    snapshot = db.get(Snapshot, audit.snapshot_id)
    device = db.get(Device, audit.device_id)
    profile_version_id = audit.profile_resolution.get("profile_version_id")
    pinned_profile = audit.version_refs.get("device_profile_version_id")
    pinned_pack = audit.version_refs.get("knowledge_pack_version_id")
    if (
        snapshot is None or device is None or snapshot.device_id != audit.device_id
        or snapshot.organization_id != organization_id or device.organization_id != organization_id
        or audit.profile_resolution.get("resolution_status") != "resolved"
        or profile_version_id not in PROFILE_REGISTRY
        or pinned_profile != profile_version_id or not isinstance(pinned_pack, str)
    ):
        raise EffectiveStateValidationError("Audit version or ownership boundary is incompatible")
    for fact in facts:
        if (
            fact.audit_id != audit.audit_id or fact.device_id != audit.device_id
            or fact.snapshot_id != audit.snapshot_id
        ):
            raise EffectiveStateValidationError("SecurityFact crosses the Audit boundary")
        if str(fact.knowledge_pack_version_id) != pinned_pack:
            raise EffectiveStateValidationError("SecurityFact knowledge-pack pin is incompatible")
        scope = scope_from_dict(fact.scope)
        value = typed_value_from_dict(fact.value)
        operation = _operation_policy(db, audit, fact)
        if value.type is TypedValueType.NULL:
            if operation.operation.value != "reset":
                raise EffectiveStateValidationError("SecurityFact null value is unsupported")
        else:
            try:
                validate_field_value_scope(fact.field_id, value, scope)
            except ValueError as exc:
                raise EffectiveStateValidationError("SecurityFact value is malformed") from exc
        get_field_policy(fact.field_id)
    return audit


def persist_effective_state(
    db: Session,
    *,
    organization_id: UUID,
    draft: EffectiveStateDraft,
) -> EffectiveState:
    """Persist one deterministic, immutable EffectiveState without resolving facts."""
    validate_effective_state_draft(draft)
    facts = tuple(db.scalars(select(SecurityFact).where(
        SecurityFact.fact_id.in_(draft.source_fact_ids)
    ))) if draft.source_fact_ids else ()
    if len(facts) != len(draft.source_fact_ids):
        raise EffectiveStateValidationError("EffectiveState source fact is missing")
    validate_resolver_facts(
        db, audit_id=draft.audit_id, organization_id=organization_id, facts=facts
    )
    for fact in facts:
        if fact.field_id != draft.field_id:
            raise EffectiveStateValidationError("EffectiveState source field is incompatible")
    key = canonical_scope_key(draft.scope)
    existing = db.scalar(select(EffectiveState).where(
        EffectiveState.audit_id == draft.audit_id,
        EffectiveState.field_id == draft.field_id,
        EffectiveState.scope_key == key,
    ))
    if existing is not None:
        if existing.effective_state_id != draft.effective_state_id:
            raise EffectiveStateValidationError("EffectiveState uniqueness is inconsistent")
        return existing
    state = EffectiveState(
        effective_state_id=draft.effective_state_id,
        audit_id=draft.audit_id,
        device_id=draft.device_id,
        field_id=draft.field_id,
        scope=draft.scope.to_dict(),
        scope_key=key,
        effective_value=(draft.effective_value.to_dict() if draft.effective_value else None),
        resolution_status=draft.resolution_status,
        source_fact_ids=[str(item) for item in draft.source_fact_ids],
        resolution_trace=list(draft.resolution_trace),
        inherited_from=(draft.inherited_from.to_dict() if draft.inherited_from else None),
        default_reference=draft.default_reference,
        referenced_objects=list(draft.referenced_objects),
        precedence_applied=list(draft.precedence_applied),
        unresolved_reason=draft.unresolved_reason,
        created_at=draft.created_at,
        schema_version=draft.schema_version,
    )
    db.add(state)
    return state


def resolve_audit_effective_states(
    db: Session, *, audit_id: UUID, organization_id: UUID
) -> tuple[EffectiveState, ...]:
    """Resolve and replace only retryable outputs for one still-processing Audit."""
    facts = tuple(db.scalars(select(SecurityFact).where(
        SecurityFact.audit_id == audit_id
    ).order_by(SecurityFact.fact_id)))
    audit = validate_resolver_facts(
        db, audit_id=audit_id, organization_id=organization_id, facts=facts
    )
    operations = {fact.fact_id: _operation_policy(db, audit, fact).operation for fact in facts}
    drafts = resolve_security_facts(audit_id=audit.audit_id, device_id=audit.device_id, facts=facts, operations=operations)
    existing = tuple(db.scalars(select(EffectiveState).where(
        EffectiveState.audit_id == audit_id
    )))
    if existing:
        # Step 6 has not completed the Audit lifecycle; retry outputs are replaceable.
        for state in existing:
            db.delete(state)
        db.flush()
    states = tuple(
        persist_effective_state(db, organization_id=organization_id, draft=draft)
        for draft in drafts
    )
    db.flush()
    # The coordinator commits in its own checkpoint; retain a stable read-only
    # result without allowing that commit to expire these returned ORM objects.
    for state in states:
        db.expunge(state)
    return states


def _operation_policy(db: Session, audit: Audit, fact: SecurityFact) -> MappingOperationPolicy:
    """Resolve static policies first, then exact immutable Step 11 pack membership."""
    try:
        return get_mapping_operation_policy(fact.knowledge_pack_version_id, fact.mapping_version_id, fact.field_id)
    except EffectiveStateValidationError:
        pass
    if fact.mapping_version_id is None or str(fact.knowledge_pack_version_id) != audit.version_refs.get("knowledge_pack_version_id"):
        raise EffectiveStateValidationError("SecurityFact mapping provenance is incompatible")
    pack = db.scalar(select(KnowledgePackVersionRecord).where(
        KnowledgePackVersionRecord.knowledge_pack_version_id == fact.knowledge_pack_version_id,
        KnowledgePackVersionRecord.organization_id == audit.organization_id,
    ))
    mapping = db.scalar(select(MappingVersion).where(
        MappingVersion.mapping_version_id == fact.mapping_version_id,
        MappingVersion.organization_id == audit.organization_id,
    ))
    if pack is None or mapping is None or str(mapping.mapping_version_id) not in pack.mapping_version_ids or mapping.status not in {MappingStatus.PUBLISHED, MappingStatus.SUPERSEDED} or mapping.target_field_id != fact.field_id:
        raise EffectiveStateValidationError("SecurityFact mapping provenance is incompatible")
    try:
        definition = MappingDefinition.model_validate({"profile_applicability": mapping.profile_applicability, "structural_match": mapping.structural_match, "target_field_id": mapping.target_field_id, "value_extraction": mapping.value_extraction, "unit_conversion": mapping.unit_conversion, "scope_resolution": mapping.scope_resolution, "negation_behavior": mapping.negation_behavior, "removal_behavior": mapping.removal_behavior, "default_behavior": mapping.default_behavior, "examples": mapping.examples})
    except ValueError:
        raise EffectiveStateValidationError("SecurityFact mapping definition is invalid") from None
    if definition.target_field_id != fact.field_id:
        raise EffectiveStateValidationError("SecurityFact mapping provenance is incompatible")
    operation = FactOperation.RESET if fact.value.get("type") == "null" and definition.negation_behavior.operation == "reset_to_default" else FactOperation.ASSIGN
    return MappingOperationPolicy(fact.knowledge_pack_version_id, mapping.mapping_version_id, fact.field_id, operation)
