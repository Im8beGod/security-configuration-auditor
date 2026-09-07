from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy import CheckConstraint, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB

from app.db.models import EffectiveState
from app.effective_state.exceptions import EffectiveStateValidationError
from app.effective_state.models import (
    ResolutionStatus,
    UnresolvedReason,
    canonical_scope_key,
    deterministic_effective_state_id,
    make_effective_state_draft,
    scope_from_dict,
    typed_value_from_dict,
    validate_effective_state_draft,
)
from app.effective_state.policy import (
    FIELD_POLICIES,
    FieldCardinality,
    lookup_documented_default,
    validate_policy_metadata,
)
from app.effective_state.service import validate_resolver_facts
from app.effective_state.resolver import resolve_security_facts
from app.knowledge_packs.cisco_iosxe_17 import CISCO_IOS_XE_17_KNOWLEDGE_PACK
from app.profile_resolution import CISCO_IOS_XE_17
from app.security_model import ScopeRef, TypedValue, TypedValueType


AUDIT_ID = UUID("10000000-0000-0000-0000-000000000001")
DEVICE_ID = UUID("20000000-0000-0000-0000-000000000001")
FACT_ID = UUID("30000000-0000-0000-0000-000000000001")
SCOPE = ScopeRef("vty_range", "vty:0-4", {"start": 0, "end": 4})


def test_scope_key_is_canonical_and_distinguishes_scope_attributes():
    equivalent = ScopeRef("vty_range", "vty:0-4", {"end": 4, "start": 0})
    other = ScopeRef("vty_range", "vty:5-15", {"start": 5, "end": 15})

    assert canonical_scope_key(SCOPE) == "vty_range::vty:0-4"
    assert canonical_scope_key(equivalent) == canonical_scope_key(SCOPE)
    assert canonical_scope_key(other) != canonical_scope_key(SCOPE)
    assert canonical_scope_key(ScopeRef("vty_range", "vty:0-4", {})) == canonical_scope_key(SCOPE)
    with pytest.raises(EffectiveStateValidationError, match="ScopeRef"):
        canonical_scope_key(ScopeRef("vty_range", "vty:0-4", {"start": 4, "end": 0}))


def test_deterministic_identity_converges_by_audit_field_and_scope():
    first = deterministic_effective_state_id(AUDIT_ID, "management.remote.ssh.enabled", SCOPE)
    second = deterministic_effective_state_id(AUDIT_ID, "management.remote.ssh.enabled", SCOPE)
    changed_scope = deterministic_effective_state_id(
        AUDIT_ID, "management.remote.ssh.enabled", ScopeRef("vty_range", "vty:5-15", {"start": 5, "end": 15})
    )

    assert first == second
    assert first != changed_scope


def test_effective_state_status_and_value_invariants_fail_closed():
    resolved = make_effective_state_draft(
        audit_id=AUDIT_ID,
        device_id=DEVICE_ID,
        field_id="management.remote.ssh.enabled",
        scope=SCOPE,
        effective_value=TypedValue(TypedValueType.BOOLEAN, True),
        resolution_status=ResolutionStatus.RESOLVED,
        source_fact_ids=(FACT_ID,),
    )
    validate_effective_state_draft(resolved)

    with pytest.raises(EffectiveStateValidationError, match="Unknown"):
        validate_effective_state_draft(replace(
            resolved,
            effective_value=None,
            resolution_status=ResolutionStatus.UNKNOWN,
            unresolved_reason=None,
        ))
    with pytest.raises(EffectiveStateValidationError, match="Conflicting"):
        validate_effective_state_draft(replace(
            resolved,
            effective_value=None,
            resolution_status=ResolutionStatus.CONFLICTING,
            unresolved_reason=UnresolvedReason.AMBIGUOUS_SCOPE,
        ))
    unknown = make_effective_state_draft(
        audit_id=AUDIT_ID,
        device_id=DEVICE_ID,
        field_id="management.remote.ssh.enabled",
        scope=SCOPE,
        effective_value=None,
        resolution_status=ResolutionStatus.UNKNOWN,
        source_fact_ids=(FACT_ID,),
        unresolved_reason=UnresolvedReason.UNRESOLVED_DEFAULT,
    )
    assert unknown.effective_value is None


def test_typed_value_and_scope_deserialization_reuses_canonical_validation():
    typed = typed_value_from_dict({
        "type": "duration", "value": 600, "unit": "seconds",
        "original_value": "10 0", "original_unit": "minutes_seconds",
    })
    scope = scope_from_dict({
        "type": "vty_range", "key": "vty:0-4", "attributes": {"start": 0, "end": 4},
    })
    assert typed == TypedValue(TypedValueType.DURATION, 600, "seconds", "10 0", "minutes_seconds")
    assert scope == SCOPE
    with pytest.raises(EffectiveStateValidationError, match="TypedValue"):
        typed_value_from_dict({"type": "boolean", "value": True})
    with pytest.raises(EffectiveStateValidationError, match="ScopeRef"):
        scope_from_dict({"type": "device", "key": "wrong", "attributes": {}})


def test_policy_is_bounded_and_default_lookup_is_safely_empty():
    assert FIELD_POLICIES["logging.remote.destination"].cardinality is FieldCardinality.REPEATABLE
    assert FIELD_POLICIES["management.remote.ssh.enabled"].cardinality is FieldCardinality.SCALAR
    assert lookup_documented_default(
        "cisco.ios_xe.17@1.0.0",
        UUID("dbad6d61-97d6-5e42-a1aa-feb4e28e15b0"),
        "management.remote.ssh.enabled",
        "vty_range",
    ) is None
    with pytest.raises(EffectiveStateValidationError, match="default metadata"):
        validate_policy_metadata(registry={
            ("cisco.ios_xe.17@1.0.0", UUID(int=1), "invented.field", "device"): {}
        })


def test_effective_state_orm_contract_enforces_immutable_identity_and_json_shapes():
    table = EffectiveState.__table__
    unique_columns = {
        tuple(constraint.columns.keys())
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    checks = {
        constraint.name for constraint in table.constraints if isinstance(constraint, CheckConstraint)
    }

    assert ("audit_id", "field_id", "scope_key") in unique_columns
    assert table.c.effective_state_id.primary_key
    assert not table.c.audit_id.nullable and not table.c.device_id.nullable
    assert isinstance(table.c.scope.type, JSONB)
    assert isinstance(table.c.effective_value.type, JSONB)
    assert "ck_effective_states_resolution_invariants" in checks
    assert "ck_effective_states_source_fact_ids" in checks


def test_resolver_rejects_security_facts_from_another_audit_or_device():
    mapping = next(
        item for item in CISCO_IOS_XE_17_KNOWLEDGE_PACK.mappings
        if item.field_id == "management.remote.ssh.enabled"
    )
    audit = SimpleNamespace(
        audit_id=AUDIT_ID,
        snapshot_id=UUID("40000000-0000-0000-0000-000000000001"),
        device_id=DEVICE_ID,
        profile_resolution={
            "profile_version_id": CISCO_IOS_XE_17.profile_version_id,
            "resolution_status": "resolved",
        },
        version_refs={
            "device_profile_version_id": CISCO_IOS_XE_17.profile_version_id,
            "knowledge_pack_version_id": str(CISCO_IOS_XE_17_KNOWLEDGE_PACK.knowledge_pack_version_id),
        },
    )
    snapshot = SimpleNamespace(
        snapshot_id=audit.snapshot_id, device_id=DEVICE_ID, organization_id=UUID(int=9)
    )
    device = SimpleNamespace(device_id=DEVICE_ID, organization_id=UUID(int=9))
    db = SimpleNamespace(scalar=lambda _statement: audit, get=lambda model, _id: (
        snapshot if model.__name__ == "Snapshot" else device
    ))
    fact = SimpleNamespace(
        audit_id=UUID(int=999), device_id=DEVICE_ID, snapshot_id=audit.snapshot_id,
        knowledge_pack_version_id=CISCO_IOS_XE_17_KNOWLEDGE_PACK.knowledge_pack_version_id,
        mapping_version_id=mapping.mapping_version_id, field_id=mapping.field_id,
        scope=SCOPE.to_dict(), value=TypedValue(TypedValueType.BOOLEAN, True).to_dict(),
    )

    with pytest.raises(EffectiveStateValidationError, match="crosses"):
        validate_resolver_facts(
            db, audit_id=AUDIT_ID, organization_id=UUID(int=9), facts=(fact,)
        )


def _resolver_fact(*, number, field_id, value, scope, mapping_version_id, artifact_id="artifact-a", line=1):
    return SimpleNamespace(
        fact_id=UUID(int=number), field_id=field_id, value=value.to_dict(),
        scope=scope.to_dict(), mapping_version_id=mapping_version_id,
        knowledge_pack_version_id=UUID("dbad6d61-97d6-5e42-a1aa-feb4e28e15b0"),
        evidence_refs=[{"artifact_id": artifact_id, "start_line": line}], dependencies=[],
    )


def test_scalar_resolution_deduplicates_and_conflicts_without_cross_artifact_ordering():
    mapping = UUID("82f62960-c06e-5ee1-a1ce-ccd574ead730")
    first = _resolver_fact(number=11, field_id="management.remote.ssh.enabled", value=TypedValue(TypedValueType.BOOLEAN, True), scope=SCOPE, mapping_version_id=mapping)
    duplicate = _resolver_fact(number=12, field_id="management.remote.ssh.enabled", value=TypedValue(TypedValueType.BOOLEAN, True), scope=SCOPE, mapping_version_id=mapping, artifact_id="artifact-b")
    resolved = resolve_security_facts(audit_id=AUDIT_ID, device_id=DEVICE_ID, facts=(first, duplicate))
    assert resolved[0].resolution_status is ResolutionStatus.RESOLVED
    assert resolved[0].source_fact_ids == (UUID(int=11), UUID(int=12))
    conflict = _resolver_fact(number=13, field_id="management.remote.ssh.enabled", value=TypedValue(TypedValueType.BOOLEAN, False), scope=SCOPE, mapping_version_id=mapping, artifact_id="artifact-c")
    outcome = resolve_security_facts(audit_id=AUDIT_ID, device_id=DEVICE_ID, facts=(first, conflict))[0]
    assert outcome.resolution_status is ResolutionStatus.CONFLICTING
    assert outcome.unresolved_reason is UnresolvedReason.CONFLICTING_EVIDENCE


def test_vty_broad_then_narrow_uses_same_artifact_source_order():
    mapping = UUID("a153b5c4-786d-5940-9fc7-2906ea7d42c7")
    broad = _resolver_fact(number=21, field_id="management.session.idle_timeout", value=TypedValue(TypedValueType.DURATION, 600, "seconds"), scope=SCOPE, mapping_version_id=mapping)
    narrow_scope = ScopeRef("vty_range", "vty:2-3", {"start": 2, "end": 3})
    narrow = _resolver_fact(number=22, field_id="management.session.idle_timeout", value=TypedValue(TypedValueType.DURATION, 300, "seconds"), scope=narrow_scope, mapping_version_id=mapping, line=2)
    outcomes = resolve_security_facts(audit_id=AUDIT_ID, device_id=DEVICE_ID, facts=(broad, narrow))
    assert [(item.scope.key, item.effective_value.value) for item in outcomes] == [
        ("vty:0-1", 600), ("vty:2-3", 300), ("vty:4-4", 600)
    ]
    assert outcomes[1].precedence_applied == ({
        "rule": "same_artifact_source_order", "winner_fact_id": str(narrow.fact_id)
    },)


def test_vty_narrow_then_broad_allows_later_broad_operation_to_supersede_overlap():
    mapping = UUID("a153b5c4-786d-5940-9fc7-2906ea7d42c7")
    narrow_scope = ScopeRef("vty_range", "vty:2-3", {"start": 2, "end": 3})
    narrow = _resolver_fact(number=23, field_id="management.session.idle_timeout", value=TypedValue(TypedValueType.DURATION, 300, "seconds"), scope=narrow_scope, mapping_version_id=mapping, line=1)
    broad = _resolver_fact(number=24, field_id="management.session.idle_timeout", value=TypedValue(TypedValueType.DURATION, 600, "seconds"), scope=SCOPE, mapping_version_id=mapping, line=2)
    outcomes = resolve_security_facts(audit_id=AUDIT_ID, device_id=DEVICE_ID, facts=(narrow, broad))
    assert [(item.scope.key, item.effective_value.value) for item in outcomes] == [
        ("vty:0-1", 600), ("vty:2-3", 600), ("vty:4-4", 600)
    ]


def test_vty_same_value_overlap_is_not_a_false_conflict_and_partitions_deterministically():
    mapping = UUID("a153b5c4-786d-5940-9fc7-2906ea7d42c7")
    narrow_scope = ScopeRef("vty_range", "vty:2-3", {"start": 2, "end": 3})
    broad = _resolver_fact(number=25, field_id="management.session.idle_timeout", value=TypedValue(TypedValueType.DURATION, 600, "seconds"), scope=SCOPE, mapping_version_id=mapping, line=1)
    narrow = _resolver_fact(number=26, field_id="management.session.idle_timeout", value=TypedValue(TypedValueType.DURATION, 600, "seconds"), scope=narrow_scope, mapping_version_id=mapping, line=2)
    first = resolve_security_facts(audit_id=AUDIT_ID, device_id=DEVICE_ID, facts=(broad, narrow))
    second = resolve_security_facts(audit_id=AUDIT_ID, device_id=DEVICE_ID, facts=(narrow, broad))
    assert [item.resolution_status for item in first] == [ResolutionStatus.RESOLVED] * 3
    assert [(item.scope.key, item.effective_value.to_dict()) for item in first] == [
        (item.scope.key, item.effective_value.to_dict()) for item in second
    ]


def test_vty_cross_artifact_overlap_conflicts_without_fabricated_order():
    mapping = UUID("a153b5c4-786d-5940-9fc7-2906ea7d42c7")
    narrow_scope = ScopeRef("vty_range", "vty:2-3", {"start": 2, "end": 3})
    broad = _resolver_fact(number=27, field_id="management.session.idle_timeout", value=TypedValue(TypedValueType.DURATION, 600, "seconds"), scope=SCOPE, mapping_version_id=mapping, artifact_id="artifact-a", line=10)
    narrow = _resolver_fact(number=28, field_id="management.session.idle_timeout", value=TypedValue(TypedValueType.DURATION, 300, "seconds"), scope=narrow_scope, mapping_version_id=mapping, artifact_id="artifact-b", line=1)
    outcomes = resolve_security_facts(audit_id=AUDIT_ID, device_id=DEVICE_ID, facts=(broad, narrow))
    assert outcomes[1].scope.key == "vty:2-3"
    assert outcomes[1].resolution_status is ResolutionStatus.CONFLICTING
    assert outcomes[1].unresolved_reason is UnresolvedReason.CONFLICTING_EVIDENCE


def test_vty_reset_inside_overlap_obeys_same_artifact_source_order():
    assign = UUID("a153b5c4-786d-5940-9fc7-2906ea7d42c7")
    reset = UUID("fa460558-d8fc-58a8-af78-caaa6272e861")
    narrow_scope = ScopeRef("vty_range", "vty:2-3", {"start": 2, "end": 3})
    broad = _resolver_fact(number=29, field_id="management.session.idle_timeout", value=TypedValue(TypedValueType.DURATION, 600, "seconds"), scope=SCOPE, mapping_version_id=assign, line=1)
    reset_fact = _resolver_fact(number=30, field_id="management.session.idle_timeout", value=TypedValue(TypedValueType.NULL, None), scope=narrow_scope, mapping_version_id=reset, line=2)
    outcomes = resolve_security_facts(audit_id=AUDIT_ID, device_id=DEVICE_ID, facts=(broad, reset_fact))
    assert [(item.scope.key, item.resolution_status, item.unresolved_reason) for item in outcomes] == [
        ("vty:0-1", ResolutionStatus.RESOLVED, None),
        ("vty:2-3", ResolutionStatus.UNKNOWN, UnresolvedReason.UNRESOLVED_DEFAULT),
        ("vty:4-4", ResolutionStatus.RESOLVED, None),
    ]


def test_effective_state_resolver_does_not_depend_on_raw_configuration_parsing():
    import inspect
    import app.effective_state.resolver as resolver

    source = inspect.getsource(resolver)
    assert "parse_artifact" not in source
    assert "parse_configuration_text" not in source
    assert "ArtifactStorage" not in source


def test_repeatable_add_remove_uses_persisted_source_order_only():
    assign = UUID("f112df12-f860-5fad-b013-7b89701d2fcf")
    remove = UUID("3fe025cc-e9bb-5860-a424-9273a7391c3a")
    device_scope = ScopeRef("device", "device", {})
    add_a = _resolver_fact(number=31, field_id="logging.remote.destination", value=TypedValue(TypedValueType.IP_ADDRESS, "192.0.2.1"), scope=device_scope, mapping_version_id=assign, line=1)
    add_b = _resolver_fact(number=32, field_id="logging.remote.destination", value=TypedValue(TypedValueType.IP_ADDRESS, "192.0.2.2"), scope=device_scope, mapping_version_id=assign, line=2)
    remove_a = _resolver_fact(number=33, field_id="logging.remote.destination", value=TypedValue(TypedValueType.IP_ADDRESS, "192.0.2.1"), scope=device_scope, mapping_version_id=remove, line=3)
    outcome = resolve_security_facts(audit_id=AUDIT_ID, device_id=DEVICE_ID, facts=(add_a, add_b, remove_a))[0]
    assert outcome.effective_value.type is TypedValueType.LIST
    assert [item["value"] for item in outcome.effective_value.value] == ["192.0.2.2"]


def test_missing_or_cyclic_dependencies_fail_closed_to_unknown():
    mapping = UUID("82f62960-c06e-5ee1-a1ce-ccd574ead730")
    fact = _resolver_fact(number=41, field_id="management.remote.ssh.enabled", value=TypedValue(TypedValueType.BOOLEAN, True), scope=SCOPE, mapping_version_id=mapping)
    fact.dependencies = [str(UUID(int=999))]
    missing = resolve_security_facts(audit_id=AUDIT_ID, device_id=DEVICE_ID, facts=(fact,))[0]
    assert missing.resolution_status is ResolutionStatus.UNKNOWN
    assert missing.unresolved_reason is UnresolvedReason.MISSING_EVIDENCE
    first = _resolver_fact(number=42, field_id="management.remote.ssh.enabled", value=TypedValue(TypedValueType.BOOLEAN, True), scope=SCOPE, mapping_version_id=mapping)
    second = _resolver_fact(number=43, field_id="management.remote.ssh.enabled", value=TypedValue(TypedValueType.BOOLEAN, True), scope=SCOPE, mapping_version_id=mapping)
    first.dependencies, second.dependencies = [str(second.fact_id)], [str(first.fact_id)]
    cyclic = resolve_security_facts(audit_id=AUDIT_ID, device_id=DEVICE_ID, facts=(first, second))[0]
    assert cyclic.resolution_status is ResolutionStatus.UNKNOWN
