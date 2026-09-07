from __future__ import annotations

import json
import re
from copy import deepcopy
from uuid import uuid4

import pytest
from sqlalchemy import CheckConstraint, JSON, MetaData, create_engine, event, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models import (
    Audit,
    AuditReevaluationReason,
    AuditStatus,
    Device,
    EffectiveState,
    FactState,
    FactValidationStatus,
    InterpretationConfidence,
    InterpretationMethod,
    KnowledgePackRecord,
    KnowledgePackVersionRecord,
    MappingOrigin,
    MappingStatus,
    MappingVersion,
    Organization,
    SecurityFact,
    Snapshot,
    SnapshotGroupingStatus,
    SnapshotSource,
    SnapshotStatus,
    User,
    UserRole,
)
from app.effective_state.exceptions import EffectiveStateValidationError
from app.effective_state.policy import MAPPING_OPERATION_POLICIES
from app.effective_state.service import resolve_audit_effective_states
from app.profile_resolution import CISCO_IOS_XE_17
from app.security_model import ScopeRef, TypedValue, TypedValueType


PROFILE_VERSION_ID = CISCO_IOS_XE_17.profile_version_id
FIELD_ID = "management.session.idle_timeout"
SCOPE = ScopeRef("vty_range", "vty:0-4", {"start": 0, "end": 4})


@pytest.fixture
def bridge_factory():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    @event.listens_for(engine, "connect")
    def sqlite_functions(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.create_function("btrim", 1, lambda value: value.strip())
        connection.create_function("char_length", 1, len)
        connection.create_function(
            "jsonb_typeof",
            1,
            lambda value: (
                "array" if isinstance(value, list)
                else "object" if isinstance(value, dict)
                else "object" if isinstance(value, str) and isinstance(json.loads(value), dict)
                else "array" if isinstance(value, str) and isinstance(json.loads(value), list)
                else "other"
            ),
        )
        connection.create_function(
            "regexp", 2, lambda pattern, value: re.fullmatch(pattern, value) is not None
        )

    metadata = MetaData()
    tables = [
        Organization, User, Device, Snapshot, Audit, SecurityFact, EffectiveState,
        KnowledgePackRecord, KnowledgePackVersionRecord, MappingVersion,
    ]
    copied = {model: model.__table__.to_metadata(metadata) for model in tables}
    for table in copied.values():
        for column in table.columns:
            if isinstance(column.type, JSONB):
                column.type = JSON()
                column.server_default = None
    for table, constraint_name, expression in (
        (copied[Organization], "ck_organizations_slug", "slug REGEXP '^[a-z0-9]+(-[a-z0-9]+)*$'"),
        (copied[Snapshot], "ck_snapshots_snapshot_hash", "snapshot_hash REGEXP '^[0-9a-f]{64}$'"),
    ):
        constraint = next(item for item in table.constraints if item.name == constraint_name)
        table.constraints.remove(constraint)
        table.append_constraint(CheckConstraint(expression, name=constraint_name))
    metadata.create_all(engine)
    try:
        yield sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    finally:
        engine.dispose()


def _definition(*, target_field_id: str = FIELD_ID, malformed: bool = False) -> dict:
    definition = {
        "profile_applicability": {"profile_version_ids": [PROFILE_VERSION_ID]},
        "structural_match": {
            "command": "exec-timeout",
            "parent_command": "line",
            "scope_type": "vty_range",
            "arguments": [
                {"operation": "capture", "name": "minutes", "value_type": "integer"},
                {"operation": "capture", "name": "seconds", "value_type": "integer"},
            ],
        },
        "target_field_id": target_field_id,
        "value_extraction": {
            "operation": "duration_from_parts",
            "parts": ["minutes", "seconds"],
            "output_type": "duration",
        },
        "unit_conversion": {"operation": "none"},
        "scope_resolution": {"strategy": "vty_range"},
        "negation_behavior": {"operation": "reset_to_default"},
        "removal_behavior": {"operation": "remove_value"},
        "default_behavior": {"operation": "unknown"},
        "examples": [],
    }
    if malformed:
        definition["structural_match"] = {"command": 7}
    return definition


def _mapping(*, organization_id, user_id, pack_id, status=MappingStatus.PUBLISHED, target_field_id=FIELD_ID, malformed=False):
    definition = _definition(target_field_id=target_field_id, malformed=malformed)
    return MappingVersion(
        mapping_id=uuid4(), organization_id=organization_id, mapping_key=f"mapping-{uuid4().hex}",
        version=1, title="Persisted mapping", description="Test mapping", status=status,
        profile_applicability=definition["profile_applicability"],
        structural_match=definition["structural_match"], target_field_id=target_field_id,
        value_extraction=definition["value_extraction"], unit_conversion=definition["unit_conversion"],
        scope_resolution=definition["scope_resolution"], negation_behavior=definition["negation_behavior"],
        removal_behavior=definition["removal_behavior"], default_behavior=definition["default_behavior"],
        examples=definition["examples"], validation_results={}, origin=MappingOrigin.ADMINISTRATOR,
        created_by=user_id, knowledge_pack_version_id=pack_id,
    )


def _source(db, *, organization_id, user_id, pack_id, mapping_id, field_id=FIELD_ID, device_id=None):
    device = Device(organization_id=organization_id, display_name="Bridge device")
    db.add(device)
    db.flush()
    snapshot = Snapshot(
        device_id=device.device_id, organization_id=organization_id, label="bridge",
        grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED, snapshot_hash="a" * 64,
        artifact_count=0, source=SnapshotSource.UPLOAD, status=SnapshotStatus.LOCKED,
        created_by=user_id,
    )
    db.add(snapshot)
    db.flush()
    audit = Audit(
        organization_id=organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id,
        revision_number=1, reevaluation_reason=AuditReevaluationReason.INITIAL,
        status=AuditStatus.COMPLETED, selected_frameworks=[],
        version_refs={"device_profile_version_id": PROFILE_VERSION_ID, "knowledge_pack_version_id": str(pack_id)},
        profile_resolution={"profile_version_id": PROFILE_VERSION_ID, "resolution_status": "resolved"},
        verdict_counts={}, severity_counts={}, coverage={}, created_by=user_id,
    )
    db.add(audit)
    db.flush()
    fact = SecurityFact(
        fact_id=uuid4(), audit_id=audit.audit_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id,
        field_id=field_id, value=TypedValue(TypedValueType.DURATION, 300, "seconds").to_dict(),
        entity=None, scope=SCOPE.to_dict(), state=FactState.EXPLICIT,
        evidence_refs=[{"artifact_id": str(uuid4()), "start_line": 1}],
        source_ir_node_ids=["node-1"], extraction_method=InterpretationMethod.ADMINISTRATOR_VALIDATED_MAPPING,
        mapping_id=uuid4(), mapping_version_id=mapping_id, knowledge_pack_version_id=pack_id,
        validation_status=FactValidationStatus.ADMINISTRATOR_VALIDATED, dependencies=[],
        interpretation_confidence=InterpretationConfidence.HIGH,
    )
    db.add(fact)
    db.flush()
    return audit, fact


def _scenario(db, *, status=MappingStatus.PUBLISHED, pack_contains=True, mapping_org=None, pack_org=None, target_field_id=FIELD_ID, malformed=False):
    organization = Organization(slug=f"org-{uuid4().hex[:12]}", name="Bridge org")
    db.add(organization)
    db.flush()
    user = User(organization_id=organization.organization_id, email=f"user-{uuid4().hex}@example.invalid", password_hash="test-hash", role=UserRole.ADMIN)
    db.add(user)
    db.flush()
    pack_owner = pack_org or organization.organization_id
    mapping_owner = mapping_org or organization.organization_id
    pack = KnowledgePackRecord(organization_id=pack_owner, pack_key=f"pack-{uuid4().hex}", name="Bridge pack")
    db.add(pack)
    db.flush()
    pack_version = KnowledgePackVersionRecord(
        knowledge_pack_id=pack.knowledge_pack_id, organization_id=pack_owner, version=1,
        mapping_version_ids=[], published_by=user.user_id,
    )
    db.add(pack_version)
    db.flush()
    mapping = _mapping(
        organization_id=mapping_owner, user_id=user.user_id, pack_id=pack_version.knowledge_pack_version_id,
        status=status, target_field_id=target_field_id, malformed=malformed,
    )
    db.add(mapping)
    db.flush()
    if pack_contains:
        pack_version.mapping_version_ids = [str(mapping.mapping_version_id)]
    audit, fact = _source(
        db, organization_id=organization.organization_id, user_id=user.user_id,
        pack_id=pack_version.knowledge_pack_version_id, mapping_id=mapping.mapping_version_id,
        field_id=FIELD_ID,
    )
    return organization, user, pack_version, mapping, audit, fact


def _state_count(db, audit_id):
    return db.scalar(select(func.count()).select_from(EffectiveState).where(EffectiveState.audit_id == audit_id))


def test_valid_published_learned_mapping_is_accepted(bridge_factory):
    with bridge_factory.begin() as db:
        _org, _user, _pack, mapping, audit, _fact = _scenario(db)
        states = resolve_audit_effective_states(db, audit_id=audit.audit_id, organization_id=audit.organization_id)
        assert len(states) == 1
        assert {
            key: states[0].effective_value[key]
            for key in ("type", "value", "unit")
        } == {"type": "duration", "value": 300, "unit": "seconds"}
        assert _state_count(db, audit.audit_id) == 1
        assert mapping.status is MappingStatus.PUBLISHED


def _assert_status_rejected(bridge_factory, status):
    with bridge_factory.begin() as db:
        _org, _user, _pack, _mapping_row, audit, _fact = _scenario(db, status=status)
        with pytest.raises(EffectiveStateValidationError, match="provenance"):
            resolve_audit_effective_states(db, audit_id=audit.audit_id, organization_id=audit.organization_id)
        assert _state_count(db, audit.audit_id) == 0


def test_draft_mapping_is_rejected(bridge_factory):
    _assert_status_rejected(bridge_factory, MappingStatus.DRAFT)


def test_testing_mapping_is_rejected(bridge_factory):
    _assert_status_rejected(bridge_factory, MappingStatus.TESTING)


def test_approved_unpublished_mapping_is_rejected(bridge_factory):
    _assert_status_rejected(bridge_factory, MappingStatus.APPROVED)


def test_rejected_mapping_is_rejected(bridge_factory):
    _assert_status_rejected(bridge_factory, MappingStatus.REJECTED)


def test_persisted_mapping_wrong_target_field_is_rejected(bridge_factory):
    with bridge_factory.begin() as db:
        _org, _user, _pack, _mapping_row, audit, _fact = _scenario(db, target_field_id="management.remote.ssh.enabled")
        with pytest.raises(EffectiveStateValidationError, match="provenance"):
            resolve_audit_effective_states(db, audit_id=audit.audit_id, organization_id=audit.organization_id)
        assert _state_count(db, audit.audit_id) == 0


def test_persisted_mapping_not_in_exact_pinned_pack_is_rejected(bridge_factory):
    with bridge_factory.begin() as db:
        _org, _user, _pack, _mapping_row, audit, _fact = _scenario(db, pack_contains=False)
        with pytest.raises(EffectiveStateValidationError, match="provenance"):
            resolve_audit_effective_states(db, audit_id=audit.audit_id, organization_id=audit.organization_id)
        assert _state_count(db, audit.audit_id) == 0


def test_cross_tenant_persisted_mapping_is_rejected(bridge_factory):
    with bridge_factory.begin() as db:
        first = Organization(slug=f"first-{uuid4().hex[:12]}", name="First")
        second = Organization(slug=f"second-{uuid4().hex[:12]}", name="Second")
        db.add_all((first, second)); db.flush()
        user = User(organization_id=first.organization_id, email=f"first-{uuid4().hex}@example.invalid", password_hash="test-hash", role=UserRole.ADMIN)
        db.add(user); db.flush()
        _org, _user, _pack, _mapping, audit, _fact = _scenario(
            db, mapping_org=second.organization_id, pack_org=second.organization_id,
        )
        with pytest.raises(EffectiveStateValidationError, match="provenance"):
            resolve_audit_effective_states(db, audit_id=audit.audit_id, organization_id=audit.organization_id)
        assert _state_count(db, audit.audit_id) == 0


def test_malformed_persisted_mapping_dsl_is_rejected(bridge_factory):
    with bridge_factory.begin() as db:
        _org, _user, _pack, _mapping_row, audit, _fact = _scenario(db, malformed=True)
        with pytest.raises(EffectiveStateValidationError, match="definition"):
            resolve_audit_effective_states(db, audit_id=audit.audit_id, organization_id=audit.organization_id)
        assert _state_count(db, audit.audit_id) == 0


def test_random_mapping_version_id_is_rejected(bridge_factory):
    with bridge_factory.begin() as db:
        _org, _user, _pack, _mapping_row, audit, fact = _scenario(db)
        fact.mapping_version_id = uuid4()
        with pytest.raises(EffectiveStateValidationError, match="provenance"):
            resolve_audit_effective_states(db, audit_id=audit.audit_id, organization_id=audit.organization_id)
        assert _state_count(db, audit.audit_id) == 0


def test_superseded_mapping_is_valid_only_through_exact_historical_pack(bridge_factory):
    with bridge_factory.begin() as db:
        _org, _user, old_pack, mapping, audit, _fact = _scenario(db, status=MappingStatus.SUPERSEDED)
        states = resolve_audit_effective_states(db, audit_id=audit.audit_id, organization_id=audit.organization_id)
        assert len(states) == 1
        other_pack = KnowledgePackRecord(organization_id=audit.organization_id, pack_key=f"other-{uuid4().hex}", name="Other")
        db.add(other_pack); db.flush()
        other_version = KnowledgePackVersionRecord(
            knowledge_pack_id=other_pack.knowledge_pack_id, organization_id=audit.organization_id, version=1,
            mapping_version_ids=[], published_by=audit.created_by,
        )
        db.add(other_version); db.flush()
        other_audit, _other_fact = _source(
            db, organization_id=audit.organization_id, user_id=audit.created_by,
            pack_id=other_version.knowledge_pack_version_id, mapping_id=mapping.mapping_version_id,
        )
        with pytest.raises(EffectiveStateValidationError, match="provenance"):
            resolve_audit_effective_states(db, audit_id=other_audit.audit_id, organization_id=audit.organization_id)
        assert _state_count(db, other_audit.audit_id) == 0
        assert old_pack.mapping_version_ids == [str(mapping.mapping_version_id)]


def test_persisted_mapping_does_not_mutate_static_registry(bridge_factory):
    before = deepcopy(dict(MAPPING_OPERATION_POLICIES))
    with bridge_factory.begin() as db:
        _org, _user, _pack, _mapping, audit, _fact = _scenario(db)
        resolve_audit_effective_states(db, audit_id=audit.audit_id, organization_id=audit.organization_id)
    assert dict(MAPPING_OPERATION_POLICIES) == before
