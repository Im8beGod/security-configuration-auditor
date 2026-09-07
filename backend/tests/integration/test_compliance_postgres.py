"""Opt-in PostgreSQL coverage for canonical Finding persistence and retry safety."""

import os
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError

from app.cli.bootstrap_admin import bootstrap_admin
from app.compliance.policy import OrganizationPolicyRegistry
from app.compliance.rule_registry import RULE_PACK
from app.compliance.service import ComplianceError, persist_audit_findings
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Audit, AuditReevaluationReason, AuditStatus, Device, EffectiveState, Finding,
    Organization, Snapshot, SnapshotGroupingStatus, SnapshotSource, SnapshotStatus, User,
)
from app.db.session import create_session_factory
from app.effective_state import ResolutionStatus
from app.profile_resolution import CISCO_IOS_XE_17
from app.security_model import ScopeRef, TypedValue, TypedValueType


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_STEP7_POSTGRES_TEST") != "1",
    reason="Set SIH_STEP7_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def _state(audit, field_id, value, scope):
    return EffectiveState(
        effective_state_id=uuid4(), audit_id=audit.audit_id, device_id=audit.device_id,
        field_id=field_id, scope=scope.to_dict(), scope_key=f"{scope.type}::{scope.key}",
        effective_value=value.to_dict(), resolution_status=ResolutionStatus.RESOLVED,
        source_fact_ids=[], resolution_trace=[], inherited_from=None, default_reference=None,
        referenced_objects=[], precedence_applied=[], unresolved_reason=None,
    )


def test_findings_are_deterministic_unique_and_retryable_only_while_processing():
    settings = get_settings()
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    organization_id = None
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260907_0007"
        suffix = uuid4().hex
        organization_id, user_id = bootstrap_admin(factory, "Step 7", f"step7-{suffix}", f"step7-{suffix}@example.invalid", "test-only-password")
        with factory.begin() as db:
            device = Device(organization_id=organization_id, display_name="Compliance Device")
            db.add(device)
            db.flush()
            snapshot = Snapshot(device_id=device.device_id, organization_id=organization_id, grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED, snapshot_hash="b" * 64, artifact_count=0, source=SnapshotSource.UPLOAD, status=SnapshotStatus.LOCKED, created_by=user_id)
            db.add(snapshot)
            db.flush()
            audit = Audit(organization_id=organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id, revision_number=1, reevaluation_reason=AuditReevaluationReason.INITIAL, status=AuditStatus.PROCESSING, selected_frameworks=[], version_refs={}, profile_resolution={"profile_version_id": CISCO_IOS_XE_17.profile_version_id, "resolution_status": "resolved"}, verdict_counts={}, severity_counts={}, coverage={}, created_by=user_id)
            db.add(audit)
            db.flush()
            scope_a = ScopeRef("vty_range", "vty:0-4", {"start": 0, "end": 4})
            scope_b = ScopeRef("vty_range", "vty:5-15", {"start": 5, "end": 15})
            db.add_all((
                _state(audit, "management.remote.telnet.enabled", TypedValue(TypedValueType.BOOLEAN, False), scope_a),
                _state(audit, "management.remote.telnet.enabled", TypedValue(TypedValueType.BOOLEAN, True), scope_b),
                _state(audit, "management.remote.ssh.enabled", TypedValue(TypedValueType.BOOLEAN, True), scope_a),
                _state(audit, "management.remote.ssh.version", TypedValue(TypedValueType.INTEGER, 2), ScopeRef("device", "device", {})),
                _state(audit, "management.session.idle_timeout", TypedValue(TypedValueType.DURATION, 300, "seconds"), scope_a),
                _state(audit, "logging.remote.destination", TypedValue(TypedValueType.LIST, [{"type": "ip_address", "value": "192.0.2.1"}]), ScopeRef("device", "device", {})),
                _state(audit, "time.ntp.server", TypedValue(TypedValueType.LIST, [{"type": "ip_address", "value": "192.0.2.2"}]), ScopeRef("device", "device", {})),
            ))
            db.flush()
            policy = OrganizationPolicyRegistry().register(organization_id=organization_id, name="test", version="1.0.0", parameters={"maximum_admin_idle_timeout_seconds": 300, "approved_logging_destinations": ["192.0.2.1"], "approved_ntp_servers": ["192.0.2.2"]})
            first = persist_audit_findings(db, audit_id=audit.audit_id, organization_id=organization_id, rule_pack=RULE_PACK, organization_policy=policy)
            first_ids = {item.finding_id for item in first}
            assert len(first) == 9  # Telnet produces one finding for each canonical VTY range.
            assert db.scalar(select(func.count()).select_from(Finding).where(Finding.audit_id == audit.audit_id)) == 9
            second = persist_audit_findings(db, audit_id=audit.audit_id, organization_id=organization_id, rule_pack=RULE_PACK, organization_policy=policy)
            assert {item.finding_id for item in second} == first_ids
            duplicate_values = {column.name: getattr(second[0], column.name) for column in Finding.__table__.columns}
            duplicate_values["finding_id"] = uuid4()
            duplicate = Finding(**duplicate_values)
            with pytest.raises(IntegrityError), db.begin_nested():
                db.add(duplicate)
                db.flush()
        with factory.begin() as db:
            audit = db.scalar(select(Audit).where(Audit.organization_id == organization_id))
            audit.status = AuditStatus.COMPLETED
            with pytest.raises(ComplianceError, match="still-processing"):
                persist_audit_findings(db, audit_id=audit.audit_id, organization_id=organization_id, rule_pack=RULE_PACK, organization_policy=None)
    finally:
        if organization_id is not None:
            with factory.begin() as db:
                audit_ids = select(Audit.audit_id).where(Audit.organization_id == organization_id)
                db.execute(delete(Finding).where(Finding.audit_id.in_(audit_ids)))
                db.execute(delete(EffectiveState).where(EffectiveState.audit_id.in_(audit_ids)))
                db.execute(delete(Audit).where(Audit.organization_id == organization_id))
                db.execute(delete(Snapshot).where(Snapshot.organization_id == organization_id))
                db.execute(delete(Device).where(Device.organization_id == organization_id))
                db.execute(delete(User).where(User.organization_id == organization_id))
                db.execute(delete(Organization).where(Organization.organization_id == organization_id))
        engine.dispose()
