"""Focused PostgreSQL proof for B1 assessment selection and result persistence."""

import os
from uuid import uuid4

import pytest
from sqlalchemy import select, text

from app.assessment_packs.service import (
    AssessmentPackError,
    compatible_packs,
    get_pack,
    pin_assessment,
    persist_assessment_results,
)
from app.compliance.verdicts import FindingSeverity, FindingVerdict
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    AssessmentPackVersion, Audit, AuditReevaluationReason, AuditStatus, Device,
    EffectiveState, Finding, Organization,
    Snapshot, SnapshotGroupingStatus, SnapshotSource, SnapshotStatus, User, UserRole,
)
from app.db.session import create_session_factory
from app.effective_state.contracts import ResolutionStatus


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_B1_POSTGRES_TEST") != "1",
    reason="Set SIH_B1_POSTGRES_TEST=1 with PostgreSQL available",
)


def _state(audit_id, device_id, value=True):
    return EffectiveState(
        effective_state_id=uuid4(), audit_id=audit_id, device_id=device_id,
        field_id="management.remote.ssh.enabled", scope={"type": "device", "key": str(device_id)},
        scope_key=f"device::{device_id}", effective_value={"type": "boolean", "value": value},
        resolution_status=ResolutionStatus.RESOLVED, source_fact_ids=[], resolution_trace=[],
        referenced_objects=[], precedence_applied=[],
    )


def _finding(audit_id, device_id):
    return Finding(
        finding_id=uuid4(), audit_id=audit_id, device_id=device_id,
        comparison_key="management.ssh.enabled::device::rule", rule_id="management.ssh.enabled",
        rule_pack_version_id=uuid4(), title="SSH management access", security_domain="management",
        verdict=FindingVerdict.PASS, severity=FindingSeverity.HIGH,
        expected_state={"operator": "equals", "value": True},
        observed_state={"type": "boolean", "value": True}, explanation="test finding",
        affected_scope=None, effective_state_refs=[], evidence_refs=[], unknown_reason=None,
        framework_references=[],
    )


def test_synthetic_packs_pin_and_change_results_without_changing_evidence():
    settings = get_settings()
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    with factory.begin() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "20260909_0014"
        organization = Organization(name="B1 Organization", slug=f"b1-{uuid4().hex[:12]}")
        other = Organization(name="B1 Other", slug=f"b1-other-{uuid4().hex[:12]}")
        db.add_all([organization, other])
        db.flush()
        user = User(organization_id=organization.organization_id, email=f"b1-{uuid4().hex}@example.invalid", password_hash="test-only-password", role=UserRole.ADMIN)
        device = Device(organization_id=organization.organization_id, display_name="B1 device")
        db.add_all([user, device])
        db.flush()
        snapshot = Snapshot(device_id=device.device_id, organization_id=organization.organization_id, status=SnapshotStatus.LOCKED, grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED, snapshot_hash="a" * 64, artifact_count=0, source=SnapshotSource.UPLOAD, created_by=user.user_id)
        db.add(snapshot)
        db.flush()
        packs = {row.pack_key: row for row in db.scalars(select(AssessmentPackVersion).where(AssessmentPackVersion.organization_id.is_(None)))}
        pack_a, pack_b = packs["synthetic_management_baseline_a"], packs["synthetic_management_baseline_b"]
        audit_a = Audit(organization_id=organization.organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id, revision_number=1, reevaluation_reason=AuditReevaluationReason.INITIAL, status=AuditStatus.PROCESSING, selected_frameworks=[], version_refs={"assessment_pack_version_id": str(pack_a.assessment_pack_version_id)}, profile_resolution={"resolution_status": "resolved", "profile_version_id": "cisco.ios_xe.17@1.0.0"}, verdict_counts={}, severity_counts={}, coverage={}, created_by=user.user_id)
        audit_b = Audit(organization_id=organization.organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id, revision_number=2, previous_audit_id=None, reevaluation_reason=AuditReevaluationReason.MANUAL_REEVALUATION, status=AuditStatus.PROCESSING, selected_frameworks=[], version_refs={"assessment_pack_version_id": str(pack_b.assessment_pack_version_id)}, profile_resolution={"resolution_status": "resolved", "profile_version_id": "cisco.ios_xe.17@1.0.0"}, verdict_counts={}, severity_counts={}, coverage={}, created_by=user.user_id)
        db.add_all([audit_a, audit_b])
        db.flush()
        state_a, state_b = _state(audit_a.audit_id, device.device_id), _state(audit_b.audit_id, device.device_id)
        finding_a, finding_b = _finding(audit_a.audit_id, device.device_id), _finding(audit_b.audit_id, device.device_id)
        db.add_all([state_a, state_b, finding_a, finding_b])
        db.flush()
        pin_assessment(db, audit_a, "cisco.ios_xe.17@1.0.0")
        pin_assessment(db, audit_b, "cisco.ios_xe.17@1.0.0")
        coverage_a = persist_assessment_results(db, audit_id=audit_a.audit_id, organization_id=organization.organization_id, profile_version_id="cisco.ios_xe.17@1.0.0", findings=[finding_a])
        coverage_b = persist_assessment_results(db, audit_id=audit_b.audit_id, organization_id=organization.organization_id, profile_version_id="cisco.ios_xe.17@1.0.0", findings=[finding_b])
        db.flush()
        assert coverage_a["automatic_verdicts"] == {"pass": 1, "fail": 0, "unknown": 0}
        assert coverage_b["automatic_verdicts"] == {"pass": 0, "fail": 1, "unknown": 0}
        assert coverage_a["manual"] == coverage_b["manual"] == 1
        assert db.get(Audit, audit_a.audit_id).version_refs["assessment_pack_version_id"] == str(pack_a.assessment_pack_version_id)
        assert db.get(Audit, audit_a.audit_id).coverage["assessment_pack"]["content_digest"] == "a" * 64
        assert db.get(Audit, audit_b.audit_id).coverage["assessment_pack"]["content_digest"] == "b" * 64
        assert compatible_packs(db, other.organization_id, "cisco.ios_xe.17@1.0.0")
        tenant_pack = AssessmentPackVersion(organization_id=organization.organization_id, pack_key="tenant-only", family="TEST/INFRASTRUCTURE", name="Tenant only", version=1, profile_version_ids=["cisco.ios_xe.17@1.0.0"], source_metadata={"notice": "TEST/INFRASTRUCTURE ONLY"}, source_version_label="tenant-only@1", content_digest="c" * 64, applicability={"profile_version_ids": ["cisco.ios_xe.17@1.0.0"]})
        db.add(tenant_pack)
        db.flush()
        with pytest.raises(AssessmentPackError, match="not available"):
            get_pack(db, other.organization_id, tenant_pack.assessment_pack_version_id)
