"""Opt-in PostgreSQL acceptance for the seeded B6 NIST AssessmentPack."""
import os
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import DatabaseError

from app.assessment_packs.service import AssessmentPackError, pin_assessment, persist_assessment_results
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    AssessmentPackVersion, AssessmentResult, Audit, AuditAssessment, AuditReevaluationReason,
    AuditStatus, Device, EffectiveState, Organization, Snapshot, SnapshotGroupingStatus,
    SnapshotSource, SnapshotStatus, User, UserRole,
)
from app.db.session import create_session_factory
from app.effective_state.contracts import ResolutionStatus


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_B6_POSTGRES_TEST") != "1",
    reason="Set SIH_B6_POSTGRES_TEST=1 with PostgreSQL available",
)

PROFILES = ("cisco.ios_xe.17@1.0.0", "fortinet.fortios.7@1.0.0", "juniper.junos.18@1.0.0")


def _state(audit_id, device_id, field_id, value):
    return EffectiveState(
        effective_state_id=uuid4(), audit_id=audit_id, device_id=device_id, field_id=field_id,
        scope={"type": "device", "key": str(device_id)}, scope_key=f"device::{device_id}",
        effective_value=value, resolution_status=ResolutionStatus.RESOLVED,
        source_fact_ids=[], resolution_trace=[], referenced_objects=[], precedence_applied=[],
    )


def test_b6_nist_pack_is_pinned_and_evaluates_shared_canonical_states_for_three_vendors():
    engine = create_database_engine(get_settings())
    factory = create_session_factory(engine)
    organization_id = None
    try:
        with factory() as db:
            pack = db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key == "nist_sp80053_rev5_scoped_technical"))
            assert pack is not None
            with pytest.raises(DatabaseError, match="immutable"):
                db.execute(text("UPDATE assessment_pack_versions SET name = 'mutation' WHERE assessment_pack_version_id = :pack_id").bindparams(pack_id=pack.assessment_pack_version_id))
            db.rollback()
        with factory.begin() as db:
            assert db.scalar(text("SELECT version_num FROM alembic_version")) == "20260909_0016"
            pack = db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key == "nist_sp80053_rev5_scoped_technical"))
            assert pack is not None and pack.version == 1 and pack.status == "published"
            assert pack.profile_version_ids == list(PROFILES)
            assert pack.source_metadata["source_sha256"] == "01f37cf90ea99d92242c936cbfbdebcc338eef1f71454e2acac36cc56e9bc062"
            organization = Organization(name="B6 NIST Organization", slug=f"b6-{uuid4().hex[:12]}")
            db.add(organization)
            db.flush()
            organization_id = organization.organization_id
            user = User(organization_id=organization_id, email=f"b6-{uuid4().hex}@example.invalid", password_hash="test-only-password", role=UserRole.ADMIN)
            db.add(user)
            db.flush()
            for revision, profile in enumerate(PROFILES, 1):
                device = Device(organization_id=organization_id, display_name=f"B6 {profile}")
                db.add(device)
                db.flush()
                snapshot = Snapshot(device_id=device.device_id, organization_id=organization_id, status=SnapshotStatus.LOCKED, grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED, snapshot_hash=uuid4().hex * 2, artifact_count=0, source=SnapshotSource.UPLOAD, created_by=user.user_id)
                db.add(snapshot)
                db.flush()
                audit = Audit(organization_id=organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id, revision_number=revision, reevaluation_reason=AuditReevaluationReason.INITIAL, status=AuditStatus.PROCESSING, selected_frameworks=[], version_refs={"assessment_pack_version_id": str(pack.assessment_pack_version_id)}, profile_resolution={"resolution_status": "resolved", "profile_version_id": profile}, verdict_counts={}, severity_counts={}, coverage={}, created_by=user.user_id)
                db.add(audit)
                db.flush()
                db.add_all([
                    _state(audit.audit_id, device.device_id, "management.remote.ssh.enabled", {"type": "boolean", "value": True}),
                    _state(audit.audit_id, device.device_id, "logging.remote.destination", {"type": "list", "value": [{"value": "logs.example.invalid"}]}),
                    _state(audit.audit_id, device.device_id, "time.ntp.configured", {"type": "boolean", "value": True}),
                    _state(audit.audit_id, device.device_id, "time.ntp.server", {"type": "list", "value": [{"value": "time.example.invalid"}]}),
                ])
                db.flush()
                pinned = pin_assessment(db, audit, profile)
                if profile == PROFILES[0]:
                    other_pack = db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key == "synthetic_management_baseline_a"))
                    assert other_pack is not None
                    audit.version_refs = {"assessment_pack_version_id": str(other_pack.assessment_pack_version_id)}
                    with pytest.raises(AssessmentPackError, match="cannot change"):
                        pin_assessment(db, audit, profile)
                    audit.version_refs = {"assessment_pack_version_id": str(pack.assessment_pack_version_id)}
                coverage = persist_assessment_results(db, audit_id=audit.audit_id, organization_id=organization_id, profile_version_id=profile, findings=[])
                assert pinned is not None and pinned.assessment_pack_version_id == pack.assessment_pack_version_id
                assert coverage["selected_obligation_count"] == 10
                assert coverage["automatic_verdicts"] == {"pass": 4, "fail": 0, "unknown": 4}
                assert coverage["manual"] == 2
                results = {item.result_identity.split(":", 1)[0]: item for item in db.scalars(select(AssessmentResult).where(AssessmentResult.audit_id == audit.audit_id))}
                assert results["ac-17.remote-ssh-enabled"].verdict == "pass"
                assert results["au-12.remote-logging"].verdict == "pass"
                assert results["au-8.ntp-server"].verdict == "pass"
                assert results["au-8.ntp-server"].result_details["effective_state"]["field_id"] == "time.ntp.server"
                assert results["ac-17.telnet-disabled"].verdict == "unknown"
                assert results["ac-17.authorization-review"].verdict is None
                if profile == PROFILES[0]:
                    extra_scope = _state(audit.audit_id, device.device_id, "management.remote.ssh.enabled", {"type": "boolean", "value": True})
                    extra_scope.scope = {"type": "vty_range", "key": "vty:5-15"}
                    extra_scope.scope_key = "vty_range::vty:5-15"
                    db.add(extra_scope)
                    db.flush()
                    persist_assessment_results(db, audit_id=audit.audit_id, organization_id=organization_id, profile_version_id=profile, findings=[])
                    scoped = {item.result_identity.split(":", 1)[0]: item for item in db.scalars(select(AssessmentResult).where(AssessmentResult.audit_id == audit.audit_id))}
                    assert scoped["ac-17.remote-ssh-enabled"].verdict == "unknown"
                    assert scoped["ac-17.remote-ssh-enabled"].result_details["unknown_reason"] == "ambiguous_scope"
                    db.delete(extra_scope)
                    ntp_state = db.scalar(select(EffectiveState).where(EffectiveState.audit_id == audit.audit_id, EffectiveState.field_id == "time.ntp.configured"))
                    ntp_state.effective_value = None
                    ntp_state.resolution_status = ResolutionStatus.CONFLICTING
                    ntp_state.unresolved_reason = "conflicting_evidence"
                    persist_assessment_results(db, audit_id=audit.audit_id, organization_id=organization_id, profile_version_id=profile, findings=[])
                    conflicted = {item.result_identity.split(":", 1)[0]: item for item in db.scalars(select(AssessmentResult).where(AssessmentResult.audit_id == audit.audit_id))}
                    assert conflicted["au-8.ntp-configured"].verdict == "unknown"
    finally:
        if organization_id is not None:
            with factory.begin() as db:
                audit_ids = select(Audit.audit_id).where(Audit.organization_id == organization_id)
                db.execute(delete(AssessmentResult).where(AssessmentResult.audit_id.in_(audit_ids)))
                db.execute(delete(AuditAssessment).where(AuditAssessment.audit_id.in_(audit_ids)))
                db.execute(delete(EffectiveState).where(EffectiveState.audit_id.in_(audit_ids)))
                db.execute(delete(Audit).where(Audit.organization_id == organization_id))
                db.execute(delete(Snapshot).where(Snapshot.organization_id == organization_id))
                db.execute(delete(Device).where(Device.organization_id == organization_id))
                db.execute(delete(User).where(User.organization_id == organization_id))
                db.execute(delete(Organization).where(Organization.organization_id == organization_id))
        engine.dispose()
