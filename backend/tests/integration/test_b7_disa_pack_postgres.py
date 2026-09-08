"""Opt-in PostgreSQL acceptance for the scoped B7 DISA NDM SRG pack."""
import os
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import DatabaseError

from app.assessment_packs.service import AssessmentPackError, compatible_packs, pin_assessment, persist_assessment_results
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import AssessmentPackVersion, AssessmentResult, Audit, AuditAssessment, AuditReevaluationReason, AuditStatus, Device, EffectiveState, Organization, Snapshot, SnapshotGroupingStatus, SnapshotSource, SnapshotStatus, User, UserRole
from app.db.session import create_session_factory
from app.effective_state.contracts import ResolutionStatus


pytestmark = pytest.mark.skipif(os.environ.get("SIH_B7_POSTGRES_TEST") != "1", reason="Set SIH_B7_POSTGRES_TEST=1 with PostgreSQL available")
PROFILES = ("cisco.ios_xe.17@1.0.0", "fortinet.fortios.7@1.0.0", "juniper.junos.18@1.0.0")


def _state(audit_id, device_id, field_id, value):
    return EffectiveState(effective_state_id=uuid4(), audit_id=audit_id, device_id=device_id, field_id=field_id, scope={"type": "device", "key": str(device_id)}, scope_key=f"device::{device_id}", effective_value=value, resolution_status=ResolutionStatus.RESOLVED, source_fact_ids=[], resolution_trace=[], referenced_objects=[], precedence_applied=[])


def test_b7_disa_pack_is_immutable_pinned_and_evaluates_shared_states_for_three_vendors():
    engine = create_database_engine(get_settings())
    factory = create_session_factory(engine)
    organization_id = None
    try:
        with factory() as db:
            disa = db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key == "disa_ndm_srg_v5r5_scoped_technical"))
            assert disa is not None
            with pytest.raises(DatabaseError, match="immutable"):
                db.execute(text("UPDATE assessment_pack_versions SET name = 'mutation' WHERE assessment_pack_version_id = :pack_id").bindparams(pack_id=disa.assessment_pack_version_id))
            db.rollback()
        with factory.begin() as db:
            assert db.scalar(text("SELECT version_num FROM alembic_version")) == "20260909_0015"
            disa = db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key == "disa_ndm_srg_v5r5_scoped_technical"))
            nist = db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key == "nist_sp80053_rev5_scoped_technical"))
            assert disa is not None and nist is not None and disa.assessment_pack_version_id != nist.assessment_pack_version_id
            assert disa.source_metadata["source_sha256"] == "d6f4415ed5cb4d4c5e589b3e8060203f43742b490aa30be479c774c6ef292a92"
            assert nist.source_metadata["source_sha256"] == "01f37cf90ea99d92242c936cbfbdebcc338eef1f71454e2acac36cc56e9bc062"
            organization = Organization(name="B7 DISA Organization", slug=f"b7-{uuid4().hex[:12]}")
            db.add(organization); db.flush(); organization_id = organization.organization_id
            user = User(organization_id=organization_id, email=f"b7-{uuid4().hex}@example.invalid", password_hash="test-only-password", role=UserRole.ADMIN)
            db.add(user); db.flush()
            for revision, profile in enumerate(PROFILES, 1):
                assert {item.pack_key for item in compatible_packs(db, organization_id, profile)} >= {"nist_sp80053_rev5_scoped_technical", "disa_ndm_srg_v5r5_scoped_technical"}
                device = Device(organization_id=organization_id, display_name=f"B7 {profile}")
                db.add(device); db.flush()
                snapshot = Snapshot(device_id=device.device_id, organization_id=organization_id, status=SnapshotStatus.LOCKED, grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED, snapshot_hash=uuid4().hex * 2, artifact_count=0, source=SnapshotSource.UPLOAD, created_by=user.user_id)
                db.add(snapshot); db.flush()
                audit = Audit(organization_id=organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id, revision_number=revision, reevaluation_reason=AuditReevaluationReason.INITIAL, status=AuditStatus.PROCESSING, selected_frameworks=[], version_refs={"assessment_pack_version_id": str(disa.assessment_pack_version_id)}, profile_resolution={"resolution_status": "resolved", "profile_version_id": profile}, verdict_counts={}, severity_counts={}, coverage={}, created_by=user.user_id)
                db.add(audit); db.flush()
                states = [
                    _state(audit.audit_id, device.device_id, "management.session.idle_timeout", {"type": "duration", "value": 300}),
                    _state(audit.audit_id, device.device_id, "logging.enabled", {"type": "boolean", "value": True}),
                    _state(audit.audit_id, device.device_id, "logging.remote.destination", {"type": "list", "value": [{"value": "logs.example.invalid"}]}),
                    _state(audit.audit_id, device.device_id, "time.ntp.configured", {"type": "boolean", "value": True}),
                    _state(audit.audit_id, device.device_id, "time.ntp.server", {"type": "list", "value": [{"value": "time.example.invalid"}]}),
                ]
                if profile == PROFILES[0]:
                    states.append(_state(audit.audit_id, device.device_id, "time.ntp.authentication.enabled", {"type": "boolean", "value": True}))
                db.add_all(states); db.flush()
                pinned = pin_assessment(db, audit, profile)
                if profile == PROFILES[0]:
                    audit.version_refs = {"assessment_pack_version_id": str(nist.assessment_pack_version_id)}
                    with pytest.raises(AssessmentPackError, match="cannot change"):
                        pin_assessment(db, audit, profile)
                    audit.version_refs = {"assessment_pack_version_id": str(disa.assessment_pack_version_id)}
                coverage = persist_assessment_results(db, audit_id=audit.audit_id, organization_id=organization_id, profile_version_id=profile, findings=[])
                assert pinned is not None and pinned.assessment_pack_version_id == disa.assessment_pack_version_id
                assert coverage["manual"] == 2
                assert coverage["automatic_verdicts"] == ({"pass": 6, "fail": 0, "unknown": 0} if profile == PROFILES[0] else {"pass": 5, "fail": 0, "unknown": 1})
                results = {item.result_identity.split(":", 1)[0]: item for item in db.scalars(select(AssessmentResult).where(AssessmentResult.audit_id == audit.audit_id))}
                assert results["v-213467.remote-log-destination"].verdict == "pass"
                assert results["v-264308.ntp-server"].verdict == "pass"
                assert results["v-202118.remote-session-crypto-review"].verdict is None
                if profile != PROFILES[0]:
                    assert results["v-202112.ntp-authentication"].verdict == "unknown"
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
