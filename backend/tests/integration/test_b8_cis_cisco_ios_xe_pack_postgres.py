"""Opt-in PostgreSQL acceptance for the scoped B8 CIS Cisco IOS XE pack."""
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import DatabaseError

from app.assessment_packs.service import AssessmentPackError, compatible_packs, pin_assessment, persist_assessment_results
from app.audit.pipeline import AuditPipelineCoordinator
from app.audit.schemas import AuditCreate
from app.audit.service import create_audit, start_audit
from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import Artifact, AssessmentPackVersion, AssessmentResult, Audit, AuditAssessment, Device, EffectiveState, Finding, Job, Organization, SecurityFact, Snapshot, UnresolvedBlock, User
from app.db.session import create_session_factory
from app.effective_state.contracts import ResolutionStatus
from app.ingestion.service import ingest_artifact
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.snapshots.schemas import SnapshotCreate
from app.snapshots.service import add_artifact, create_snapshot, finalize_snapshot


pytestmark = pytest.mark.skipif(os.environ.get("SIH_B8_POSTGRES_TEST") != "1", reason="Set SIH_B8_POSTGRES_TEST=1 with PostgreSQL available")
PROFILE = "cisco.ios_xe.17@1.0.0"
FIXTURE = (Path(__file__).parents[1] / "fixtures" / "cisco_ios_xe" / "semantic.cfg").read_bytes()


def _state(audit_id, device_id, field_id, value, *, scope_type="device", scope_key=None):
    key = scope_key or str(device_id)
    return EffectiveState(effective_state_id=uuid4(), audit_id=audit_id, device_id=device_id, field_id=field_id, scope={"type": scope_type, "key": key}, scope_key=f"{scope_type}::{key}", effective_value=value, resolution_status=ResolutionStatus.RESOLVED, source_fact_ids=[], resolution_trace=[], referenced_objects=[], precedence_applied=[])


def _results(db, audit_id):
    return {item.result_identity.split(":", 1)[0]: item for item in db.scalars(select(AssessmentResult).where(AssessmentResult.audit_id == audit_id))}


def test_b8_cis_pack_is_immutable_profile_constrained_and_persists_honest_verdicts(tmp_path):
    engine = create_database_engine(get_settings())
    factory = create_session_factory(engine)
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    organization_id = None
    cis_id = nist_id = None
    try:
        with factory() as db:
            cis = db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key == "cis_cisco_ios_xe_17_v2_2_1_scoped_technical"))
            assert cis is not None
            with pytest.raises(DatabaseError, match="immutable"):
                db.execute(text("UPDATE assessment_pack_versions SET name = 'mutation' WHERE assessment_pack_version_id = :pack_id").bindparams(pack_id=cis.assessment_pack_version_id))
            db.rollback()
        suffix = uuid4().hex
        organization_id, _ = bootstrap_admin(factory, "B8 CIS Organization", f"b8-{suffix}", f"b8-{suffix}@example.invalid", "test-only-password")
        with factory() as db:
            assert db.scalar(text("SELECT version_num FROM alembic_version")) == "20260909_0016"
            cis = db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key == "cis_cisco_ios_xe_17_v2_2_1_scoped_technical"))
            nist = db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key == "nist_sp80053_rev5_scoped_technical"))
            disa = db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key == "disa_ndm_srg_v5r5_scoped_technical"))
            assert cis is not None and nist is not None and disa is not None
            cis_id, nist_id = cis.assessment_pack_version_id, nist.assessment_pack_version_id
            assert cis.profile_version_ids == [PROFILE] and cis.source_metadata["source_sha256"] == "e5330afdf64cc7a44ba051733e7b3a5b835d7d341610dddb5d5292eabe126b25"
            assert {item.pack_key for item in compatible_packs(db, organization_id, PROFILE)} >= {"cis_cisco_ios_xe_17_v2_2_1_scoped_technical", "nist_sp80053_rev5_scoped_technical", "disa_ndm_srg_v5r5_scoped_technical"}
            assert "cis_cisco_ios_xe_17_v2_2_1_scoped_technical" not in {item.pack_key for item in compatible_packs(db, organization_id, "fortinet.fortios.7@1.0.0")}
            assert "cis_cisco_ios_xe_17_v2_2_1_scoped_technical" not in {item.pack_key for item in compatible_packs(db, organization_id, "juniper.junos.18@1.0.0")}

            user = db.scalar(select(User).where(User.organization_id == organization_id))
            device = Device(organization_id=organization_id, display_name="B8 Cisco state device"); db.add(device); db.flush()
            version = ingest_artifact(db, storage, user, b"Cisco IOS XE Software, Version 17.9.4a\n", "show-version.txt", "text/plain")
            config = ingest_artifact(db, storage, user, FIXTURE, "running.cfg", "text/plain")
            snapshot = create_snapshot(db, user, device.device_id, SnapshotCreate(label="B8 Cisco pipeline"))
            add_artifact(db, user, snapshot.snapshot_id, version.artifact_id); add_artifact(db, user, snapshot.snapshot_id, config.artifact_id); finalize_snapshot(db, user, snapshot.snapshot_id)
            audit = create_audit(db, user, AuditCreate(snapshot_id=snapshot.snapshot_id, assessment_pack_version_id=cis_id))
            audit, _ = start_audit(db, user, audit.audit_id)
            pipeline_audit_id = audit.audit_id

        pipeline = AuditPipelineCoordinator(factory, storage)
        outcome = pipeline.run(pipeline_audit_id, organization_id)
        assert outcome.profile_resolution.selected_profile_version_id == PROFILE
        with factory() as db:
            audit = db.get(Audit, pipeline_audit_id)
            pin = db.get(AuditAssessment, pipeline_audit_id)
            results = _results(db, pipeline_audit_id)
            assert audit is not None and pin is not None and pin.assessment_pack_version_id == cis_id
            assert audit.coverage["automatic_verdicts"] == {"pass": 5, "fail": 0, "unknown": 1} and audit.coverage["manual"] == 5
            assert results["cis-1.2.5.vty-source-restriction"].verdict == "pass"
            assert results["cis-1.2.8.vty-idle-timeout"].verdict == "unknown"
            assert results["cis-1.2.8.vty-idle-timeout"].result_details["unknown_reason"] == "ambiguous_scope"
            assert results["cis-2.1.1.2.ssh-version-review"].verdict is None
            source_state = db.scalar(select(EffectiveState).where(EffectiveState.audit_id == pipeline_audit_id, EffectiveState.field_id == "management.remote.source.restriction.configured"))
            assert source_state is not None and source_state.source_fact_ids
            source_state.effective_value = {"type": "boolean", "value": False}
            persist_assessment_results(db, audit_id=pipeline_audit_id, organization_id=organization_id, profile_version_id=PROFILE, findings=[])
            assert _results(db, pipeline_audit_id)["cis-1.2.5.vty-source-restriction"].verdict == "fail"

            audit.version_refs = {"assessment_pack_version_id": str(nist_id)}
            with pytest.raises(AssessmentPackError, match="cannot change"):
                pin_assessment(db, audit, PROFILE)
            audit.version_refs = {"assessment_pack_version_id": str(cis_id)}
            with pytest.raises(AssessmentPackError, match="incompatible"):
                pin_assessment(db, audit, "fortinet.fortios.7@1.0.0")
            with pytest.raises(AssessmentPackError, match="incompatible"):
                pin_assessment(db, audit, "juniper.junos.18@1.0.0")
    finally:
        if organization_id is not None:
            with factory.begin() as db:
                audit_ids = select(Audit.audit_id).where(Audit.organization_id == organization_id)
                db.execute(delete(AssessmentResult).where(AssessmentResult.audit_id.in_(audit_ids)))
                db.execute(delete(AuditAssessment).where(AuditAssessment.audit_id.in_(audit_ids)))
                db.execute(delete(Finding).where(Finding.audit_id.in_(audit_ids)))
                db.execute(delete(EffectiveState).where(EffectiveState.audit_id.in_(audit_ids)))
                db.execute(delete(UnresolvedBlock).where(UnresolvedBlock.audit_id.in_(audit_ids)))
                db.execute(delete(SecurityFact).where(SecurityFact.audit_id.in_(audit_ids)))
                db.execute(delete(Job).where(Job.audit_id.in_(audit_ids)))
                db.execute(delete(Audit).where(Audit.organization_id == organization_id))
                db.execute(delete(Artifact).where(Artifact.organization_id == organization_id))
                db.execute(delete(Snapshot).where(Snapshot.organization_id == organization_id))
                db.execute(delete(Device).where(Device.organization_id == organization_id))
                db.execute(delete(User).where(User.organization_id == organization_id))
                db.execute(delete(Organization).where(Organization.organization_id == organization_id))
        engine.dispose()
