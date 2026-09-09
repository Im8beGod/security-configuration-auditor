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

pytestmark = pytest.mark.skipif(os.environ.get("SIH_B9_POSTGRES_TEST") != "1", reason="Set SIH_B9_POSTGRES_TEST=1 with PostgreSQL available")
PROFILES = ("cisco.ios_xe.17@1.0.0", "fortinet.fortios.7@1.0.0", "juniper.junos.18@1.0.0")
def _state(a,d,f,v): return EffectiveState(effective_state_id=uuid4(), audit_id=a, device_id=d, field_id=f, scope={"type":"device","key":str(d)}, scope_key=f"device::{d}", effective_value=v, resolution_status=ResolutionStatus.RESOLVED, source_fact_ids=[], resolution_trace=[], referenced_objects=[], precedence_applied=[])

def test_b9_alignment_is_immutable_pinned_and_multivendor():
    engine=create_database_engine(get_settings()); factory=create_session_factory(engine); oid=None
    try:
      with factory() as db:
        pack=db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key=="iso27001_2022_nist_olir_technical_alignment")); assert pack
        with pytest.raises(DatabaseError,match="immutable"): db.execute(text("UPDATE assessment_pack_versions SET name='x' WHERE assessment_pack_version_id=:id").bindparams(id=pack.assessment_pack_version_id))
        db.rollback()
      with factory.begin() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "20260909_0017"
        pack=db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key=="iso27001_2022_nist_olir_technical_alignment")); b6=db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key=="nist_sp80053_rev5_scoped_technical")); b7=db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key=="disa_ndm_srg_v5r5_scoped_technical")); b8=db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key=="cis_cisco_ios_xe_17_v2_2_1_scoped_technical")); assert pack and b6 and b7 and b8
        org=Organization(name="B9",slug=f"b9-{uuid4().hex[:12]}"); db.add(org); db.flush(); oid=org.organization_id
        user=User(organization_id=oid,email=f"b9-{uuid4().hex}@example.invalid",password_hash="test",role=UserRole.ADMIN); db.add(user); db.flush()
        for n,profile in enumerate(PROFILES,1):
          assert "iso27001_2022_nist_olir_technical_alignment" in {x.pack_key for x in compatible_packs(db,oid,profile)}
          device=Device(organization_id=oid,display_name=profile); db.add(device); db.flush(); snap=Snapshot(device_id=device.device_id,organization_id=oid,status=SnapshotStatus.LOCKED,grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,snapshot_hash=uuid4().hex*2,artifact_count=0,source=SnapshotSource.UPLOAD,created_by=user.user_id); db.add(snap); db.flush()
          audit=Audit(organization_id=oid,device_id=device.device_id,snapshot_id=snap.snapshot_id,revision_number=n,reevaluation_reason=AuditReevaluationReason.INITIAL,status=AuditStatus.PROCESSING,selected_frameworks=[],version_refs={"assessment_pack_version_id":str(pack.assessment_pack_version_id)},profile_resolution={"profile_version_id":profile},verdict_counts={},severity_counts={},coverage={},created_by=user.user_id); db.add(audit); db.flush()
          db.add_all([_state(audit.audit_id,device.device_id,"management.remote.ssh.enabled",{"type":"boolean","value":True}),_state(audit.audit_id,device.device_id,"management.remote.telnet.enabled",{"type":"boolean","value":False}),_state(audit.audit_id,device.device_id,"management.remote.ssh.version",{"type":"integer","value":2}),_state(audit.audit_id,device.device_id,"management.session.idle_timeout",{"type":"duration","value":900}),_state(audit.audit_id,device.device_id,"logging.enabled",{"type":"boolean","value":True}),_state(audit.audit_id,device.device_id,"logging.remote.destination",{"type":"list","value":[{"value":"logs.example.invalid"}]}),_state(audit.audit_id,device.device_id,"time.ntp.configured",{"type":"boolean","value":True}),_state(audit.audit_id,device.device_id,"time.ntp.server",{"type":"list","value":[{"value":"time.example.invalid"}]})]); db.flush()
          pin=pin_assessment(db,audit,profile); coverage=persist_assessment_results(db,audit_id=audit.audit_id,organization_id=oid,profile_version_id=profile,findings=[]); results={x.result_identity.split(":",1)[0]:x for x in db.scalars(select(AssessmentResult).where(AssessmentResult.audit_id==audit.audit_id))}
          assert pin.assessment_pack_version_id==pack.assessment_pack_version_id and coverage["automatic_verdicts"]=={"pass":8,"fail":0,"unknown":0} and coverage["manual"]==2 and results["iso27001-a.5.14-remote-ssh-enabled"].verdict=="pass"
          if n==1:
            audit.version_refs={"assessment_pack_version_id":str(b6.assessment_pack_version_id)}
            with pytest.raises(AssessmentPackError,match="cannot change"): pin_assessment(db,audit,profile)
            state=db.scalar(select(EffectiveState).where(EffectiveState.audit_id==audit.audit_id,EffectiveState.field_id=="management.remote.ssh.enabled")); state.effective_value={"type":"boolean","value":False}; persist_assessment_results(db,audit_id=audit.audit_id,organization_id=oid,profile_version_id=profile,findings=[]); assert {x.result_identity.split(":",1)[0]:x for x in db.scalars(select(AssessmentResult).where(AssessmentResult.audit_id==audit.audit_id))}["iso27001-a.5.14-remote-ssh-enabled"].verdict=="fail"
    finally:
      if oid:
       with factory.begin() as db:
        ids=select(Audit.audit_id).where(Audit.organization_id==oid); db.execute(delete(AssessmentResult).where(AssessmentResult.audit_id.in_(ids))); db.execute(delete(AuditAssessment).where(AuditAssessment.audit_id.in_(ids))); db.execute(delete(EffectiveState).where(EffectiveState.audit_id.in_(ids))); db.execute(delete(Audit).where(Audit.organization_id==oid)); db.execute(delete(Snapshot).where(Snapshot.organization_id==oid)); db.execute(delete(Device).where(Device.organization_id==oid)); db.execute(delete(User).where(User.organization_id==oid)); db.execute(delete(Organization).where(Organization.organization_id==oid))
      engine.dispose()
