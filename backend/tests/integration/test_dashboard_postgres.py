import os
from hashlib import sha256
from uuid import uuid4
import pytest
from sqlalchemy import delete
from app.cli.bootstrap_admin import bootstrap_admin
from app.compliance.verdicts import FindingSeverity, FindingVerdict
from app.core.config import get_settings
from app.dashboard.service import get_dashboard
from app.db.engine import create_database_engine
from app.db.models import Audit, AuditReevaluationReason, AuditStatus, Device, Finding, Organization, Snapshot, SnapshotGroupingStatus, SnapshotSource, SnapshotStatus, User
from app.db.session import create_session_factory

pytestmark=pytest.mark.skipif(os.environ.get("SIH_DASHBOARD_POSTGRES_TEST")!="1",reason="Set SIH_DASHBOARD_POSTGRES_TEST=1 with test PostgreSQL settings")

def test_dashboard_postgres_is_tenant_scoped_and_uses_latest_completed_truth():
    engine=create_database_engine(get_settings()); factory=create_session_factory(engine)
    slug=str(uuid4())[:8]
    first=bootstrap_admin(factory,"Dashboard A",f"dash-a-{slug}",f"a-{slug}@example.invalid","test-password")
    second=bootstrap_admin(factory,"Dashboard B",f"dash-b-{slug}",f"b-{slug}@example.invalid","test-password")
    try:
        with factory.begin() as db:
            organization_id,user_id=first; other_organization_id,other_user_id=second
            device=Device(organization_id=organization_id,display_name="Visible")
            foreign=Device(organization_id=other_organization_id,display_name="Foreign")
            db.add_all([device,foreign]); db.flush()
            snapshot=Snapshot(organization_id=organization_id,device_id=device.device_id,label="dashboard",grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,snapshot_hash=sha256(b"dashboard").hexdigest(),artifact_count=0,source=SnapshotSource.UPLOAD,status=SnapshotStatus.LOCKED,created_by=user_id)
            foreign_snapshot=Snapshot(organization_id=other_organization_id,device_id=foreign.device_id,label="foreign",grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,snapshot_hash=sha256(b"foreign").hexdigest(),artifact_count=0,source=SnapshotSource.UPLOAD,status=SnapshotStatus.LOCKED,created_by=other_user_id)
            db.add_all([snapshot,foreign_snapshot]); db.flush()
            completed=Audit(organization_id=organization_id,device_id=device.device_id,snapshot_id=snapshot.snapshot_id,revision_number=1,reevaluation_reason=AuditReevaluationReason.INITIAL,status=AuditStatus.COMPLETED_WITH_UNKNOWNS,selected_frameworks=[],version_refs={"device_profile_version_id":"cisco.ios_xe.17@1.0.0"},profile_resolution={"vendor":"Cisco"},verdict_counts={"fail":1,"unknown":1},severity_counts={"critical":1},coverage={"decision_coverage":{"numerator":1,"denominator":2}},created_by=user_id)
            processing=Audit(organization_id=organization_id,device_id=device.device_id,snapshot_id=snapshot.snapshot_id,revision_number=2,reevaluation_reason=AuditReevaluationReason.MANUAL_REEVALUATION,status=AuditStatus.PROCESSING,selected_frameworks=[],version_refs={},profile_resolution={},verdict_counts={},severity_counts={},coverage={},created_by=user_id)
            db.add_all([completed,processing]); db.flush()
            completed_id=completed.audit_id
            db.add(Finding(finding_id=uuid4(),audit_id=completed.audit_id,device_id=device.device_id,comparison_key="dashboard",rule_id="dashboard.rule",rule_pack_version_id=uuid4(),title="Critical",security_domain="management",verdict=FindingVerdict.FAIL,severity=FindingSeverity.CRITICAL,expected_state={},observed_state={},explanation="persisted",affected_scope=None,effective_state_refs=[],evidence_refs=[],unknown_reason=None,framework_references=[],remediation_procedure_id=None))
        with factory() as db:
            result=get_dashboard(db,db.get(User,user_id))
            assert result["total_devices"]==1 and result["critical_risk_devices"]==1
            assert result["devices"][0]["latest_audit_status"]=="processing"
            assert result["devices"][0]["latest_completed_audit_id"]==completed_id
            assert "Foreign" not in str(result)
    finally:
        with factory.begin() as db:
            for organization_id in (first[0],second[0]):
                audit_ids=[row.audit_id for row in db.query(Audit).filter(Audit.organization_id==organization_id)]
                if audit_ids: db.execute(delete(Finding).where(Finding.audit_id.in_(audit_ids)))
                db.execute(delete(Audit).where(Audit.organization_id==organization_id)); db.execute(delete(Snapshot).where(Snapshot.organization_id==organization_id)); db.execute(delete(Device).where(Device.organization_id==organization_id)); db.execute(delete(User).where(User.organization_id==organization_id)); db.execute(delete(Organization).where(Organization.organization_id==organization_id))
        engine.dispose()
