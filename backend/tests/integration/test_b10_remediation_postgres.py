import os
from uuid import uuid4
import pytest
from sqlalchemy import select,text
from sqlalchemy.exc import DatabaseError
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.session import create_session_factory
from app.db.models import *
from app.compliance.verdicts import FindingSeverity,FindingVerdict
from app.remediation.service import preview_remediation,RemediationError
pytestmark=pytest.mark.skipif(os.environ.get('SIH_B10_POSTGRES_TEST')!='1',reason='opt-in')
P=[('cisco.ios_xe.17@1.0.0','management.telnet.disabled','cisco.ssh-only-vty',{'vty_range':'0 4'}),('fortinet.fortios.7@1.0.0','management.remote.telnet.enabled','fortios.secure-interface-access',{'interface':'port1','protocols':'https ssh'}),('juniper.junos.18@1.0.0','management.remote.telnet.enabled','junos.ssh-only-service',{})]
def test_b10_persisted_previews():
 e=create_database_engine(get_settings());f=create_session_factory(e)
 with f.begin() as d:
  assert d.scalar(text('select version_num from alembic_version'))=='20260909_0019';assert d.scalar(text("select count(*) from remediation_procedures"))==9
  o=Organization(name='b10',slug='b10-'+uuid4().hex[:8]);d.add(o);d.flush();u=User(organization_id=o.organization_id,email=uuid4().hex+'@x.invalid',password_hash='x',role=UserRole.ADMIN);d.add(u);d.flush()
  for n,(profile,rule,key,params) in enumerate(P,1):
   q=d.scalar(select(RemediationProcedure).where(RemediationProcedure.procedure_key==key));dev=Device(organization_id=o.organization_id,display_name=key);d.add(dev);d.flush();s=Snapshot(device_id=dev.device_id,organization_id=o.organization_id,status=SnapshotStatus.LOCKED,grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,snapshot_hash=uuid4().hex*2,artifact_count=0,source=SnapshotSource.UPLOAD,created_by=u.user_id);d.add(s);d.flush();a=Audit(organization_id=o.organization_id,device_id=dev.device_id,snapshot_id=s.snapshot_id,revision_number=n,reevaluation_reason=AuditReevaluationReason.INITIAL,status=AuditStatus.COMPLETED,selected_frameworks=[],version_refs={'device_profile_version_id':profile},profile_resolution={'profile_version_id':profile,'resolution_status':'resolved'},verdict_counts={},severity_counts={},coverage={},created_by=u.user_id);d.add(a);d.flush();x=Finding(finding_id=uuid4(),audit_id=a.audit_id,device_id=dev.device_id,comparison_key=key,rule_id=rule,rule_pack_version_id=uuid4(),title=key,security_domain='management',verdict=FindingVerdict.FAIL,severity=FindingSeverity.MEDIUM,expected_state={},observed_state={},explanation='x',affected_scope=None,effective_state_refs=[],evidence_refs=[],unknown_reason=None,framework_references=[],remediation_procedure_id=q.procedure_id);d.add(x);d.flush();r=preview_remediation(d,u,x.finding_id,params);assert r['procedure_key']==key and r['rendered_steps'] and r['verification_steps'] and r['rollback_steps'] and r['source_references']
  with pytest.raises(RemediationError):preview_remediation(d,u,x.finding_id,{'bad':'x'})
  q=d.scalar(select(RemediationProcedure).where(RemediationProcedure.procedure_key=='cisco.ssh-only-vty'))
  with pytest.raises(DatabaseError,match='immutable'):d.execute(text("update remediation_procedures set title='x' where procedure_id=:i").bindparams(i=q.procedure_id))
 e.dispose()
