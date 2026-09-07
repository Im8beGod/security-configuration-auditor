from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from uuid import uuid4
from app.compliance.verdicts import FindingSeverity, FindingVerdict
from app.db.models import AuditStatus, DeviceClass
from app.dashboard.service import build_dashboard

NOW=datetime(2026,9,8,tzinfo=timezone.utc)
def device(name="device"):
    return SimpleNamespace(device_id=uuid4(),display_name=name,device_class=DeviceClass.ROUTER)
def audit(device_id,status,minutes,coverage=None):
    return SimpleNamespace(audit_id=uuid4(),device_id=device_id,status=status,created_at=NOW+timedelta(minutes=minutes),completed_at=NOW+timedelta(minutes=minutes) if status in {AuditStatus.COMPLETED,AuditStatus.COMPLETED_WITH_UNKNOWNS,AuditStatus.COMPLETED_WITH_ERRORS} else None,verdict_counts={},severity_counts={},coverage=coverage or {},version_refs={"device_profile_version_id":"cisco.ios_xe.17@1.0.0"},profile_resolution={"vendor":"Cisco"})
def finding(audit_id,device_id,verdict,severity=FindingSeverity.MEDIUM):
    return SimpleNamespace(audit_id=audit_id,device_id=device_id,verdict=verdict,severity=severity)

def test_empty_and_unaudited_fleet():
    assert build_dashboard([],[],[])["total_devices"]==0
    result=build_dashboard([device()],[],[])
    assert (result["audited_devices"],result["unaudited_devices"])==(0,1)
    assert result["coverage"]["decision_coverage"]["status"]=="not_assessed"

def test_latest_status_does_not_replace_completed_truth_and_risk_is_exclusive():
    critical,high,review=device("critical"),device("high"),device("review")
    old_critical=audit(critical.device_id,AuditStatus.COMPLETED,1)
    processing=audit(critical.device_id,AuditStatus.PROCESSING,2)
    old_high=audit(high.device_id,AuditStatus.COMPLETED_WITH_UNKNOWNS,1)
    failed=audit(high.device_id,AuditStatus.FAILED,2)
    old_review=audit(review.device_id,AuditStatus.COMPLETED_WITH_ERRORS,1)
    findings=[finding(old_critical.audit_id,critical.device_id,FindingVerdict.FAIL,FindingSeverity.CRITICAL),finding(old_critical.audit_id,critical.device_id,FindingVerdict.FAIL,FindingSeverity.HIGH),finding(old_high.audit_id,high.device_id,FindingVerdict.FAIL,FindingSeverity.HIGH),finding(old_review.audit_id,review.device_id,FindingVerdict.UNKNOWN),finding(old_review.audit_id,review.device_id,FindingVerdict.MANUAL_REVIEW),finding(old_review.audit_id,review.device_id,FindingVerdict.PROCESS_ERROR)]
    result=build_dashboard([critical,high,review],[old_critical,processing,old_high,failed,old_review],findings)
    assert result["critical_risk_devices"]==1 and result["high_risk_devices"]==1
    assert result["devices_needing_review"]==1
    rows={row["device_id"]:row for row in result["devices"]}
    assert rows[critical.device_id]["latest_audit_status"]=="processing"
    assert rows[critical.device_id]["latest_completed_audit_id"]==old_critical.audit_id
    assert rows[high.device_id]["latest_audit_status"]=="failed"
    assert result["verdict_distribution"]=={"fail":3,"unknown":1,"manual_review":1,"process_error":1}

def test_coverage_aggregates_counts_and_recent_audits_are_bounded_and_ordered():
    first,second=device("one"),device("two")
    a1=audit(first.device_id,AuditStatus.COMPLETED,1,{"implementation_coverage":{"numerator":1,"denominator":2},"decision_coverage":{"numerator":0,"denominator":0}})
    a2=audit(second.device_id,AuditStatus.COMPLETED,2,{"implementation":{"numerator":2,"denominator":3},"decision":{"numerator":1,"denominator":4},"conformance":{"numerator":3,"denominator":4}})
    result=build_dashboard([first,second],[a1,a2],[],recent_limit=1)
    assert result["coverage"]["implementation_coverage"]=={"numerator":3,"denominator":5,"percentage":60.0,"status":"assessed"}
    assert result["coverage"]["decision_coverage"]=={"numerator":1,"denominator":4,"percentage":25.0,"status":"assessed"}
    assert result["recent_audits"][0]["audit_id"]==a2.audit_id
