from collections import Counter, defaultdict
from typing import Iterable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.compliance.verdicts import FindingSeverity, FindingVerdict
from app.db.models import Audit, AuditStatus, Device, Finding, User


COMPLETED = {AuditStatus.COMPLETED, AuditStatus.COMPLETED_WITH_UNKNOWNS, AuditStatus.COMPLETED_WITH_ERRORS}
REVIEW = {FindingVerdict.UNKNOWN, FindingVerdict.MANUAL_REVIEW, FindingVerdict.PROCESS_ERROR}
METRICS = {
    "implementation_coverage": ("implementation_coverage", "implementation"),
    "decision_coverage": ("decision_coverage", "decision"),
    "conformance_among_decisive_checks": ("conformance_among_decisive_checks", "conformance"),
}


def _value(item): return item.value if hasattr(item, "value") else str(item)
def _audit_order(audit): return (audit.created_at, str(audit.audit_id))
def _count(mapping, key):
    value = (mapping or {}).get(key, 0)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _coverage(audits):
    result = {}
    for canonical, aliases in METRICS.items():
        numerator = denominator = 0
        for audit in audits:
            metric = next(((audit.coverage or {}).get(key) for key in aliases if key in (audit.coverage or {})), None)
            if isinstance(metric, dict):
                n, d = metric.get("numerator"), metric.get("denominator")
                if isinstance(n, int) and isinstance(d, int) and not isinstance(n, bool) and not isinstance(d, bool) and n >= 0 and d >= 0:
                    numerator += n; denominator += d
        result[canonical] = {"numerator": numerator, "denominator": denominator, "percentage": round(numerator * 100 / denominator, 2) if denominator else None, "status": "assessed" if denominator else "not_assessed"}
    return result


def build_dashboard(devices: Iterable[Device], audits: Iterable[Audit], findings: Iterable[Finding], *, recent_limit: int = 20):
    devices = list(devices); audits = sorted(audits, key=_audit_order, reverse=True); findings = list(findings)
    audits_by_device = defaultdict(list)
    for audit in audits: audits_by_device[audit.device_id].append(audit)
    findings_by_audit = defaultdict(list)
    for finding in findings: findings_by_audit[finding.audit_id].append(finding)
    latest, completed, rows = {}, {}, []
    for device in devices:
        history = audits_by_device[device.device_id]
        latest[device.device_id] = history[0] if history else None
        completed[device.device_id] = next((audit for audit in history if audit.status in COMPLETED), None)
        rows.append({"device_id":device.device_id,"display_name":device.display_name,"latest_audit_id":latest[device.device_id].audit_id if latest[device.device_id] else None,"latest_audit_status":_value(latest[device.device_id].status) if latest[device.device_id] else None,"latest_completed_audit_id":completed[device.device_id].audit_id if completed[device.device_id] else None})
    selected = [audit for audit in completed.values() if audit]
    selected_findings = [finding for audit in selected for finding in findings_by_audit[audit.audit_id]]
    critical = {f.device_id for f in selected_findings if f.verdict == FindingVerdict.FAIL and f.severity == FindingSeverity.CRITICAL}
    high_candidates = {f.device_id for f in selected_findings if f.verdict == FindingVerdict.FAIL and f.severity == FindingSeverity.HIGH}
    review = {f.device_id for f in selected_findings if f.verdict in REVIEW}
    verdicts = Counter(_value(f.verdict) for f in selected_findings); severities = Counter(_value(f.severity) for f in selected_findings)
    statuses = Counter(_value(a.status) for a in latest.values() if a)
    families = Counter(_value(device.device_class) for device in devices)
    profiles = Counter((a.version_refs or {}).get("device_profile_version_id") or (a.profile_resolution or {}).get("profile_version_id") or "unresolved" for a in selected)
    vendors = Counter((a.profile_resolution or {}).get("vendor") or ((a.version_refs or {}).get("device_profile_version_id") or "unresolved").split(".",1)[0] for a in selected)
    names = {d.device_id:d.display_name for d in devices}
    recent=[]
    for audit in audits[:recent_limit]:
        recent.append({"audit_id":audit.audit_id,"device_id":audit.device_id,"device_name":names.get(audit.device_id,"Unknown device"),"status":_value(audit.status),"created_at":audit.created_at,"completed_at":audit.completed_at,"fail_count":_count(audit.verdict_counts,"fail"),"unknown_count":_count(audit.verdict_counts,"unknown"),"critical_count":_count(audit.severity_counts,"critical"),"high_count":_count(audit.severity_counts,"high")})
    return {"total_devices":len(devices),"audited_devices":len(selected),"unaudited_devices":len(devices)-len(selected),"critical_risk_devices":len(critical),"high_risk_devices":len(high_candidates-critical),"devices_needing_review":len(review),"verdict_distribution":dict(verdicts),"severity_distribution":dict(severities),"audit_status_distribution":dict(statuses),"vendor_distribution":dict(vendors),"profile_distribution":dict(profiles),"device_family_distribution":dict(families),"coverage":_coverage(selected),"devices":rows,"recent_audits":recent}


def get_dashboard(db: Session, user: User):
    devices=list(db.scalars(select(Device).where(Device.organization_id==user.organization_id)))
    audits=list(db.scalars(select(Audit).where(Audit.organization_id==user.organization_id)))
    audit_ids=[audit.audit_id for audit in audits]
    findings=list(db.scalars(select(Finding).where(Finding.audit_id.in_(audit_ids)))) if audit_ids else []
    return build_dashboard(devices,audits,findings)
