import hashlib
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.db.models import AssessmentObligation, AssessmentResult, Audit, AuditAssessment, AssessmentPackVersion, AuditStatus, Device, Finding, Report, ReportStatus, User
from app.db.models.common import utc_now
from app.jobs.enums import JobType
from app.jobs.service import enqueue_job
from app.remediation.service import get_remediation
from app.reporting import repository
from app.reporting.pdf import build_device_compliance_pdf
from app.reporting.storage import ReportStorage

class ReportingError(ValueError): pass
class ReportNotFound(ReportingError): pass


def _enum_value(value):
    return value.value if hasattr(value, "value") else value


def build_report_document(device: Device, audit: Audit, findings: list[dict], assessment: dict | None = None, assessment_results: list[dict] | None = None) -> dict:
    """Build report data from persisted inventory and the immutable audit profile."""
    profile = audit.profile_resolution or {}
    device_class = profile.get("device_class") or _enum_value(device.device_class)
    return {
        "device": {"display_name": device.display_name},
        "device_identification": {
            "display_name": device.display_name,
            "hostname": device.latest_hostname,
            "vendor": profile.get("vendor"),
            "product_family": profile.get("product_family"),
            "os": profile.get("os"),
            "os_version": profile.get("os_version"),
            "device_class": device_class,
            "model": profile.get("model"),
            "serial_number": profile.get("serial_number") or device.stable_serial_number,
            "asset_tag": device.asset_tag,
        },
        "audit": {
            "audit_id": audit.audit_id,
            "revision_number": audit.revision_number,
            "status": audit.status.value,
            "profile": audit.version_refs.get("device_profile_version_id")
            or profile.get("profile_version_id"),
            "verdict_counts": audit.verdict_counts,
            "severity_counts": audit.severity_counts,
            "coverage": audit.coverage,
            "assessment": assessment or {},
        },
        "findings": findings,
        "assessment_results": assessment_results or [],
    }

def create_report(db: Session, user: User, audit_id: UUID):
    audit = db.scalar(select(Audit).where(Audit.audit_id == audit_id, Audit.organization_id == user.organization_id))
    if not audit: raise ReportNotFound("Audit not found")
    if audit.status not in {AuditStatus.COMPLETED, AuditStatus.COMPLETED_WITH_UNKNOWNS, AuditStatus.COMPLETED_WITH_ERRORS}: raise ReportingError("Audit is not complete")
    findings = list(db.scalars(select(Finding).where(Finding.audit_id == audit_id).order_by(Finding.finding_id)))
    report = Report(organization_id=user.organization_id, device_id=audit.device_id, audit_id=audit.audit_id, template_version="1.0.0", generator_version="1.0.0", audit_schema_version=audit.schema_version, source_finding_ids=[str(item.finding_id) for item in findings], generated_by=user.user_id)
    repository.add(db, report); db.flush()
    job = enqueue_job(db, JobType.PDF_GENERATION, payload={"report_id": str(report.report_id)}, audit_id=audit.audit_id, device_id=audit.device_id, stage="report_generation")
    db.commit(); db.refresh(report)
    return report, job

def get_report(db: Session, user: User, report_id: UUID):
    report = repository.by_id(db, report_id, user.organization_id)
    if not report: raise ReportNotFound("Report not found")
    return report

def mark_generating(db: Session, report_id: UUID):
    report = repository.by_id_for_update(db, report_id)
    if not report or report.status != ReportStatus.PENDING: raise ReportingError("Report cannot be generated")
    report.status = ReportStatus.GENERATING; db.flush()
    return report

def generate_report(db: Session, report_id: UUID, storage: ReportStorage):
    report = repository.by_id_for_update(db, report_id)
    if not report or report.status != ReportStatus.GENERATING: raise ReportingError("Report cannot be generated")
    audit = db.get(Audit, report.audit_id); device = db.get(Device, report.device_id); user = db.get(User, report.generated_by)
    findings = list(db.scalars(select(Finding).where(Finding.audit_id == report.audit_id).order_by(Finding.finding_id)))
    if [str(item.finding_id) for item in findings] != report.source_finding_ids: raise ReportingError("Report source findings changed")
    records=[]
    for item in findings:
        remediation = get_remediation(db, user, item.finding_id) if user else {"status":"unavailable","reason":"generator_identity_unavailable"}
        records.append({key: getattr(item,key).value if hasattr(getattr(item,key),"value") else getattr(item,key) for key in ("title","verdict","severity","expected_state","observed_state","explanation","affected_scope","framework_references","evidence_refs")} | {"remediation": remediation})
    assessment = {}
    assessment_results = []
    pinned = db.get(AuditAssessment, audit.audit_id)
    if pinned is not None:
        pack = db.get(AssessmentPackVersion, pinned.assessment_pack_version_id)
        if pack is not None:
            assessment = {
                "assessment_pack_version_id": str(pack.assessment_pack_version_id),
                "family": pack.family, "name": pack.name, "version": pack.version,
                "source_version_label": pack.source_version_label,
                "content_digest": pack.content_digest,
            }
            rows = db.execute(select(AssessmentResult, AssessmentObligation).join(
                AssessmentObligation,
                AssessmentResult.assessment_obligation_id == AssessmentObligation.assessment_obligation_id,
            ).where(AssessmentResult.audit_id == audit.audit_id).order_by(AssessmentObligation.obligation_key)).all()
            assessment_results = [{
                "obligation_key": obligation.obligation_key,
                "title": obligation.title,
                "control_id": (obligation.source_reference or {}).get("control_id"),
                "control_title": (obligation.source_reference or {}).get("control_title"),
                "assessment_method": result.assessment_method,
                "implementation_status": result.implementation_status,
                "verdict": result.verdict,
                "details": result.result_details,
            } for result, obligation in rows]
    pdf = build_device_compliance_pdf(build_report_document(device, audit, records, assessment, assessment_results))
    reference = storage.write(pdf, organization_id=report.organization_id, report_id=report.report_id)
    report.storage_reference=reference; report.sha256=hashlib.sha256(pdf).hexdigest(); report.byte_size=len(pdf); report.generated_at=utc_now(); report.status=ReportStatus.READY; db.flush()
    return report

def fail_report(db: Session, report_id: UUID, code="generation_failed", message="Report generation failed"):
    report=repository.by_id_for_update(db,report_id)
    if report and report.status in {ReportStatus.PENDING,ReportStatus.GENERATING}:
        report.status=ReportStatus.FAILED; report.failure_code=code; report.failure_message=message; db.flush()
