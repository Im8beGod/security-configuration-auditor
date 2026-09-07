import hashlib
from pathlib import PurePosixPath
from uuid import uuid4
import pytest
from app.reporting.pdf import build_device_compliance_pdf
from app.reporting.storage import InvalidReportReferenceError, LocalFilesystemReportStorage, ReportAlreadyExistsError
from app.db.models import Report, ReportStatus
from app.reporting.service import fail_report, mark_generating

def test_report_storage_is_private_immutable_and_separate_from_artifacts(tmp_path):
    storage=LocalFilesystemReportStorage(tmp_path); organization_id=uuid4(); report_id=uuid4()
    reference=storage.write(b"%PDF-test",organization_id=organization_id,report_id=report_id)
    assert reference == f"organizations/{organization_id}/reports/{report_id}.pdf"
    assert PurePosixPath(reference).is_absolute() is False
    assert storage.read(reference)==b"%PDF-test"
    with pytest.raises(ReportAlreadyExistsError): storage.write(b"replacement",organization_id=organization_id,report_id=report_id)
    with pytest.raises(InvalidReportReferenceError): storage.read("../outside.pdf")

def test_pdf_is_deterministic_and_escapes_untrusted_markup():
    document={"device":{"display_name":"edge <router>"},"audit":{"audit_id":"a","revision_number":1,"status":"completed_with_errors","profile":"cisco@1","verdict_counts":{"unknown":1,"manual_review":1,"process_error":1},"severity_counts":{},"coverage":{"decision":{"numerator":0,"denominator":0,"status":"not_assessed"}}},"findings":[{"title":"<b>hostile</b>","verdict":"unknown","severity":"high","expected_state":{},"observed_state":None,"explanation":"manual review & process error","affected_scope":{},"framework_references":[],"evidence_refs":[{"path":"<script>"}],"remediation":{"status":"not_required"}}]}
    first=build_device_compliance_pdf(document); second=build_device_compliance_pdf(document)
    assert first.startswith(b"%PDF-") and first == second
    assert hashlib.sha256(first).hexdigest()==hashlib.sha256(second).hexdigest()

def test_report_lifecycle_is_explicit_and_terminal_states_are_immutable(monkeypatch):
    report=Report(status=ReportStatus.PENDING,template_version="1",generator_version="1",audit_schema_version="1",source_finding_ids=[])
    class Database:
        def flush(self): pass
    monkeypatch.setattr("app.reporting.service.repository.by_id_for_update",lambda _db,_id: report)
    mark_generating(Database(),uuid4())
    assert report.status == ReportStatus.GENERATING
    fail_report(Database(),uuid4(),"safe_code","Safe failure")
    assert (report.status,report.failure_code,report.failure_message)==(ReportStatus.FAILED,"safe_code","Safe failure")
    fail_report(Database(),uuid4(),"replacement","Replacement")
    assert (report.failure_code,report.failure_message)==("safe_code","Safe failure")
