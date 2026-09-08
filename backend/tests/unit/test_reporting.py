import hashlib
import re
from base64 import a85decode
from pathlib import PurePosixPath
from uuid import uuid4
from zlib import decompress
import pytest
from app.reporting.pdf import build_device_compliance_pdf, format_counts, format_framework_references, format_readable
from app.reporting.storage import InvalidReportReferenceError, LocalFilesystemReportStorage, ReportAlreadyExistsError
from app.db.models import Report, ReportStatus
from app.reporting.service import build_report_document, fail_report, mark_generating

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


def test_pdf_formatters_render_structured_values_as_human_readable_text():
    assert format_counts({"pass": 1}, verdict=True) == "PASS: 1"
    assert format_counts({"low": 1}) == "Low: 1"
    assert format_framework_references([{"control": "1.1", "framework": "CIS"}]) == "CIS - Control 1.1"
    assert format_readable({"value": True, "type": "boolean"}) == "Enabled / true"
    assert format_readable({"type": "device"}) == "Device"
    assert format_readable({"nested": {"value": True}, "items": ["one", "two"]}) == "Items: one<br/>two; Nested: Value: true"
    assert format_readable(None) == "Not provided"
    assert format_framework_references([]) == "Not provided"


@pytest.mark.parametrize(
    ("vendor", "profile", "expected"),
    [
        ("Cisco", {"vendor": "Cisco", "product_family": "IOS XE", "os": "IOS XE", "os_version": "17.9.4a", "model": "C9300-48P", "serial_number": "FDO00000001"}, "Cisco"),
        ("Fortinet", {"vendor": "Fortinet", "product_family": "FortiGate", "os": "FortiOS", "os_version": "7.4.3"}, "Fortinet"),
    ],
)
def test_report_document_surfaces_generic_multivendor_device_identity(vendor, profile, expected):
    from types import SimpleNamespace

    device = SimpleNamespace(
        display_name=f"{vendor} edge", latest_hostname="edge.example", stable_serial_number="INV-001",
        asset_tag="ASSET-001", device_class="firewall",
    )
    audit = SimpleNamespace(
        profile_resolution=profile, version_refs={"device_profile_version_id": f"{vendor.lower()}@1"},
        audit_id="audit-1", revision_number=1, status=SimpleNamespace(value="completed"),
        verdict_counts={"pass": 1}, severity_counts={"low": 1}, coverage={"decision": {"status": "complete"}},
    )
    document = build_report_document(device, audit, [{"title": "Finding", "verdict": "pass", "severity": "low", "framework_references": ["NIST AC-11"], "remediation": {"status": "unavailable"}}])
    identity = document["device_identification"]
    assert identity["vendor"] == expected
    assert identity["hostname"] == "edge.example"
    assert identity["os_version"] == profile.get("os_version")
    assert identity["serial_number"] == profile.get("serial_number") or identity["serial_number"] == "INV-001"
    assert identity["asset_tag"] == "ASSET-001"
    assert document["findings"][0]["verdict"] == "pass"
    assert document["findings"][0]["framework_references"] == ["NIST AC-11"]


def test_pdf_contains_device_identification_and_missing_optional_values_are_safe():
    from types import SimpleNamespace

    device = SimpleNamespace(display_name="FortiOS edge", latest_hostname="forti-edge", stable_serial_number=None, asset_tag=None, device_class="firewall")
    audit = SimpleNamespace(
        profile_resolution={"vendor": "Fortinet", "product_family": "FortiGate", "os": "FortiOS", "os_version": "7.4.3", "model": None, "serial_number": None},
        version_refs={"device_profile_version_id": "fortinet.fortios.7@1.0.0"}, audit_id="audit-2", revision_number=1,
        status=SimpleNamespace(value="completed"), verdict_counts={"unknown": 1}, severity_counts={"medium": 1}, coverage={},
    )
    document = build_report_document(device, audit, [{"title": "NTP", "verdict": "unknown", "severity": "medium", "expected_state": {}, "observed_state": {}, "explanation": "review", "affected_scope": {}, "framework_references": ["NIST AU-8"], "evidence_refs": [], "remediation": {"status": "unavailable"}}])
    pdf = build_device_compliance_pdf(document)
    assert b"%PDF-" in pdf
    streams = re.findall(rb"stream\r?\n(.*?)endstream", pdf, re.S)
    assert streams
    rendered = b"".join(decompress(a85decode(stream.strip(), adobe=True)) for stream in streams)
    assert len(rendered) > 1000
    assert pdf.count(b"/Type /Page") >= 1
    assert document["device_identification"]["model"] is None
    assert document["device_identification"]["serial_number"] is None
    assert document["findings"][0]["framework_references"] == ["NIST AU-8"]


def test_pdf_wraps_long_content_and_keeps_ordered_remediation_data():
    finding = {
        "title": "Long finding",
        "verdict": "fail",
        "severity": "high",
        "expected_state": {"type": "string", "value": "secure"},
        "observed_state": {"type": "string", "value": "insecure"},
        "explanation": "Long explanation " * 250,
        "affected_scope": {"type": "device", "key": "edge"},
        "framework_references": [{"framework": "CIS", "control": "1.1"}],
        "evidence_refs": [{"artifact_id": "artifact-1", "start_line": 10, "end_line": 14}],
        "remediation": {
            "status": "applicable",
            "title": "Reviewed procedure",
            "selection_source": "built_in_reviewed_catalog",
            "ordered_steps": [{"text": "First reviewed step"}, {"text": "Second reviewed step"}],
        },
    }
    document = {
        "device": {"display_name": "Cisco edge"},
        "device_identification": {"display_name": "Cisco edge", "vendor": "Cisco"},
        "audit": {"audit_id": "audit-long", "revision_number": 1, "profile": "cisco@1", "verdict_counts": {"fail": 1}, "severity_counts": {"high": 1}, "coverage": {}},
        "findings": [finding] * 12,
    }
    pdf = build_device_compliance_pdf(document)
    assert pdf.startswith(b"%PDF-")
    assert pdf.count(b"/Type /Page") > 1
    assert finding["remediation"]["ordered_steps"] == [{"text": "First reviewed step"}, {"text": "Second reviewed step"}]


def test_cisco_and_fortios_pdf_outputs_are_generated_for_visual_review(tmp_path):
    from types import SimpleNamespace

    cases = [
        ("cisco", "Cisco edge", {"vendor": "Cisco", "product_family": "IOS XE", "os": "IOS XE", "os_version": "17.9.4a", "model": "C9300-48P", "serial_number": "FDO00000001"}),
        ("fortios", "FortiOS edge", {"vendor": "Fortinet", "product_family": "FortiGate", "os": "FortiOS", "os_version": "7.4.3", "model": None, "serial_number": None}),
    ]
    for name, display_name, profile in cases:
        device = SimpleNamespace(display_name=display_name, latest_hostname=f"{name}.example", stable_serial_number=None, asset_tag=None, device_class="firewall")
        audit = SimpleNamespace(profile_resolution=profile, version_refs={"device_profile_version_id": f"{name}@1"}, audit_id=f"audit-{name}", revision_number=1, status=SimpleNamespace(value="completed"), verdict_counts={"pass": 1}, severity_counts={"low": 1}, coverage={})
        document = build_report_document(device, audit, [{"title": "Reviewed finding", "verdict": "pass", "severity": "low", "expected_state": {"value": True}, "observed_state": {"value": True}, "explanation": "Persisted result", "affected_scope": {"type": "device"}, "framework_references": [{"framework": "CIS", "control": "1.1"}], "evidence_refs": [{"artifact_id": f"{name}-artifact", "start_line": 2, "end_line": 3}], "remediation": {"status": "not_required"}}])
        output = tmp_path / f"{name}-device-compliance.pdf"
        output.write_bytes(build_device_compliance_pdf(document))
        assert output.read_bytes().startswith(b"%PDF-")
        print(output)

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
