import os
import re
from base64 import a85decode
from uuid import uuid4
from zlib import decompress

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import sessionmaker

from app.assessment_packs.service import persist_assessment_results, pin_assessment
from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    AssessmentPackVersion, AssessmentResult, Audit, AuditReevaluationReason,
    AuditStatus, Device, EffectiveState, ReportStatus, Snapshot, SnapshotGroupingStatus,
    SnapshotSource, SnapshotStatus, User,
)
from app.effective_state.contracts import ResolutionStatus, UnresolvedReason
from app.reporting.service import create_report, generate_report, mark_generating
from app.reporting.storage import LocalFilesystemReportStorage


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_STAGE6_POSTGRES_TEST") != "1",
    reason="Set SIH_STAGE6_POSTGRES_TEST=1 with PostgreSQL available",
)


def _state(audit_id, device_id, field_id, value):
    return EffectiveState(
        effective_state_id=uuid4(), audit_id=audit_id, device_id=device_id,
        field_id=field_id, scope={"type": "device", "key": "device"},
        scope_key=f"device::{field_id}", effective_value=value,
        resolution_status=ResolutionStatus.RESOLVED, source_fact_ids=[],
        resolution_trace=[], referenced_objects=[], precedence_applied=[],
    )


def _results(db, audit_id):
    return {
        item.result_identity.split(":", 2)[-2]: item
        for item in db.scalars(select(AssessmentResult).where(AssessmentResult.audit_id == audit_id))
    }


def test_stage6_nist_and_iso_ac17_evidence_is_versioned_and_fail_closed(tmp_path):
    engine = create_database_engine(get_settings())
    connection = engine.connect()
    outer = connection.begin()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False)
    try:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260924_0027"
        suffix = uuid4().hex
        organization_id, user_id = bootstrap_admin(factory, "Stage 6", f"stage6-{suffix}", f"stage6-{suffix}@example.invalid", "test-only-password")
        with factory.begin() as db:
            user = db.get(User, user_id)
            nist = db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key == "nist_sp80053_rev5_scoped_technical", AssessmentPackVersion.version == 3))
            iso = db.scalar(select(AssessmentPackVersion).where(AssessmentPackVersion.pack_key == "iso27001_2022_nist_olir_technical_alignment", AssessmentPackVersion.version == 3))
            assert nist is not None and iso is not None
            device = Device(organization_id=organization_id, display_name="Stage 6 FortiOS")
            db.add(device); db.flush()
            snapshot = Snapshot(device_id=device.device_id, organization_id=organization_id, status=SnapshotStatus.LOCKED, grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED, snapshot_hash=uuid4().hex * 2, artifact_count=0, source=SnapshotSource.UPLOAD, created_by=user.user_id)
            db.add(snapshot); db.flush()
            audit = Audit(organization_id=organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id, revision_number=1, reevaluation_reason=AuditReevaluationReason.INITIAL, status=AuditStatus.PROCESSING, selected_frameworks=["nist", "iso"], version_refs={}, profile_resolution={"resolution_status": "resolved", "profile_version_id": "fortinet.fortios.7@1.0.0"}, verdict_counts={}, severity_counts={}, coverage={}, created_by=user.user_id)
            db.add(audit); db.flush()
            db.add_all([
                _state(audit.audit_id, device.device_id, "management.remote.source.restriction.configured", {"type": "boolean", "value": True}),
                _state(audit.audit_id, device.device_id, "management.remote.http.enabled", {"type": "boolean", "value": False}),
                _state(audit.audit_id, device.device_id, "management.remote.https.enabled", {"type": "boolean", "value": True}),
                _state(audit.audit_id, device.device_id, "management.remote.tls.minimum_version", {"type": "enum", "value": "tlsv1-2"}),
            ])
            db.flush()
            pin_assessment(db, audit, "fortinet.fortios.7@1.0.0")
            persist_assessment_results(db, audit_id=audit.audit_id, organization_id=organization_id, profile_version_id="fortinet.fortios.7@1.0.0", findings=[])
            results = _results(db, audit.audit_id)
            for key in ("ac-17.management-source-restriction", "ac-17.http-disabled", "ac-17.https-enabled", "ac-17.tls-minimum-1-2", "iso27001-a.5.14-management-source-restriction", "iso27001-a.5.14-http-disabled", "iso27001-a.5.14-https-enabled", "iso27001-a.5.14-tls-minimum-1-2"):
                assert results[key].verdict == "pass"
                assert results[key].result_details["effective_state"]["resolution_status"] == "resolved"
            tls = db.scalar(select(EffectiveState).where(EffectiveState.audit_id == audit.audit_id, EffectiveState.field_id == "management.remote.tls.minimum_version"))
            tls.effective_value = None; tls.resolution_status = ResolutionStatus.UNKNOWN; tls.unresolved_reason = UnresolvedReason.MISSING_EVIDENCE
            persist_assessment_results(db, audit_id=audit.audit_id, organization_id=organization_id, profile_version_id="fortinet.fortios.7@1.0.0", findings=[])
            results = _results(db, audit.audit_id)
            assert results["ac-17.tls-minimum-1-2"].verdict == "unknown"
            assert results["iso27001-a.5.14-tls-minimum-1-2"].verdict == "unknown"
            audit.status = AuditStatus.COMPLETED_WITH_UNKNOWNS
        with factory() as db:
            user = db.get(User, user_id)
            report, _ = create_report(db, user, audit.audit_id)
            report_id = report.report_id
        with factory.begin() as db:
            mark_generating(db, report_id)
            generated = generate_report(
                db, report_id, LocalFilesystemReportStorage(tmp_path / "reports"),
            )
            assert generated.status is ReportStatus.READY
            pdf = LocalFilesystemReportStorage(tmp_path / "reports").read(generated.storage_reference)
            streams = re.findall(rb"stream\r?\n(.*?)endstream", pdf, re.S)
            rendered = b"".join(decompress(a85decode(stream.strip(), adobe=True)) for stream in streams)
            assert b"AC-17" in rendered and b"A.5.14" in rendered
            assert b"ac-17.tls-minimum-1-2" in rendered
            assert b"not_assigned" in rendered and b"Evidence references" in rendered
    finally:
        outer.rollback(); connection.close(); engine.dispose()
