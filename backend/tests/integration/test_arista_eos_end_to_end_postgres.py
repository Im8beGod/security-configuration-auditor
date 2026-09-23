"""Opt-in Arista EOS upload-to-PDF production-pipeline verification."""

import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text

from app.assessment_packs.service import compatible_packs
from app.audit.pipeline import AuditPipelineCoordinator
from app.audit.schemas import AuditCreate
from app.audit.service import create_audit, start_audit
from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Artifact, AssessmentResult, Audit, AuditAssessment, Device, EffectiveState,
    Finding, Job, Organization, Report, ReportStatus, SecurityFact, Snapshot,
    UnresolvedBlock, User,
)
from app.db.session import create_session_factory
from app.ingestion.service import ingest_artifact
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.remediation.service import preview_remediation
from app.reporting.service import create_report, generate_report, mark_generating
from app.reporting.storage import LocalFilesystemReportStorage
from app.snapshots.schemas import SnapshotCreate
from app.snapshots.service import add_artifact, create_snapshot, finalize_snapshot


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_ARISTA_POSTGRES_TEST") != "1",
    reason="Set SIH_ARISTA_POSTGRES_TEST=1 with PostgreSQL available",
)
PROFILE = "arista.eos.4@1.0.0"
FIXTURES = Path(__file__).parents[1] / "fixtures" / "arista_eos"


def test_arista_upload_audit_remediation_and_pdf(tmp_path):
    engine = create_database_engine(get_settings())
    factory = create_session_factory(engine)
    artifacts = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    reports = LocalFilesystemReportStorage(tmp_path / "reports")
    organization_id = None
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260922_0024"
        suffix = uuid4().hex
        organization_id, _ = bootstrap_admin(
            factory, "Arista E2E", f"arista-e2e-{suffix}",
            f"arista-e2e-{suffix}@example.invalid", "test-only-password",
        )
        with factory() as db:
            user = db.scalar(select(User).where(User.organization_id == organization_id))
            device = Device(organization_id=organization_id, display_name="Arista leaf")
            db.add(device); db.commit(); db.refresh(device)
            version = ingest_artifact(
                db, artifacts, user, (FIXTURES / "show-version.txt").read_bytes(),
                "show-version.txt", "text/plain",
            )
            config = ingest_artifact(
                db, artifacts, user, (FIXTURES / "representative.cfg").read_bytes(),
                "running.cfg", "text/plain",
            )
            snapshot = create_snapshot(db, user, device.device_id, SnapshotCreate(label="Arista EOS 4"))
            add_artifact(db, user, snapshot.snapshot_id, version.artifact_id)
            add_artifact(db, user, snapshot.snapshot_id, config.artifact_id)
            finalize_snapshot(db, user, snapshot.snapshot_id)
            pack = max(compatible_packs(db, organization_id, PROFILE), key=lambda item: item.version)
            audit = create_audit(db, user, AuditCreate(
                snapshot_id=snapshot.snapshot_id,
                assessment_pack_version_id=pack.assessment_pack_version_id,
            ))
            audit, _job = start_audit(db, user, audit.audit_id)
            audit_id = audit.audit_id

        outcome = AuditPipelineCoordinator(factory, artifacts).run(audit_id, organization_id)
        assert outcome.profile_resolution.selected_profile_version_id == PROFILE

        with factory() as db:
            user = db.scalar(select(User).where(User.organization_id == organization_id))
            findings = list(db.scalars(select(Finding).where(Finding.audit_id == audit_id)))
            telnet = next(item for item in findings if item.rule_id == "management.telnet.disabled")
            assert telnet.verdict.value == "fail"
            preview = preview_remediation(db, user, telnet.finding_id, {})
            assert preview["procedure_key"] == "arista.eos.4.disable-telnet"
            assert "shutdown" in preview["rendered_steps"]
            report, _job = create_report(db, user, audit_id)
            report_id = report.report_id

        with factory.begin() as db:
            mark_generating(db, report_id)
            generated = generate_report(db, report_id, reports)
            reference = generated.storage_reference
            assert generated.status == ReportStatus.READY
        assert reports.read(reference).startswith(b"%PDF")
    finally:
        if organization_id is not None:
            with factory.begin() as db:
                audit_ids = select(Audit.audit_id).where(Audit.organization_id == organization_id)
                db.execute(delete(Report).where(Report.organization_id == organization_id))
                db.execute(delete(AssessmentResult).where(AssessmentResult.audit_id.in_(audit_ids)))
                db.execute(delete(AuditAssessment).where(AuditAssessment.audit_id.in_(audit_ids)))
                db.execute(delete(UnresolvedBlock).where(UnresolvedBlock.audit_id.in_(audit_ids)))
                db.execute(delete(Finding).where(Finding.audit_id.in_(audit_ids)))
                db.execute(delete(EffectiveState).where(EffectiveState.audit_id.in_(audit_ids)))
                db.execute(delete(SecurityFact).where(SecurityFact.audit_id.in_(audit_ids)))
                db.execute(delete(Job).where(Job.audit_id.in_(audit_ids)))
                db.execute(delete(Audit).where(Audit.organization_id == organization_id))
                db.execute(delete(Artifact).where(Artifact.organization_id == organization_id))
                db.execute(delete(Snapshot).where(Snapshot.organization_id == organization_id))
                db.execute(delete(Device).where(Device.organization_id == organization_id))
                db.execute(delete(User).where(User.organization_id == organization_id))
                db.execute(delete(Organization).where(Organization.organization_id == organization_id))
        engine.dispose()
