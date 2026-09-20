import os
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import sessionmaker

from app.audit.pipeline import AuditPipelineCoordinator
from app.audit.schemas import AuditCreate
from app.audit.service import create_audit, start_audit
from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import Device, Finding, ReportStatus, User
from app.ingestion.service import ingest_artifact
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.remediation.service import preview_remediation
from app.reporting.service import create_report, generate_report, mark_generating
from app.reporting.storage import LocalFilesystemReportStorage
from app.snapshots.schemas import SnapshotCreate
from app.snapshots.service import add_artifact, create_snapshot, finalize_snapshot


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_PHASE5_POSTGRES_TEST") != "1",
    reason="Set SIH_PHASE5_POSTGRES_TEST=1 with PostgreSQL available",
)

CASES = (
    (
        "cisco.ios_xe.17@1.0.0",
        b"Cisco IOS XE Software, Version 17.9.4a\n",
        b"hostname demo-cisco\nline vty 0 4\n exec-timeout 10 0\n transport input telnet ssh\nip ssh version 2\nlogging host 192.0.2.10\nntp server 192.0.2.20\n",
        "running.cfg", "text/plain", "management.telnet.disabled",
        {"vty_range": "0 4"}, "transport input ssh",
    ),
    (
        "fortinet.fortios.7@1.0.0",
        b"FortiOS v7.4.3,build2573\n",
        b"#config-version=FGT v7.4.3\nconfig system interface\n edit \"port1\"\n  set allowaccess telnet https ssh\n next\nend\nconfig system global\n set admintimeout 10\nend\n",
        "fortios.conf", "text/plain", "management.telnet.disabled",
        {"interface": "port1", "protocols": "https ssh"}, "set allowaccess https ssh",
    ),
    (
        "juniper.junos.18@1.0.0",
        b"JUNOS Software Release [18.4R1-S2.4]\n",
        b"<configuration><version>18.4R1-S2.4</version><system><services><ssh/><telnet/></services><login><idle-timeout>15</idle-timeout></login></system></configuration>",
        "junos.xml", "application/xml", "management.idle_timeout.maximum",
        {"minutes": "10"}, "set system login idle-timeout 10",
    ),
)


@pytest.mark.parametrize("profile,version_data,config_data,filename,media_type,rule_id,parameters,expected_command", CASES)
def test_vendor_upload_audit_remediation_and_pdf(
    tmp_path, profile, version_data, config_data, filename, media_type,
    rule_id, parameters, expected_command,
):
    engine = create_database_engine(get_settings())
    connection = engine.connect()
    outer = connection.begin()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False)
    artifacts = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    reports = LocalFilesystemReportStorage(tmp_path / "reports")
    try:
        assert connection.scalar(text("select version_num from alembic_version")) == "20260920_0023"
        suffix = uuid4().hex
        organization_id, _ = bootstrap_admin(
            factory, "P5 Vendor", f"p5-vendor-{suffix}",
            f"p5-vendor-{suffix}@example.invalid", "test-only-password",
        )
        with factory() as db:
            user = db.scalar(select(User).where(User.organization_id == organization_id))
            device = Device(organization_id=organization_id, display_name=profile)
            db.add(device); db.commit(); db.refresh(device)
            version = ingest_artifact(db, artifacts, user, version_data, "show-version.txt", "text/plain")
            config = ingest_artifact(db, artifacts, user, config_data, filename, media_type)
            snapshot = create_snapshot(db, user, device.device_id, SnapshotCreate(label=profile))
            add_artifact(db, user, snapshot.snapshot_id, version.artifact_id)
            add_artifact(db, user, snapshot.snapshot_id, config.artifact_id)
            finalize_snapshot(db, user, snapshot.snapshot_id)
            audit = create_audit(db, user, AuditCreate(snapshot_id=snapshot.snapshot_id))
            audit, _ = start_audit(db, user, audit.audit_id)
            audit_id = audit.audit_id

        outcome = AuditPipelineCoordinator(factory, artifacts).run(audit_id, organization_id)
        assert outcome.profile_resolution.selected_profile_version_id == profile
        with factory() as db:
            user = db.scalar(select(User).where(User.organization_id == organization_id))
            finding = db.scalar(select(Finding).where(
                Finding.audit_id == audit_id,
                Finding.rule_id == rule_id,
                Finding.verdict == "fail",
            ))
            assert finding is not None and finding.evidence_refs
            preview = preview_remediation(db, user, finding.finding_id, parameters)
            assert expected_command in preview["rendered_steps"]
            assert preview["rendered_verification_steps"] and preview["rendered_rollback_steps"]
            report, _ = create_report(db, user, audit_id)
            report_id = report.report_id
        with factory.begin() as db:
            mark_generating(db, report_id)
            generated = generate_report(db, report_id, reports)
            assert generated.status is ReportStatus.READY
            assert reports.read(generated.storage_reference).startswith(b"%PDF")
    finally:
        outer.rollback()
        connection.close()
        engine.dispose()
