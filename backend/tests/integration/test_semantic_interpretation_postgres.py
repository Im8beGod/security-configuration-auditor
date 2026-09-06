"""Opt-in PostgreSQL verification for canonical SecurityFact persistence."""

import os
from hashlib import sha256
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import SQLAlchemyError

from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Artifact,
    ArtifactContentFamily,
    ArtifactEvidenceType,
    ArtifactStatus,
    Audit,
    AuditReevaluationReason,
    AuditStatus,
    Device,
    Job,
    JobStatus,
    JobType,
    Organization,
    SecurityFact,
    Snapshot,
    SnapshotGroupingStatus,
    SnapshotSource,
    SnapshotStatus,
    User,
)
from app.db.session import create_session_factory
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.interpretation import (
    InterpretationInfrastructureError,
    InterpretationNotFoundError,
    InterpretationValidationError,
    interpret_audit,
    list_audit_security_facts,
)
from app.jobs.runner import PRODUCTION_HANDLERS
from app.jobs.service import enqueue_job
from app.profile_resolution import CISCO_IOS_XE_17
from app.snapshots.service import calculate_snapshot_hash


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_INTERPRETATION_POSTGRES_TEST") != "1",
    reason="Set SIH_INTERPRETATION_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def test_audit_interpretation_is_atomic_idempotent_and_tenant_safe(tmp_path, monkeypatch):
    settings = get_settings()
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    organization_ids = []

    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260907_0005"

        suffix = uuid4().hex
        first_org, first_user = bootstrap_admin(
            factory, "Interpretation A", f"interpret-a-{suffix}",
            f"interpret-a-{suffix}@example.invalid", "test-only-password",
        )
        second_org, second_user = bootstrap_admin(
            factory, "Interpretation B", f"interpret-b-{suffix}",
            f"interpret-b-{suffix}@example.invalid", "test-only-password",
        )
        organization_ids.extend([first_org, second_org])

        with factory.begin() as db:
            device = Device(organization_id=first_org, display_name="Semantic Device")
            failure_device = Device(organization_id=first_org, display_name="Failure Device")
            foreign_device = Device(organization_id=second_org, display_name="Foreign Device")
            db.add_all([device, failure_device, foreign_device])
            db.flush()

            snapshot, artifacts = _snapshot_with_configs(
                db,
                storage,
                organization_id=first_org,
                device_id=device.device_id,
                user_id=first_user,
                contents=(
                    (
                        "primary.cfg",
                        b"ip ssh version 2\nlogging host 192.0.2.10\n"
                        b"line vty 0 4\n exec-timeout 10 0\n transport input telnet ssh\n",
                    ),
                    (
                        "secondary.cfg",
                        b"logging host 192.0.2.11\nntp server 192.0.2.20\n",
                    ),
                ),
            )
            failure_snapshot, _ = _snapshot_with_configs(
                db,
                storage,
                organization_id=first_org,
                device_id=failure_device.device_id,
                user_id=first_user,
                contents=(("failure.cfg", b"ip ssh version 2\nlogging host 192.0.2.30\n"),),
            )
            foreign_snapshot, _ = _snapshot_with_configs(
                db,
                storage,
                organization_id=second_org,
                device_id=foreign_device.device_id,
                user_id=second_user,
                contents=(("foreign.cfg", b"ip ssh version 2\n"),),
            )

            audit = _audit(first_org, device.device_id, snapshot.snapshot_id, first_user)
            failure_audit = _audit(
                first_org, failure_device.device_id, failure_snapshot.snapshot_id, first_user
            )
            inconsistent_audit = _audit(
                first_org, foreign_device.device_id, foreign_snapshot.snapshot_id, first_user
            )
            db.add_all([audit, failure_audit, inconsistent_audit])
            db.flush()
            job = enqueue_job(
                db, JobType.AUDIT, audit_id=audit.audit_id, device_id=device.device_id
            )
            audit_id = audit.audit_id
            failure_audit_id = failure_audit.audit_id
            inconsistent_audit_id = inconsistent_audit.audit_id
            job_id = job.job_id
            source_artifact_ids = {artifact.artifact_id for artifact in artifacts}

        with factory() as db:
            with pytest.raises(InterpretationNotFoundError):
                interpret_audit(db, storage, audit_id, second_org)
            db.rollback()
            assert list_audit_security_facts(db, audit_id, second_org) == []

        with factory() as db:
            with pytest.raises(InterpretationValidationError):
                interpret_audit(db, storage, inconsistent_audit_id, first_org)
            db.rollback()
            assert list_audit_security_facts(db, inconsistent_audit_id, first_org) == []

        with factory() as db:
            first = interpret_audit(db, storage, audit_id, first_org)
            first_ids = {fact.fact_id for fact in first.facts}
            assert len(first.facts) == 7
            assert len(first.artifact_results) == 2

        with factory() as db:
            second = interpret_audit(db, storage, audit_id, first_org)
            assert {fact.fact_id for fact in second.facts} == first_ids
            assert db.scalar(select(func.count()).select_from(SecurityFact).where(
                SecurityFact.audit_id == audit_id
            )) == 7
            persisted = list_audit_security_facts(db, audit_id, first_org)
            assert {fact.fact_id for fact in persisted} == first_ids
            assert {fact.field_id for fact in persisted} == {
                "management.remote.telnet.enabled",
                "management.remote.ssh.enabled",
                "management.remote.ssh.version",
                "management.session.idle_timeout",
                "logging.remote.destination",
                "time.ntp.server",
            }
            assert {
                ref["artifact_id"]
                for fact in persisted
                for ref in fact.evidence_refs
            } == {str(item) for item in source_artifact_ids}
            assert all(ref["source_path"] in {"primary.cfg", "secondary.cfg"}
                       for fact in persisted for ref in fact.evidence_refs)
            assert all("artifacts" not in ref["source_path"]
                       for fact in persisted for ref in fact.evidence_refs)
            audit_row = db.get(Audit, audit_id)
            assert audit_row.status == AuditStatus.QUEUED
            assert audit_row.processing_stage is None
            assert audit_row.started_at is None and audit_row.completed_at is None
            assert audit_row.verdict_counts == {}
            assert audit_row.severity_counts == {}
            assert audit_row.coverage == {}
            queued_job = db.get(Job, job_id)
            assert queued_job.status == JobStatus.QUEUED
            assert queued_job.attempt_count == 0 and queued_job.started_at is None
            assert JobType.AUDIT not in PRODUCTION_HANDLERS

        with factory() as db:
            original_commit = db.commit

            def fail_commit():
                raise SQLAlchemyError("forced persistence failure")

            monkeypatch.setattr(db, "commit", fail_commit)
            with pytest.raises(InterpretationInfrastructureError):
                interpret_audit(db, storage, failure_audit_id, first_org)
            monkeypatch.setattr(db, "commit", original_commit)

        with factory() as db:
            assert db.scalar(select(func.count()).select_from(SecurityFact).where(
                SecurityFact.audit_id == failure_audit_id
            )) == 0
    finally:
        if organization_ids:
            with factory.begin() as db:
                audit_ids = select(Audit.audit_id).where(
                    Audit.organization_id.in_(organization_ids)
                )
                db.execute(delete(SecurityFact).where(SecurityFact.audit_id.in_(audit_ids)))
                db.execute(delete(Job).where(Job.audit_id.in_(audit_ids)))
                db.execute(delete(Audit).where(Audit.organization_id.in_(organization_ids)))
                db.execute(delete(Artifact).where(Artifact.organization_id.in_(organization_ids)))
                db.execute(delete(Snapshot).where(Snapshot.organization_id.in_(organization_ids)))
                db.execute(delete(Device).where(Device.organization_id.in_(organization_ids)))
                db.execute(delete(User).where(User.organization_id.in_(organization_ids)))
                db.execute(delete(Organization).where(
                    Organization.organization_id.in_(organization_ids)
                ))
        engine.dispose()


def _snapshot_with_configs(
    db, storage, *, organization_id, device_id, user_id, contents
):
    artifacts = []
    hashes = []
    for filename, content in contents:
        artifact_id = uuid4()
        reference = storage.write(
            content, organization_id=organization_id, artifact_id=artifact_id
        )
        digest = sha256(content).hexdigest()
        hashes.append(digest)
        artifacts.append(Artifact(
            artifact_id=artifact_id,
            organization_id=organization_id,
            original_filename=filename,
            storage_reference=reference,
            byte_size=len(content),
            sha256=digest,
            encoding="utf-8",
            content_family=ArtifactContentFamily.TEXT,
            evidence_type=ArtifactEvidenceType.CONFIGURATION,
            status=ArtifactStatus.READY,
            uploaded_by=user_id,
        ))
    snapshot = Snapshot(
        device_id=device_id,
        organization_id=organization_id,
        grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
        snapshot_hash=calculate_snapshot_hash(hashes),
        artifact_count=len(artifacts),
        source=SnapshotSource.UPLOAD,
        status=SnapshotStatus.LOCKED,
        created_by=user_id,
    )
    db.add(snapshot)
    db.flush()
    for artifact in artifacts:
        artifact.snapshot_id = snapshot.snapshot_id
    db.add_all(artifacts)
    return snapshot, artifacts


def _audit(organization_id, device_id, snapshot_id, created_by):
    return Audit(
        organization_id=organization_id,
        device_id=device_id,
        snapshot_id=snapshot_id,
        revision_number=1,
        reevaluation_reason=AuditReevaluationReason.INITIAL,
        status=AuditStatus.QUEUED,
        processing_stage=None,
        selected_frameworks=[],
        version_refs={},
        profile_resolution={
            "profile_id": CISCO_IOS_XE_17.profile_id,
            "profile_version_id": CISCO_IOS_XE_17.profile_version_id,
            "vendor": "Cisco",
            "product_family": "Catalyst",
            "os": "IOS XE",
            "os_version": "17.9.4a",
            "model": "C9300-48P",
            "serial_number": None,
            "confidence": "high",
            "resolution_status": "resolved",
        },
        verdict_counts={},
        severity_counts={},
        coverage={},
        created_by=created_by,
    )
