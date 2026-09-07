"""Opt-in PostgreSQL verification for the Batch 5A audit integration boundary."""

import os
from hashlib import sha256
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text

from app.audit.errors import AuditNotFoundError, AuditValidationError
from app.audit.service import resolve_audit_profile
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
    Snapshot,
    SnapshotGroupingStatus,
    SnapshotSource,
    SnapshotStatus,
    User,
)
from app.db.session import create_session_factory
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.jobs.runner import PRODUCTION_HANDLERS, WorkerRuntime
from app.jobs.service import enqueue_job
from app.profile_resolution import CISCO_IOS_XE_17, ResolutionStatus
from app.snapshots.errors import SnapshotConflictError
from app.snapshots.service import calculate_snapshot_hash, remove_artifact


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_PROFILE_POSTGRES_TEST") != "1",
    reason="Set SIH_PROFILE_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def test_profile_resolution_persists_atomically_with_tenant_and_snapshot_boundaries(tmp_path):
    settings = get_settings()
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    organization_ids = []

    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260907_0009"

        suffix = uuid4().hex
        first_org, first_user = bootstrap_admin(
            factory,
            "Profile Integration A",
            f"profile-a-{suffix}",
            f"profile-a-{suffix}@example.invalid",
            "test-only-password",
        )
        second_org, second_user = bootstrap_admin(
            factory,
            "Profile Integration B",
            f"profile-b-{suffix}",
            f"profile-b-{suffix}@example.invalid",
            "test-only-password",
        )
        organization_ids.extend([first_org, second_org])

        with factory.begin() as db:
            device = Device(organization_id=first_org, display_name="Profile Device")
            foreign_device = Device(organization_id=second_org, display_name="Foreign Device")
            db.add_all([device, foreign_device])
            db.flush()

            evidence_specs = (
                (
                    "running-config.txt",
                    ArtifactEvidenceType.CONFIGURATION,
                    b"hostname edge\ninterface GigabitEthernet1\naaa new-model\nline vty 0 4\n",
                    True,
                ),
                (
                    "show-version.txt",
                    ArtifactEvidenceType.VERSION_OUTPUT,
                    b"Cisco IOS XE Software, Version 17.9.4a\n"
                    b"cisco C9300-48P (X86) processor with 8388608K bytes of memory\n",
                    True,
                ),
                (
                    "show-inventory.txt",
                    ArtifactEvidenceType.INVENTORY_OUTPUT,
                    b'NAME: "Chassis", DESCR: "Cisco Catalyst 9300"\n'
                    b"PID: C9300-48P, VID: V02, SN: FCW00000001\n",
                    True,
                ),
                (
                    "unavailable.txt",
                    ArtifactEvidenceType.UNKNOWN_EVIDENCE,
                    b"unavailable metadata remains bounded",
                    False,
                ),
            )
            artifact_rows = []
            artifact_hashes = []
            for filename, evidence_type, content, store_bytes in evidence_specs:
                artifact_id = uuid4()
                reference = f"organizations/{first_org}/artifacts/{artifact_id}"
                if store_bytes:
                    reference = storage.write(
                        content, organization_id=first_org, artifact_id=artifact_id
                    )
                artifact_hash = sha256(content).hexdigest()
                artifact_hashes.append(artifact_hash)
                artifact_rows.append(Artifact(
                    artifact_id=artifact_id,
                    organization_id=first_org,
                    original_filename=filename,
                    storage_reference=reference,
                    byte_size=len(content),
                    sha256=artifact_hash,
                    encoding="utf-8",
                    content_family=ArtifactContentFamily.TEXT,
                    evidence_type=evidence_type,
                    status=ArtifactStatus.READY,
                    uploaded_by=first_user,
                ))

            snapshot = Snapshot(
                device_id=device.device_id,
                organization_id=first_org,
                grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
                snapshot_hash=calculate_snapshot_hash(artifact_hashes),
                artifact_count=len(artifact_rows),
                source=SnapshotSource.UPLOAD,
                status=SnapshotStatus.LOCKED,
                created_by=first_user,
            )
            db.add(snapshot)
            db.flush()
            for artifact in artifact_rows:
                artifact.snapshot_id = snapshot.snapshot_id
            db.add_all(artifact_rows)

            unrelated_content = b"Junos: 23.4R1.9\n"
            unrelated_id = uuid4()
            unrelated_reference = storage.write(
                unrelated_content, organization_id=first_org, artifact_id=unrelated_id
            )
            unrelated_hash = sha256(unrelated_content).hexdigest()
            unrelated_snapshot = Snapshot(
                device_id=device.device_id,
                organization_id=first_org,
                grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
                snapshot_hash=calculate_snapshot_hash([unrelated_hash]),
                artifact_count=1,
                source=SnapshotSource.UPLOAD,
                status=SnapshotStatus.LOCKED,
                created_by=first_user,
            )
            db.add(unrelated_snapshot)
            db.flush()
            db.add(Artifact(
                artifact_id=unrelated_id,
                organization_id=first_org,
                snapshot_id=unrelated_snapshot.snapshot_id,
                original_filename="unrelated-version.txt",
                storage_reference=unrelated_reference,
                byte_size=len(unrelated_content),
                sha256=unrelated_hash,
                encoding="utf-8",
                content_family=ArtifactContentFamily.TEXT,
                evidence_type=ArtifactEvidenceType.VERSION_OUTPUT,
                status=ArtifactStatus.READY,
                uploaded_by=first_user,
            ))

            foreign_content = b"Junos: 22.4R3\n"
            foreign_artifact_id = uuid4()
            foreign_reference = storage.write(
                foreign_content, organization_id=second_org, artifact_id=foreign_artifact_id
            )
            foreign_hash = sha256(foreign_content).hexdigest()
            foreign_snapshot = Snapshot(
                device_id=foreign_device.device_id,
                organization_id=second_org,
                grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
                snapshot_hash=calculate_snapshot_hash([foreign_hash]),
                artifact_count=1,
                source=SnapshotSource.UPLOAD,
                status=SnapshotStatus.LOCKED,
                created_by=second_user,
            )
            db.add(foreign_snapshot)
            db.flush()
            db.add(Artifact(
                artifact_id=foreign_artifact_id,
                organization_id=second_org,
                snapshot_id=foreign_snapshot.snapshot_id,
                original_filename="foreign-version.txt",
                storage_reference=foreign_reference,
                byte_size=len(foreign_content),
                sha256=foreign_hash,
                encoding="utf-8",
                content_family=ArtifactContentFamily.TEXT,
                evidence_type=ArtifactEvidenceType.VERSION_OUTPUT,
                status=ArtifactStatus.READY,
                uploaded_by=second_user,
            ))

            audit = _audit(first_org, device.device_id, snapshot.snapshot_id, first_user)
            inconsistent_audit = _audit(
                first_org,
                foreign_device.device_id,
                foreign_snapshot.snapshot_id,
                first_user,
            )
            db.add_all([audit, inconsistent_audit])
            db.flush()
            job = enqueue_job(
                db, JobType.AUDIT, audit_id=audit.audit_id, device_id=device.device_id
            )
            audit_id = audit.audit_id
            inconsistent_audit_id = inconsistent_audit.audit_id
            snapshot_id = snapshot.snapshot_id
            first_artifact_id = artifact_rows[0].artifact_id
            job_id = job.job_id

        with factory() as db:
            with pytest.raises(AuditNotFoundError):
                resolve_audit_profile(db, storage, audit_id, second_org)
            db.rollback()
            assert db.get(Audit, audit_id).profile_resolution == {}

        with factory() as db:
            with pytest.raises(AuditValidationError):
                resolve_audit_profile(db, storage, inconsistent_audit_id, first_org)
            db.rollback()
            assert db.get(Audit, inconsistent_audit_id).profile_resolution == {}

        with factory() as db:
            result = resolve_audit_profile(db, storage, audit_id, first_org)
            assert result.resolution_status == ResolutionStatus.RESOLVED
            assert result.selected_profile_version_id == CISCO_IOS_XE_17.profile_version_id
            assert result.os_version == "17.9.4a"
            assert result.model == "C9300-48P"
            assert result.serial_number == "FCW00000001"

        with factory() as db:
            persisted = db.get(Audit, audit_id)
            assert persisted.profile_resolution == result.to_persisted()
            assert persisted.status == AuditStatus.QUEUED
            assert persisted.processing_stage is None
            assert persisted.started_at is None and persisted.completed_at is None
            assert persisted.version_refs == {}
            assert persisted.verdict_counts == {}
            assert persisted.severity_counts == {}
            assert persisted.coverage == {}
            snapshot = db.get(Snapshot, snapshot_id)
            assert snapshot.status == SnapshotStatus.LOCKED
            assert snapshot.artifact_count == len(evidence_specs)
            with pytest.raises(SnapshotConflictError):
                remove_artifact(db, db.get(User, first_user), snapshot_id, first_artifact_id)
            db.rollback()

        runtime = WorkerRuntime(
            factory,
            handlers=PRODUCTION_HANDLERS,
            poll_interval_seconds=settings.worker_poll_interval_seconds,
        )
        assert JobType.AUDIT not in runtime.supported_job_types
        assert runtime.run_iteration() is False
        with factory() as db:
            queued_job = db.get(Job, job_id)
            assert queued_job.status == JobStatus.QUEUED
            assert queued_job.attempt_count == 0 and queued_job.started_at is None
    finally:
        if organization_ids:
            with factory.begin() as db:
                audit_ids = select(Audit.audit_id).where(
                    Audit.organization_id.in_(organization_ids)
                )
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
        profile_resolution={},
        verdict_counts={},
        severity_counts={},
        coverage={},
        created_by=created_by,
    )
