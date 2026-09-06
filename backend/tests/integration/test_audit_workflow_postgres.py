"""Opt-in PostgreSQL transaction checks for Step 4C Audit submission."""

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select, text

from app.audit.errors import AuditConflictError
from app.audit.schemas import AuditCreate
from app.audit.service import create_audit, start_audit
from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Artifact, ArtifactContentFamily, ArtifactEvidenceType, ArtifactStatus,
    Audit, AuditStatus, Device, Job, JobStatus, Organization, Snapshot,
    SnapshotGroupingStatus, SnapshotSource, SnapshotStatus, User,
)
from app.db.session import create_session_factory, get_db
from app.jobs.enums import JobType
from app.jobs.runner import PRODUCTION_HANDLERS, WorkerRuntime
from app.main import create_app
from app.snapshots.errors import SnapshotConflictError
from app.snapshots.service import add_artifact, calculate_snapshot_hash


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_AUDIT_POSTGRES_TEST") != "1",
    reason="Set SIH_AUDIT_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def test_concurrent_audit_start_is_atomic_tenant_scoped_and_worker_safe():
    settings = get_settings().model_copy(update={
        "api_prefix": "/api/v1", "auth_cookie_name": "audit_postgres_test",
        "auth_cookie_secure": False, "auth_cookie_samesite": "lax",
    })
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    organization_ids = []
    device_id = None
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260906_0004"
        suffix = uuid4().hex
        first_org, first_user = bootstrap_admin(
            factory, "Audit Integration A", f"audit-integration-a-{suffix}",
            f"audit-a-{suffix}@example.invalid", "test-password"
        )
        second_org, _ = bootstrap_admin(
            factory, "Audit Integration B", f"audit-integration-b-{suffix}",
            f"audit-b-{suffix}@example.invalid", "test-password"
        )
        organization_ids.extend([first_org, second_org])
        with factory.begin() as db:
            device = Device(organization_id=first_org, display_name="Audit Device")
            db.add(device)
            db.flush()
            device_id = device.device_id
            artifact_hash = "a" * 64
            snapshot = Snapshot(
                device_id=device_id,
                organization_id=first_org,
                grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
                snapshot_hash=calculate_snapshot_hash([artifact_hash]),
                artifact_count=1,
                source=SnapshotSource.UPLOAD,
                status=SnapshotStatus.READY,
                created_by=first_user,
            )
            db.add(snapshot)
            db.flush()
            snapshot_id = snapshot.snapshot_id
            member = Artifact(
                organization_id=first_org,
                snapshot_id=snapshot_id,
                original_filename="member.cfg",
                storage_reference=f"organizations/{first_org}/artifacts/{uuid4()}",
                byte_size=1,
                sha256=artifact_hash,
                content_family=ArtifactContentFamily.TEXT,
                evidence_type=ArtifactEvidenceType.CONFIGURATION,
                status=ArtifactStatus.READY,
                uploaded_by=first_user,
            )
            extra = Artifact(
                organization_id=first_org,
                original_filename="extra.cfg",
                storage_reference=f"organizations/{first_org}/artifacts/{uuid4()}",
                byte_size=1,
                sha256="b" * 64,
                content_family=ArtifactContentFamily.TEXT,
                evidence_type=ArtifactEvidenceType.CONFIGURATION,
                status=ArtifactStatus.READY,
                uploaded_by=first_user,
            )
            db.add_all([member, extra])
            db.flush()
            extra_id = extra.artifact_id

        with factory() as db:
            audit = create_audit(
                db, db.get(User, first_user),
                AuditCreate(snapshot_id=snapshot_id, selected_frameworks=["future-framework"]),
            )
            audit_id = audit.audit_id
            assert audit.status == AuditStatus.DRAFT
        with factory() as db:
            assert db.get(Snapshot, snapshot_id).status == SnapshotStatus.READY

        barrier = Barrier(2)

        def submit():
            with factory() as db:
                user = db.get(User, first_user)
                barrier.wait(timeout=5)
                try:
                    _, job = start_audit(db, user, audit_id)
                    return "queued", job.job_id
                except AuditConflictError:
                    db.rollback()
                    return "conflict", None

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _index: submit(), range(2)))
        assert sorted(result[0] for result in results) == ["conflict", "queued"]
        job_id = next(result[1] for result in results if result[1] is not None)

        with factory() as db:
            audit = db.get(Audit, audit_id)
            snapshot = db.get(Snapshot, snapshot_id)
            job = db.get(Job, job_id)
            assert audit.status == AuditStatus.QUEUED
            assert audit.processing_stage is None and audit.started_at is None
            assert snapshot.status == SnapshotStatus.LOCKED
            assert db.scalar(select(func.count()).select_from(Job).where(
                Job.audit_id == audit_id, Job.job_type == JobType.AUDIT
            )) == 1
            assert job.status == JobStatus.QUEUED
            assert job.progress == 0 and job.attempt_count == 0
            assert job.started_at is None and job.completed_at is None
            with pytest.raises(SnapshotConflictError):
                add_artifact(db, db.get(User, first_user), snapshot_id, extra_id)
            db.rollback()

        runtime = WorkerRuntime(
            factory, handlers=PRODUCTION_HANDLERS,
            poll_interval_seconds=settings.worker_poll_interval_seconds,
        )
        assert JobType.AUDIT not in runtime.supported_job_types
        assert runtime.run_iteration() is False
        with factory() as db:
            job = db.get(Job, job_id)
            assert job.status == JobStatus.QUEUED and job.attempt_count == 0

        application = create_app(settings)
        application.dependency_overrides[get_settings] = lambda: settings

        def session_dependency():
            with factory() as db:
                yield db

        application.dependency_overrides[get_db] = session_dependency
        with TestClient(application) as client:
            assert client.post("/api/v1/auth/login", json={
                "email": f"audit-a-{suffix}@example.invalid", "password": "test-password"
            }).status_code == 200
            assert client.get(f"/api/v1/jobs/{job_id}").status_code == 200
            client.cookies.clear()
            assert client.post("/api/v1/auth/login", json={
                "email": f"audit-b-{suffix}@example.invalid", "password": "test-password"
            }).status_code == 200
            assert client.get(f"/api/v1/audits/{audit_id}").status_code == 404
            assert client.get(f"/api/v1/jobs/{job_id}").status_code == 404
    finally:
        if organization_ids and device_id is not None:
            with factory.begin() as db:
                db.execute(delete(Job).where(Job.device_id == device_id))
                db.execute(delete(Audit).where(Audit.organization_id.in_(organization_ids)))
                db.execute(delete(Artifact).where(Artifact.organization_id.in_(organization_ids)))
                db.execute(delete(Snapshot).where(Snapshot.organization_id.in_(organization_ids)))
                db.execute(delete(Device).where(Device.organization_id.in_(organization_ids)))
                db.execute(delete(User).where(User.organization_id.in_(organization_ids)))
                db.execute(delete(Organization).where(
                    Organization.organization_id.in_(organization_ids)
                ))
        engine.dispose()
