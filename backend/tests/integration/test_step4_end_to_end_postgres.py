"""Integrated Step 4 acceptance against an already-migrated PostgreSQL database."""

import os
from hashlib import sha256
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select, text

from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Artifact, Audit, Device, Job, JobStatus, Organization, Snapshot,
    SnapshotStatus, User,
)
from app.db.session import create_session_factory, get_db
from app.ingestion.storage import LocalFilesystemArtifactStorage, get_artifact_storage
from app.jobs.enums import JobType
from app.jobs.runner import PRODUCTION_HANDLERS, WorkerRuntime
from app.main import create_app
from app.snapshots.service import calculate_snapshot_hash


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_STEP4_POSTGRES_TEST") != "1",
    reason="Set SIH_STEP4_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def test_step4_integrated_workflow_reaches_truthful_queue_boundary(tmp_path):
    settings = get_settings().model_copy(update={
        "api_prefix": "/api/v1",
        "auth_cookie_name": "step4_acceptance_test",
        "auth_cookie_secure": False,
        "auth_cookie_samesite": "lax",
        "artifact_max_upload_bytes": 1024,
        "artifact_max_bulk_files": 5,
    })
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    organization_ids = []
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260907_0009"

        suffix = uuid4().hex
        first_org, _ = bootstrap_admin(
            factory, "Step 4 Acceptance A", f"step4-acceptance-a-{suffix}",
            f"step4-a-{suffix}@example.invalid", "test-only-password",
        )
        second_org, _ = bootstrap_admin(
            factory, "Step 4 Acceptance B", f"step4-acceptance-b-{suffix}",
            f"step4-b-{suffix}@example.invalid", "test-only-password",
        )
        organization_ids.extend([first_org, second_org])

        application = create_app(settings)
        application.dependency_overrides[get_settings] = lambda: settings
        application.dependency_overrides[get_artifact_storage] = lambda: storage

        def session_dependency():
            with factory() as db:
                yield db

        application.dependency_overrides[get_db] = session_dependency
        with TestClient(application) as client:
            assert client.post("/api/v1/auth/login", json={
                "email": f"step4-a-{suffix}@example.invalid",
                "password": "test-only-password",
            }).status_code == 200

            config_bytes = b"hostname acceptance-edge\ninterface GigabitEthernet1\n"
            json_bytes = b'{"source":"synthetic","interfaces":[]}'
            mixed = client.post("/api/v1/artifacts/bulk-upload", files=[
                ("files", ("../acceptance.cfg", config_bytes, "application/octet-stream")),
                ("files", ("acceptance.json", json_bytes, "text/plain")),
                ("files", ("rejected.json", b'{"broken":', "application/json")),
            ])
            assert mixed.status_code == 200
            body = mixed.json()
            assert (body["total"], body["succeeded"], body["failed"]) == (3, 2, 1)
            successful = [item["artifact"] for item in body["results"] if item["status"] == "success"]
            rejected = next(item for item in body["results"] if item["status"] == "failed")
            assert rejected["error"] == {
                "code": "malformed_json", "message": "Uploaded JSON is malformed",
            }
            assert successful[0]["original_filename"] == "acceptance.cfg"
            assert successful[0]["sha256"] == sha256(config_bytes).hexdigest()
            assert successful[0]["byte_size"] == len(config_bytes)
            assert storage.read(successful[0]["storage_reference"]) == config_bytes
            assert successful[1]["sha256"] == sha256(json_bytes).hexdigest()
            listed = client.get("/api/v1/artifacts").json()
            assert {item["artifact_id"] for item in listed} == {
                item["artifact_id"] for item in successful
            }

            device = client.post("/api/v1/devices", json={
                "display_name": "Acceptance Edge", "device_class": "unknown",
                "identity_status": "manually_confirmed",
            })
            assert device.status_code == 201
            device_id = device.json()["device_id"]
            snapshot = client.post(f"/api/v1/devices/{device_id}/snapshots", json={
                "label": "Acceptance evidence", "source": "upload",
                "grouping_status": "manually_confirmed",
            })
            assert snapshot.status_code == 201
            snapshot_id = snapshot.json()["snapshot_id"]
            artifact_id = successful[0]["artifact_id"]
            attached = client.post(f"/api/v1/snapshots/{snapshot_id}/artifacts/{artifact_id}")
            assert attached.status_code == 200
            assert attached.json()["artifact_count"] == 1
            assert attached.json()["snapshot_hash"] == calculate_snapshot_hash([
                successful[0]["sha256"]
            ])
            ready = client.post(f"/api/v1/snapshots/{snapshot_id}/finalize")
            assert ready.status_code == 200 and ready.json()["status"] == "ready"

            audit = client.post("/api/v1/audits", json={
                "snapshot_id": snapshot_id, "selected_frameworks": [],
            })
            assert audit.status_code == 201 and audit.json()["status"] == "draft"
            audit_id = audit.json()["audit_id"]
            assert client.get(f"/api/v1/snapshots/{snapshot_id}").json()["status"] == "ready"
            queued = client.post(f"/api/v1/audits/{audit_id}/run")
            assert queued.status_code == 200 and queued.json()["status"] == "queued"
            job = queued.json()["job"]
            assert job["job_type"] == "audit" and job["status"] == "queued"
            assert job["progress"] == 0 and job["attempt_count"] == 0
            assert job["started_at"] is None and job["completed_at"] is None
            job_id = job["job_id"]

            runtime = WorkerRuntime(
                factory, handlers=PRODUCTION_HANDLERS,
                poll_interval_seconds=settings.worker_poll_interval_seconds,
            )
            assert runtime.supported_job_types == frozenset({JobType.SYSTEM_NOOP})
            assert [runtime.run_iteration() for _ in range(3)] == [False, False, False]
            assert client.post(
                f"/api/v1/snapshots/{snapshot_id}/artifacts/{successful[1]['artifact_id']}"
            ).status_code == 409
            assert client.patch(
                f"/api/v1/snapshots/{snapshot_id}", json={"label": "Too late"}
            ).status_code == 409
            assert client.post(f"/api/v1/snapshots/{snapshot_id}/finalize").status_code == 409

            persisted_audit = client.get(f"/api/v1/audits/{audit_id}")
            persisted_job = client.get(f"/api/v1/jobs/{job_id}")
            persisted_snapshot = client.get(f"/api/v1/snapshots/{snapshot_id}")
            assert persisted_audit.status_code == persisted_job.status_code == 200
            assert persisted_snapshot.json()["status"] == "locked"
            assert persisted_audit.json()["status"] == "queued"
            assert persisted_audit.json()["verdict_counts"] == {}
            assert persisted_audit.json()["severity_counts"] == {}
            assert persisted_audit.json()["coverage"] == {}
            assert persisted_job.json()["status"] == "queued"
            assert persisted_job.json()["attempt_count"] == 0
            with factory() as db:
                assert db.scalar(select(func.count()).select_from(Job).where(
                    Job.audit_id == audit_id, Job.job_type == JobType.AUDIT,
                )) == 1

            client.cookies.clear()
            assert client.post("/api/v1/auth/login", json={
                "email": f"step4-b-{suffix}@example.invalid",
                "password": "test-only-password",
            }).status_code == 200
            assert client.get(f"/api/v1/artifacts/{artifact_id}").status_code == 404
            assert client.get(f"/api/v1/devices/{device_id}").status_code == 404
            assert client.get(f"/api/v1/snapshots/{snapshot_id}").status_code == 404
            assert client.get(f"/api/v1/audits/{audit_id}").status_code == 404
            assert client.get(f"/api/v1/jobs/{job_id}").status_code == 404
            assert all(item["organization_id"] == str(second_org) for item in client.get(
                "/api/v1/artifacts"
            ).json())
    finally:
        if organization_ids:
            with factory.begin() as db:
                db.execute(delete(Job).where(Job.audit_id.in_(
                    select(Audit.audit_id).where(Audit.organization_id.in_(organization_ids))
                )))
                db.execute(delete(Audit).where(Audit.organization_id.in_(organization_ids)))
                db.execute(delete(Artifact).where(Artifact.organization_id.in_(organization_ids)))
                db.execute(delete(Snapshot).where(Snapshot.organization_id.in_(organization_ids)))
                db.execute(delete(Device).where(Device.organization_id.in_(organization_ids)))
                db.execute(delete(User).where(User.organization_id.in_(organization_ids)))
                db.execute(delete(Organization).where(
                    Organization.organization_id.in_(organization_ids)
                ))
        engine.dispose()
