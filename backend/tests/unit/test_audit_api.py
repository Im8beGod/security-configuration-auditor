from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.models import Audit, AuditStatus, Job, JobStatus, JobType, Snapshot, SnapshotStatus, User, UserRole
from app.db.session import get_db
from app.ingestion.storage import LocalFilesystemArtifactStorage, get_artifact_storage
from app.jobs.errors import JobError
from app.jobs.runner import PRODUCTION_HANDLERS, WorkerRuntime
from app.jobs.service import enqueue_job
from app.main import create_app


@pytest.fixture
def audit_context(workflow_factory, auth_settings, tmp_path):
    first = bootstrap_admin(
        workflow_factory, "Audit A", "audit-a", "audit-a@example.invalid", "test-password"
    )
    second = bootstrap_admin(
        workflow_factory, "Audit B", "audit-b", "audit-b@example.invalid", "test-password"
    )
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    application = create_app(auth_settings)
    application.dependency_overrides[get_settings] = lambda: auth_settings
    application.dependency_overrides[get_artifact_storage] = lambda: storage

    def session_dependency():
        with workflow_factory() as db:
            yield db

    application.dependency_overrides[get_db] = session_dependency
    with TestClient(application) as client:
        yield client, workflow_factory, application, first, second


def login(client, email="audit-a@example.invalid"):
    response = client.post(
        "/api/v1/auth/login", json={"email": email, "password": "test-password"}
    )
    assert response.status_code == 200


def ready_snapshot(client):
    device = client.post("/api/v1/devices", json={"display_name": "Audit Device"}).json()
    snapshot = client.post(
        f"/api/v1/devices/{device['device_id']}/snapshots", json={}
    ).json()
    artifact = client.post("/api/v1/artifacts/upload", files={
        "file": ("audit.cfg", b"hostname audit\n", "text/plain")
    }).json()
    assert client.post(
        f"/api/v1/snapshots/{snapshot['snapshot_id']}/artifacts/{artifact['artifact_id']}"
    ).status_code == 200
    finalized = client.post(f"/api/v1/snapshots/{snapshot['snapshot_id']}/finalize")
    assert finalized.status_code == 200
    return device, finalized.json(), artifact


def create_audit(client, snapshot_id, **extra):
    return client.post("/api/v1/audits", json={
        "snapshot_id": snapshot_id, "selected_frameworks": ["future-framework"], **extra
    })


def test_audit_endpoints_require_authentication(audit_context):
    client = audit_context[0]
    assert client.get("/api/v1/audits").status_code == 401
    assert client.post("/api/v1/audits", json={"snapshot_id": str(uuid4())}).status_code == 401
    assert client.get(f"/api/v1/jobs/{uuid4()}").status_code == 401


def test_create_initial_audit_is_honest_and_does_not_lock_snapshot(audit_context):
    client, _, _, (organization_id, user_id), _ = audit_context
    login(client)
    device, snapshot, _ = ready_snapshot(client)
    response = create_audit(client, snapshot["snapshot_id"])
    assert response.status_code == 201
    body = response.json()
    assert body["organization_id"] == str(organization_id)
    assert body["device_id"] == device["device_id"]
    assert body["snapshot_id"] == snapshot["snapshot_id"]
    assert body["created_by"] == str(user_id)
    assert body["revision_number"] == 1
    assert body["previous_audit_id"] is None
    assert body["audit_batch_id"] is None
    assert body["reevaluation_reason"] == "initial"
    assert body["status"] == "draft" and body["processing_stage"] is None
    assert body["started_at"] is None and body["completed_at"] is None
    assert body["selected_frameworks"] == ["future-framework"]
    assert body["version_refs"] == body["profile_resolution"] == {}
    assert body["verdict_counts"] == body["severity_counts"] == body["coverage"] == {}
    assert body["job"] is None
    assert client.get(f"/api/v1/snapshots/{snapshot['snapshot_id']}").json()["status"] == "ready"
    assert create_audit(client, snapshot["snapshot_id"]).status_code == 409
    listed = client.get("/api/v1/audits").json()
    assert [item["audit_id"] for item in listed] == [body["audit_id"]]
    assert client.get(f"/api/v1/audits/{body['audit_id']}").status_code == 200


def test_create_rejects_protected_fields_and_non_ready_snapshots(audit_context):
    client, factory, *_ = audit_context
    login(client)
    device = client.post("/api/v1/devices", json={"display_name": "Draft"}).json()
    draft = client.post(f"/api/v1/devices/{device['device_id']}/snapshots", json={}).json()
    assert create_audit(client, draft["snapshot_id"]).status_code == 409
    _, ready, _ = ready_snapshot(client)
    assert create_audit(client, ready["snapshot_id"], status="queued").status_code == 422
    for state in (SnapshotStatus.LOCKED, SnapshotStatus.ARCHIVED):
        with factory.begin() as db:
            db.execute(update(Snapshot).where(
                Snapshot.snapshot_id == UUID(ready["snapshot_id"])
            ).values(status=state))
        assert create_audit(client, ready["snapshot_id"]).status_code == 409


def test_run_atomically_locks_snapshot_and_enqueues_truthful_job(audit_context):
    client, factory, *_ = audit_context
    login(client)
    _, snapshot, artifact = ready_snapshot(client)
    audit = create_audit(client, snapshot["snapshot_id"]).json()
    response = client.post(f"/api/v1/audits/{audit['audit_id']}/run")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "queued"
    assert body["processing_stage"] is None
    assert body["started_at"] is None and body["completed_at"] is None
    job = body["job"]
    assert job["job_type"] == "audit" and job["status"] == "queued"
    assert job["progress"] == 0 and job["attempt_count"] == 0
    assert job["stage"] is None and job["started_at"] is None
    assert client.get(f"/api/v1/snapshots/{snapshot['snapshot_id']}").json()["status"] == "locked"
    assert client.patch(
        f"/api/v1/snapshots/{snapshot['snapshot_id']}", json={"label": "changed"}
    ).status_code == 409
    assert client.delete(
        f"/api/v1/snapshots/{snapshot['snapshot_id']}/artifacts/{artifact['artifact_id']}"
    ).status_code == 409
    repeated = client.post(f"/api/v1/audits/{audit['audit_id']}/run")
    assert repeated.status_code == 409
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Job).where(
            Job.audit_id == UUID(audit["audit_id"])
        )) == 1


def test_queue_failure_rolls_back_audit_and_snapshot(audit_context, monkeypatch):
    client, factory, _, *_ = audit_context
    login(client)
    _, snapshot, _ = ready_snapshot(client)
    audit = create_audit(client, snapshot["snapshot_id"]).json()

    def fail_enqueue(*_args, **_kwargs):
        raise JobError("private queue detail")

    monkeypatch.setattr("app.audit.service.enqueue_job", fail_enqueue)
    response = client.post(f"/api/v1/audits/{audit['audit_id']}/run")
    assert response.status_code == 503
    assert "private" not in response.text
    with factory() as db:
        persisted_audit = db.get(Audit, UUID(audit["audit_id"]))
        persisted_snapshot = db.get(Snapshot, UUID(snapshot["snapshot_id"]))
        assert persisted_audit.status == AuditStatus.DRAFT
        assert persisted_snapshot.status == SnapshotStatus.READY
        assert db.scalar(select(func.count()).select_from(Job).where(
            Job.audit_id == persisted_audit.audit_id
        )) == 0


def test_audit_and_job_retrieval_are_tenant_scoped_and_payload_hidden(audit_context):
    client, factory, *_ = audit_context
    login(client)
    _, snapshot, _ = ready_snapshot(client)
    audit = create_audit(client, snapshot["snapshot_id"]).json()
    queued = client.post(f"/api/v1/audits/{audit['audit_id']}/run").json()
    job_id = queued["job"]["job_id"]
    own_job = client.get(f"/api/v1/jobs/{job_id}")
    assert own_job.status_code == 200
    assert "payload" not in own_job.json()
    with factory.begin() as db:
        system_job_id = enqueue_job(
            db, JobType.SYSTEM_NOOP, payload={"secret": "must-not-be-exposed"}
        ).job_id
    assert client.get(f"/api/v1/jobs/{system_job_id}").status_code == 404
    client.cookies.clear()
    login(client, "audit-b@example.invalid")
    assert client.get(f"/api/v1/audits/{audit['audit_id']}").status_code == 404
    assert client.post(f"/api/v1/audits/{audit['audit_id']}/run").status_code == 404
    assert client.get(f"/api/v1/jobs/{job_id}").status_code == 404
    assert client.get("/api/v1/audits").json() == []


def test_current_worker_leaves_created_audit_job_queued(audit_context):
    client, factory, *_ = audit_context
    login(client)
    _, snapshot, _ = ready_snapshot(client)
    audit = create_audit(client, snapshot["snapshot_id"]).json()
    job_id = UUID(client.post(f"/api/v1/audits/{audit['audit_id']}/run").json()["job"]["job_id"])
    runtime = WorkerRuntime(factory, handlers=PRODUCTION_HANDLERS, poll_interval_seconds=1.0)
    assert JobType.AUDIT not in runtime.supported_job_types
    assert runtime.run_iteration() is False
    with factory() as db:
        job = db.get(Job, job_id)
        assert job.status == JobStatus.QUEUED
        assert job.attempt_count == 0 and job.started_at is None


def test_analyst_cannot_start_reevaluation(audit_context):
    client, factory, _, (_, user_id), _ = audit_context
    login(client)
    _, snapshot, _ = ready_snapshot(client)
    audit = create_audit(client, snapshot["snapshot_id"]).json()
    with factory.begin() as db:
        db.get(User, user_id).role = UserRole.ANALYST
    response = client.post(f"/api/v1/audits/{audit['audit_id']}/re-evaluate", json={"knowledge_pack_version_id": str(uuid4())})
    assert response.status_code == 403
