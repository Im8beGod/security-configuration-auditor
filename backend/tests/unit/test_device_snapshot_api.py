from hashlib import sha256
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.models import Artifact, Snapshot, SnapshotStatus
from app.db.session import get_db
from app.ingestion.storage import LocalFilesystemArtifactStorage, get_artifact_storage
from app.main import create_app
from app.snapshots.service import EMPTY_SNAPSHOT_HASH, calculate_snapshot_hash


@pytest.fixture
def workflow_context(workflow_factory, auth_settings, tmp_path):
    first = bootstrap_admin(
        workflow_factory, "Workflow A", "workflow-a", "a@example.invalid", "test-password"
    )
    second = bootstrap_admin(
        workflow_factory, "Workflow B", "workflow-b", "b@example.invalid", "test-password"
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
        yield client, workflow_factory, first, second


def login(client, email="a@example.invalid"):
    response = client.post(
        "/api/v1/auth/login", json={"email": email, "password": "test-password"}
    )
    assert response.status_code == 200


def create_device(client, name="Edge One"):
    return client.post("/api/v1/devices", json={
        "display_name": name,
        "latest_hostname": "edge-1",
        "device_class": "router",
        "identity_status": "manually_confirmed",
    })


def create_snapshot(client, device_id, **body):
    return client.post(f"/api/v1/devices/{device_id}/snapshots", json=body)


def upload(client, name, data):
    response = client.post(
        "/api/v1/artifacts/upload", files={"file": (name, data, "text/plain")}
    )
    assert response.status_code == 201
    return response.json()


def test_device_endpoints_require_authentication(workflow_context):
    client = workflow_context[0]
    assert client.get("/api/v1/devices").status_code == 401
    assert create_device(client).status_code == 401


def test_device_crud_is_tenant_scoped_and_fields_are_server_authoritative(workflow_context):
    client, _, (organization_id, _), _ = workflow_context
    login(client)
    created = create_device(client)
    assert created.status_code == 201
    body = created.json()
    assert body["organization_id"] == str(organization_id)
    assert body["display_name"] == "Edge One"
    assert body["device_class"] == "router"
    assert "vendor" not in body and "os_version" not in body
    device_id = body["device_id"]
    assert [item["device_id"] for item in client.get("/api/v1/devices").json()] == [device_id]
    assert client.get(f"/api/v1/devices/{device_id}").status_code == 200
    patched = client.patch(f"/api/v1/devices/{device_id}", json={
        "display_name": " Edge Updated ", "asset_tag": " asset-7 ", "is_active": False
    })
    assert patched.status_code == 200
    assert patched.json()["display_name"] == "Edge Updated"
    assert patched.json()["asset_tag"] == "asset-7"
    assert patched.json()["is_active"] is False
    assert client.patch(f"/api/v1/devices/{device_id}", json={
        "organization_id": str(organization_id)
    }).status_code == 422
    assert create_device(client, "Second").status_code == 201
    assert [item["display_name"] for item in client.get("/api/v1/devices").json()] == [
        "Edge Updated", "Second"
    ]
    client.cookies.clear()
    login(client, "b@example.invalid")
    assert client.get(f"/api/v1/devices/{device_id}").status_code == 404
    assert client.patch(f"/api/v1/devices/{device_id}", json={"display_name": "x"}).status_code == 404
    assert client.get("/api/v1/devices").json() == []


@pytest.mark.parametrize("field,value", [
    ("device_class", "server"), ("identity_status", "guessed")
])
def test_device_exact_enums_are_validated(workflow_context, field, value):
    client = workflow_context[0]
    login(client)
    response = client.post("/api/v1/devices", json={"display_name": "x", field: value})
    assert response.status_code == 422


def test_snapshot_creation_defaults_and_tenant_isolation(workflow_context):
    client, _, (_, user_id), _ = workflow_context
    login(client)
    device = create_device(client).json()
    created = create_snapshot(client, device["device_id"])
    assert created.status_code == 201
    body = created.json()
    assert body["status"] == "draft"
    assert body["grouping_status"] == "manually_confirmed"
    assert body["source"] == "upload"
    assert body["created_by"] == str(user_id)
    assert body["artifact_count"] == 0
    assert body["snapshot_hash"] == EMPTY_SNAPSHOT_HASH
    assert body["captured_at"] is None and body["artifacts"] == []
    assert client.patch(f"/api/v1/snapshots/{body['snapshot_id']}", json={
        "label": " September evidence ", "grouping_status": "needs_review"
    }).json()["label"] == "September evidence"
    assert client.patch(f"/api/v1/snapshots/{body['snapshot_id']}", json={
        "status": "ready"
    }).status_code == 422
    assert create_snapshot(client, device["device_id"], grouping_status="automatic").status_code == 422
    client.cookies.clear()
    login(client, "b@example.invalid")
    assert create_snapshot(client, device["device_id"]).status_code == 404
    assert client.get(f"/api/v1/snapshots/{body['snapshot_id']}").status_code == 404
    assert client.get(f"/api/v1/devices/{device['device_id']}/snapshots").status_code == 404


def test_membership_updates_count_hash_and_remove(workflow_context):
    client, factory, *_ = workflow_context
    login(client)
    device_id = create_device(client).json()["device_id"]
    snapshot_id = create_snapshot(client, device_id).json()["snapshot_id"]
    first = upload(client, "a.cfg", b"hostname a\n")
    second = upload(client, "b.cfg", b"hostname b\n")
    added = client.post(f"/api/v1/snapshots/{snapshot_id}/artifacts/{first['artifact_id']}")
    assert added.status_code == 200
    assert added.json()["artifact_count"] == 1
    assert added.json()["snapshot_hash"] == calculate_snapshot_hash([first["sha256"]])
    added = client.post(f"/api/v1/snapshots/{snapshot_id}/artifacts/{second['artifact_id']}")
    assert added.json()["artifact_count"] == 2
    expected = calculate_snapshot_hash([first["sha256"], second["sha256"]])
    assert added.json()["snapshot_hash"] == expected
    assert [item["artifact_id"] for item in added.json()["artifacts"]] == sorted([
        first["artifact_id"], second["artifact_id"]
    ])
    with factory() as db:
        assert db.get(Artifact, UUID(first["artifact_id"])).snapshot_id is not None
    removed = client.delete(f"/api/v1/snapshots/{snapshot_id}/artifacts/{first['artifact_id']}")
    assert removed.status_code == 204
    refreshed = client.get(f"/api/v1/snapshots/{snapshot_id}").json()
    assert refreshed["artifact_count"] == 1
    assert refreshed["snapshot_hash"] == calculate_snapshot_hash([second["sha256"]])


def test_hash_is_independent_of_insertion_order(workflow_context):
    client = workflow_context[0]
    login(client)
    device_id = create_device(client).json()["device_id"]
    first_snapshot = create_snapshot(client, device_id).json()["snapshot_id"]
    second_snapshot = create_snapshot(client, device_id).json()["snapshot_id"]
    evidence = [("a.cfg", b"first"), ("b.cfg", b"second")]
    first_pair = [upload(client, name, data) for name, data in evidence]
    second_pair = [upload(client, f"copy-{name}", data) for name, data in evidence]
    for item in first_pair:
        client.post(f"/api/v1/snapshots/{first_snapshot}/artifacts/{item['artifact_id']}")
    for item in reversed(second_pair):
        client.post(f"/api/v1/snapshots/{second_snapshot}/artifacts/{item['artifact_id']}")
    assert client.get(f"/api/v1/snapshots/{first_snapshot}").json()["snapshot_hash"] == (
        client.get(f"/api/v1/snapshots/{second_snapshot}").json()["snapshot_hash"]
    )


def test_assignment_conflicts_and_tenant_artifacts_are_hidden(workflow_context):
    client = workflow_context[0]
    login(client)
    device_id = create_device(client).json()["device_id"]
    first = create_snapshot(client, device_id).json()["snapshot_id"]
    second = create_snapshot(client, device_id).json()["snapshot_id"]
    artifact = upload(client, "one.cfg", b"hostname one")
    assert client.post(f"/api/v1/snapshots/{first}/artifacts/{artifact['artifact_id']}").status_code == 200
    conflict = client.post(f"/api/v1/snapshots/{second}/artifacts/{artifact['artifact_id']}")
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "artifact_already_assigned"
    client.cookies.clear()
    login(client, "b@example.invalid")
    own_device = create_device(client, "Tenant B").json()["device_id"]
    own_snapshot = create_snapshot(client, own_device).json()["snapshot_id"]
    assert client.post(f"/api/v1/snapshots/{own_snapshot}/artifacts/{artifact['artifact_id']}").status_code == 404
    own_artifact = upload(client, "b.cfg", b"hostname b")
    assert client.post(f"/api/v1/snapshots/{first}/artifacts/{own_artifact['artifact_id']}").status_code == 404


def test_ineligible_artifact_and_empty_finalize_are_rejected(workflow_context):
    client, factory, *_ = workflow_context
    login(client)
    device_id = create_device(client).json()["device_id"]
    snapshot_id = create_snapshot(client, device_id).json()["snapshot_id"]
    empty = client.post(f"/api/v1/snapshots/{snapshot_id}/finalize")
    assert empty.status_code == 422
    artifact = upload(client, "rejected.cfg", b"hostname rejected")
    with factory.begin() as db:
        db.execute(update(Artifact).where(
            Artifact.artifact_id == UUID(artifact["artifact_id"])
        ).values(status="rejected"))
    rejected = client.post(f"/api/v1/snapshots/{snapshot_id}/artifacts/{artifact['artifact_id']}")
    assert rejected.status_code == 422
    assert rejected.json()["detail"]["code"] == "artifact_ineligible"


def test_ready_locked_and_archived_snapshots_are_immutable(workflow_context):
    client, factory, *_ = workflow_context
    login(client)
    device_id = create_device(client).json()["device_id"]
    snapshot_id = create_snapshot(client, device_id).json()["snapshot_id"]
    first = upload(client, "first.cfg", b"hostname first")
    second = upload(client, "second.cfg", b"hostname second")
    client.post(f"/api/v1/snapshots/{snapshot_id}/artifacts/{first['artifact_id']}")
    finalized = client.post(f"/api/v1/snapshots/{snapshot_id}/finalize")
    assert finalized.status_code == 200 and finalized.json()["status"] == "ready"
    for method, path, body in (
        (client.post, f"/api/v1/snapshots/{snapshot_id}/artifacts/{second['artifact_id']}", None),
        (client.delete, f"/api/v1/snapshots/{snapshot_id}/artifacts/{first['artifact_id']}", None),
        (client.patch, f"/api/v1/snapshots/{snapshot_id}", {"label": "changed"}),
    ):
        response = method(path, **({"json": body} if body else {}))
        assert response.status_code == 409
    for state in (SnapshotStatus.LOCKED, SnapshotStatus.ARCHIVED):
        with factory.begin() as db:
            db.execute(update(Snapshot).where(
                Snapshot.snapshot_id == UUID(snapshot_id)
            ).values(status=state))
        assert client.patch(f"/api/v1/snapshots/{snapshot_id}", json={"label": "x"}).status_code == 409
