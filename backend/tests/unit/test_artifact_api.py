from hashlib import sha256
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text, update

from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.models import Artifact
from app.db.session import get_db
from app.ingestion.storage import LocalFilesystemArtifactStorage, get_artifact_storage
from app.main import create_app


@pytest.fixture
def artifact_context(artifact_factory, auth_settings, tmp_path):
    auth_settings.artifact_max_upload_bytes = 64
    auth_settings.artifact_max_bulk_files = 3
    first = bootstrap_admin(
        artifact_factory, "Artifact Tests", "artifact-tests",
        "first@example.invalid", "test-only-password"
    )
    second = bootstrap_admin(
        artifact_factory, "Other Tenant", "other-tenant",
        "second@example.invalid", "test-only-password"
    )
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    application = create_app(auth_settings)
    application.dependency_overrides[get_settings] = lambda: auth_settings
    application.dependency_overrides[get_artifact_storage] = lambda: storage

    def session_dependency():
        with artifact_factory() as db:
            yield db

    application.dependency_overrides[get_db] = session_dependency
    with TestClient(application) as client:
        yield client, artifact_factory, storage, first, second


def login(client, email="first@example.invalid"):
    response = client.post("/api/v1/auth/login", json={
        "email": email, "password": "test-only-password"
    })
    assert response.status_code == 200


def upload(client, name="router.cfg", data=b"hostname edge\ninterface uplink\n", mime="text/plain"):
    return client.post("/api/v1/artifacts/upload", files={"file": (name, data, mime)})


def test_upload_requires_authentication(artifact_context):
    response = upload(artifact_context[0])
    assert response.status_code == 401


def test_upload_persists_canonical_metadata_bytes_and_duplicates(artifact_context):
    client, factory, storage, (organization_id, user_id), _ = artifact_context
    login(client)
    data = b"hostname edge\ninterface uplink\n"
    first = upload(client, "../../router.cfg", data)
    second = upload(client, "router.cfg", data)
    assert first.status_code == second.status_code == 201
    body = first.json()
    assert body["organization_id"] == str(organization_id)
    assert body["uploaded_by"] == str(user_id)
    assert body["original_filename"] == "router.cfg"
    assert body["byte_size"] == len(data)
    assert body["sha256"] == sha256(data).hexdigest()
    assert body["content_family"] == "text"
    assert body["evidence_type"] == "configuration"
    assert body["status"] == "ready"
    assert body["schema_version"] == "1.0.0"
    assert body["storage_reference"].startswith(f"organizations/{organization_id}/artifacts/")
    assert str(storage.root) not in first.text
    assert storage.read(body["storage_reference"]) == data
    assert first.json()["artifact_id"] != second.json()["artifact_id"]
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Artifact)) == 2


@pytest.mark.parametrize(("name", "data", "mime", "code"), [
    ("empty.cfg", b"", "text/plain", "empty_file"),
    ("large.cfg", b"x" * 65, "text/plain", "file_too_large"),
    ("binary.bin", b"abc\x00def", "application/octet-stream", "unsupported_binary"),
    ("bad.json", b'{"broken":', "application/json", "malformed_json"),
    ("bad.xml", b"<root>", "application/xml", "malformed_xml"),
    ("entity.xml", b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>', "application/xml", "unsafe_xml"),
])
def test_rejected_uploads_are_controlled_and_not_persisted(
    artifact_context, name, data, mime, code
):
    client, factory, *_ = artifact_context
    login(client)
    response = upload(client, name, data, mime)
    assert response.status_code in {413, 422}
    assert response.json()["detail"]["code"] == code
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Artifact)) == 0


@pytest.mark.parametrize(("name", "data", "mime", "family", "evidence"), [
    ("export.json", b'{"interfaces": []}', "application/json", "json", "structured_export"),
    ("export.xml", b"<inventory><item /></inventory>", "application/xml", "xml", "structured_export"),
    ("mystery.txt", b"frobnicate tunnel lunar-mode\n", "text/plain", "text", "unknown_evidence"),
])
def test_supported_content_classification(
    artifact_context, name, data, mime, family, evidence
):
    client = artifact_context[0]
    login(client)
    response = upload(client, name, data, mime)
    assert response.status_code == 201
    assert response.json()["content_family"] == family
    assert response.json()["evidence_type"] == evidence


def test_filename_controls_are_metadata_only(artifact_context):
    client = artifact_context[0]
    login(client)
    response = upload(client, "..\\folder\\evil\x00\n.cfg", b"unknown command\n")
    assert response.status_code == 201
    assert response.json()["original_filename"] == "evil__.cfg"
    assert "evil" not in response.json()["storage_reference"]


def test_bulk_upload_isolates_failures(artifact_context):
    client, factory, storage, *_ = artifact_context
    login(client)
    response = client.post("/api/v1/artifacts/bulk-upload", files=[
        ("files", ("a.cfg", b"hostname a\n", "text/plain")),
        ("files", ("bad.json", b"{bad", "application/json")),
        ("files", ("unknown.txt", b"frobnicate lunar\n", "text/plain")),
    ])
    assert response.status_code == 200
    body = response.json()
    assert (body["total"], body["succeeded"], body["failed"]) == (3, 2, 1)
    assert [item["status"] for item in body["results"]] == ["success", "failed", "success"]
    assert body["results"][1]["filename"] == "bad.json"
    assert body["results"][1]["error"]["code"] == "malformed_json"
    with factory() as db:
        artifacts = list(db.scalars(select(Artifact)))
        assert len(artifacts) == 2
        assert all(storage.exists(item.storage_reference) for item in artifacts)


def test_bulk_count_limit_is_enforced(artifact_context):
    client, factory, *_ = artifact_context
    login(client)
    response = client.post("/api/v1/artifacts/bulk-upload", files=[
        ("files", (f"{index}.cfg", b"hostname x", "text/plain")) for index in range(4)
    ])
    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "too_many_files"
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Artifact)) == 0


def test_artifact_retrieval_is_tenant_isolated(artifact_context):
    client = artifact_context[0]
    login(client)
    created = upload(client).json()
    assert client.get(f"/api/v1/artifacts/{created['artifact_id']}").status_code == 200
    client.cookies.clear()
    login(client, "second@example.invalid")
    response = client.get(f"/api/v1/artifacts/{created['artifact_id']}")
    assert response.status_code == 404
    assert response.json() == {"detail": "Artifact not found"}


def test_artifact_list_is_tenant_scoped_and_filters_assigned(artifact_context):
    client, factory, _, _, _ = artifact_context
    login(client)
    first = upload(client, "first.cfg", b"hostname first").json()
    second = upload(client, "second.cfg", b"hostname second").json()
    with factory.begin() as db:
        snapshot_id = uuid4()
        db.execute(text("INSERT INTO snapshots (snapshot_id) VALUES (:snapshot_id)"), {
            "snapshot_id": snapshot_id.hex
        })
        db.execute(update(Artifact).where(
            Artifact.artifact_id == UUID(first["artifact_id"])
        ).values(snapshot_id=snapshot_id))
    listed = client.get("/api/v1/artifacts")
    assert listed.status_code == 200
    assert {item["artifact_id"] for item in listed.json()} == {
        first["artifact_id"], second["artifact_id"]
    }
    unassigned = client.get("/api/v1/artifacts?unassigned=true")
    assert [item["artifact_id"] for item in unassigned.json()] == [second["artifact_id"]]
    client.cookies.clear()
    login(client, "second@example.invalid")
    assert client.get("/api/v1/artifacts").json() == []
