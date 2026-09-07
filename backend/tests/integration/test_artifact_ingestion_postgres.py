"""Opt-in Artifact API verification against an already-migrated PostgreSQL DB."""

import os
from hashlib import sha256
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.orm import sessionmaker

from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import Artifact
from app.db.session import get_db
from app.ingestion.storage import LocalFilesystemArtifactStorage, get_artifact_storage
from app.main import create_app


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_ARTIFACT_POSTGRES_TEST") != "1",
    reason="Set SIH_ARTIFACT_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def test_postgres_artifact_ingestion_and_tenant_isolation(tmp_path):
    settings = get_settings().model_copy(update={
        "api_prefix": "/api/v1", "auth_cookie_name": "artifact_postgres_test",
        "auth_cookie_secure": False, "auth_cookie_samesite": "lax",
        "artifact_max_upload_bytes": 1024, "artifact_max_bulk_files": 5,
    })
    engine = create_database_engine(settings)
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260907_0009"
            before = connection.scalar(select(func.count()).select_from(Artifact))
            connection.rollback()
            outer = connection.begin()
            factory = sessionmaker(
                bind=connection, join_transaction_mode="create_savepoint",
                autoflush=False, autocommit=False,
            )
            try:
                suffix = uuid4().hex
                first_org, first_user = bootstrap_admin(
                    factory, "Artifact Integration A", f"artifact-a-{suffix}",
                    f"artifact-a-{suffix}@example.invalid", "test-only-password"
                )
                _, second_user = bootstrap_admin(
                    factory, "Artifact Integration B", f"artifact-b-{suffix}",
                    f"artifact-b-{suffix}@example.invalid", "test-only-password"
                )
                application = create_app(settings)
                application.dependency_overrides[get_settings] = lambda: settings
                application.dependency_overrides[get_artifact_storage] = lambda: storage

                def session_dependency():
                    with factory() as db:
                        yield db

                application.dependency_overrides[get_db] = session_dependency
                with TestClient(application) as client:
                    login = client.post("/api/v1/auth/login", json={
                        "email": f"artifact-a-{suffix}@example.invalid",
                        "password": "test-only-password",
                    })
                    assert login.status_code == 200
                    payload = b"hostname postgres-edge\n"
                    first = client.post("/api/v1/artifacts/upload", files={
                        "file": ("edge.cfg", payload, "text/plain")
                    })
                    duplicate = client.post("/api/v1/artifacts/upload", files={
                        "file": ("edge-copy.cfg", payload, "text/plain")
                    })
                    assert first.status_code == duplicate.status_code == 201
                    body = first.json()
                    assert body["organization_id"] == str(first_org)
                    assert body["uploaded_by"] == str(first_user)
                    assert body["sha256"] == sha256(payload).hexdigest()
                    assert storage.read(body["storage_reference"]) == payload
                    assert body["artifact_id"] != duplicate.json()["artifact_id"]

                    mixed = client.post("/api/v1/artifacts/bulk-upload", files=[
                        ("files", ("valid.cfg", b"hostname valid", "text/plain")),
                        ("files", ("bad.json", b"{bad", "application/json")),
                    ])
                    assert mixed.status_code == 200
                    assert mixed.json()["succeeded"] == 1
                    assert mixed.json()["failed"] == 1
                    assert connection.scalar(select(func.count()).select_from(Artifact)) == before + 3

                    client.cookies.clear()
                    token = client.post("/api/v1/auth/login", json={
                        "email": f"artifact-b-{suffix}@example.invalid",
                        "password": "test-only-password",
                    })
                    assert token.status_code == 200
                    assert client.get(f"/api/v1/artifacts/{body['artifact_id']}").status_code == 404
                    assert second_user is not None
            finally:
                outer.rollback()
            assert connection.scalar(select(func.count()).select_from(Artifact)) == before
    finally:
        engine.dispose()
