"""Opt-in PostgreSQL locking checks for the Snapshot workflow."""

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, text
from sqlalchemy.orm import sessionmaker

from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Artifact, ArtifactContentFamily, ArtifactEvidenceType, ArtifactStatus,
    Device, Organization, Snapshot, SnapshotGroupingStatus, SnapshotSource,
    SnapshotStatus, User,
)
from app.db.session import get_db
from app.main import create_app
from app.snapshots.errors import SnapshotConflictError
from app.snapshots.service import EMPTY_SNAPSHOT_HASH, add_artifact, calculate_snapshot_hash


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_WORKFLOW_POSTGRES_TEST") != "1",
    reason="Set SIH_WORKFLOW_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def test_concurrent_artifact_assignment_has_one_atomic_winner():
    engine = create_database_engine(get_settings())
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    suffix = uuid4().hex
    organization_id = user_id = device_id = artifact_id = None
    snapshot_ids = []
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260907_0009"
        organization_id, user_id = bootstrap_admin(
            factory, "Snapshot Concurrency", f"snapshot-race-{suffix}",
            f"snapshot-race-{suffix}@example.invalid", "test-password"
        )
        with factory.begin() as db:
            device = Device(
                organization_id=organization_id, display_name="Race Device"
            )
            db.add(device)
            db.flush()
            device_id = device.device_id
            snapshots = [Snapshot(
                device_id=device_id,
                organization_id=organization_id,
                grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
                snapshot_hash=EMPTY_SNAPSHOT_HASH,
                artifact_count=0,
                source=SnapshotSource.UPLOAD,
                status=SnapshotStatus.DRAFT,
                created_by=user_id,
            ) for _ in range(2)]
            artifact = Artifact(
                organization_id=organization_id,
                original_filename="race.cfg",
                storage_reference=f"organizations/{organization_id}/artifacts/{uuid4()}",
                byte_size=4,
                sha256="a" * 64,
                content_family=ArtifactContentFamily.TEXT,
                evidence_type=ArtifactEvidenceType.CONFIGURATION,
                status=ArtifactStatus.READY,
                uploaded_by=user_id,
            )
            db.add_all([*snapshots, artifact])
            db.flush()
            snapshot_ids = [item.snapshot_id for item in snapshots]
            artifact_id = artifact.artifact_id

        barrier = Barrier(2)

        def assign(snapshot_id):
            with factory() as db:
                user = db.get(User, user_id)
                barrier.wait(timeout=5)
                try:
                    add_artifact(db, user, snapshot_id, artifact_id)
                    return "assigned"
                except SnapshotConflictError:
                    db.rollback()
                    return "conflict"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(assign, snapshot_ids))
        assert sorted(results) == ["assigned", "conflict"]

        with factory() as db:
            artifact = db.get(Artifact, artifact_id)
            snapshots = list(db.scalars(select(Snapshot).where(
                Snapshot.snapshot_id.in_(snapshot_ids)
            )))
            assert artifact.snapshot_id in snapshot_ids
            assert sum(item.artifact_count for item in snapshots) == 1
            winner = next(item for item in snapshots if item.snapshot_id == artifact.snapshot_id)
            loser = next(item for item in snapshots if item.snapshot_id != artifact.snapshot_id)
            assert winner.snapshot_hash == calculate_snapshot_hash([artifact.sha256])
            assert loser.snapshot_hash == EMPTY_SNAPSHOT_HASH
    finally:
        if organization_id is not None:
            with factory.begin() as db:
                db.execute(delete(Artifact).where(Artifact.organization_id == organization_id))
                db.execute(delete(Snapshot).where(Snapshot.organization_id == organization_id))
                db.execute(delete(Device).where(Device.organization_id == organization_id))
                db.execute(delete(User).where(User.organization_id == organization_id))
                db.execute(delete(Organization).where(
                    Organization.organization_id == organization_id
                ))
        engine.dispose()


def test_postgres_device_snapshot_api_is_tenant_isolated():
    settings = get_settings().model_copy(update={
        "api_prefix": "/api/v1", "auth_cookie_name": "workflow_postgres_test",
        "auth_cookie_secure": False, "auth_cookie_samesite": "lax",
    })
    engine = create_database_engine(settings)
    try:
        with engine.connect() as connection:
            outer = connection.begin()
            factory = sessionmaker(
                bind=connection, join_transaction_mode="create_savepoint",
                autoflush=False, autocommit=False,
            )
            try:
                suffix = uuid4().hex
                first_org, _ = bootstrap_admin(
                    factory, "Workflow Tenant A", f"workflow-tenant-a-{suffix}",
                    f"workflow-a-{suffix}@example.invalid", "test-password"
                )
                bootstrap_admin(
                    factory, "Workflow Tenant B", f"workflow-tenant-b-{suffix}",
                    f"workflow-b-{suffix}@example.invalid", "test-password"
                )
                application = create_app(settings)
                application.dependency_overrides[get_settings] = lambda: settings

                def session_dependency():
                    with factory() as db:
                        yield db

                application.dependency_overrides[get_db] = session_dependency
                with TestClient(application) as client:
                    assert client.post("/api/v1/auth/login", json={
                        "email": f"workflow-a-{suffix}@example.invalid",
                        "password": "test-password",
                    }).status_code == 200
                    device = client.post("/api/v1/devices", json={
                        "display_name": "Tenant A Device"
                    })
                    assert device.status_code == 201
                    assert device.json()["organization_id"] == str(first_org)
                    snapshot = client.post(
                        f"/api/v1/devices/{device.json()['device_id']}/snapshots", json={}
                    )
                    assert snapshot.status_code == 201

                    client.cookies.clear()
                    assert client.post("/api/v1/auth/login", json={
                        "email": f"workflow-b-{suffix}@example.invalid",
                        "password": "test-password",
                    }).status_code == 200
                    assert client.get(
                        f"/api/v1/devices/{device.json()['device_id']}"
                    ).status_code == 404
                    assert client.patch(
                        f"/api/v1/devices/{device.json()['device_id']}",
                        json={"display_name": "Hidden"},
                    ).status_code == 404
                    assert client.get(
                        f"/api/v1/snapshots/{snapshot.json()['snapshot_id']}"
                    ).status_code == 404
                    assert client.get(
                        f"/api/v1/devices/{device.json()['device_id']}/snapshots"
                    ).status_code == 404
                    assert client.post(
                        f"/api/v1/devices/{device.json()['device_id']}/snapshots", json={}
                    ).status_code == 404
            finally:
                outer.rollback()
    finally:
        engine.dispose()
