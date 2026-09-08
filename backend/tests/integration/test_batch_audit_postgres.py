"""Opt-in PostgreSQL proof for stateless multi-device audit submission."""

import os
from hashlib import sha256
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, text

from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Artifact, ArtifactContentFamily, ArtifactEvidenceType, ArtifactStatus,
    Audit, AuditStatus, Device, Job, JobType, Organization, Snapshot,
    SnapshotGroupingStatus, SnapshotSource, SnapshotStatus, User,
)
from app.db.session import create_session_factory, get_db
from app.main import create_app
from app.snapshots.service import calculate_snapshot_hash


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_BATCH_AUDIT_POSTGRES_TEST") != "1",
    reason="Set SIH_BATCH_AUDIT_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def test_batch_submission_persists_independent_cisco_and_fortios_audits():
    settings = get_settings().model_copy(update={
        "api_prefix": "/api/v1", "auth_cookie_name": "batch_audit_postgres_test",
        "auth_cookie_secure": False, "auth_cookie_samesite": "lax",
    })
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    organization_id = None
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260909_0014"

        suffix = uuid4().hex
        organization_id, user_id = bootstrap_admin(
            factory, "Batch Audit Integration", f"batch-audit-{suffix}",
            f"batch-audit-{suffix}@example.invalid", "test-password",
        )
        configs = {
            "Cisco edge": b"Cisco IOS XE Software, Version 17.9.4a\nhostname cisco\n",
            "FortiOS edge": b"FortiOS v7.4.3,build2573\nconfig system global\n",
        }
        device_ids, snapshot_ids = [], []
        with factory.begin() as db:
            for name, contents in configs.items():
                digest = sha256(contents).hexdigest()
                device = Device(organization_id=organization_id, display_name=name)
                db.add(device)
                db.flush()
                snapshot = Snapshot(
                    organization_id=organization_id, device_id=device.device_id,
                    grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
                    snapshot_hash=calculate_snapshot_hash([digest]), artifact_count=1,
                    source=SnapshotSource.UPLOAD, status=SnapshotStatus.READY,
                    created_by=user_id,
                )
                db.add(snapshot)
                db.flush()
                artifact = Artifact(
                    organization_id=organization_id, snapshot_id=snapshot.snapshot_id,
                    original_filename=f"{name.lower().replace(' ', '-')}.cfg",
                    storage_reference=f"organizations/{organization_id}/artifacts/{uuid4()}",
                    byte_size=len(contents), sha256=digest,
                    content_family=ArtifactContentFamily.TEXT,
                    evidence_type=ArtifactEvidenceType.CONFIGURATION,
                    status=ArtifactStatus.READY, uploaded_by=user_id,
                )
                db.add(artifact)
                device_ids.append(device.device_id)
                snapshot_ids.append(snapshot.snapshot_id)

        application = create_app(settings)

        def session_dependency():
            with factory() as db:
                yield db

        application.dependency_overrides[get_settings] = lambda: settings
        application.dependency_overrides[get_db] = session_dependency
        with TestClient(application) as client:
            assert client.post("/api/v1/auth/login", json={
                "email": f"batch-audit-{suffix}@example.invalid", "password": "test-password",
            }).status_code == 200
            response = client.post("/api/v1/audits/batch", json={"items": [
                {"device_id": str(device_ids[0]), "snapshot_id": str(snapshot_ids[0]), "selected_frameworks": ["NIST"]},
                {"device_id": str(device_ids[1]), "snapshot_id": str(snapshot_ids[1]), "selected_frameworks": ["NIST"]},
            ]})
            assert response.status_code == 200
            body = response.json()
            assert (body["accepted"], body["rejected"]) == (2, 0)
            assert len({item["audit_id"] for item in body["results"]}) == 2
            assert len({item["job_id"] for item in body["results"]}) == 2

        with factory() as db:
            audits = list(db.scalars(select(Audit).where(Audit.organization_id == organization_id)))
            jobs = list(db.scalars(select(Job).where(Job.device_id.in_(device_ids), Job.job_type == JobType.AUDIT)))
            assert {audit.status for audit in audits} == {AuditStatus.QUEUED}
            assert {audit.snapshot_id for audit in audits} == set(snapshot_ids)
            assert len(jobs) == 2
            assert all(db.get(Snapshot, snapshot_id).status == SnapshotStatus.LOCKED for snapshot_id in snapshot_ids)
            assert db.scalar(select(Artifact.status).where(Artifact.snapshot_id == snapshot_ids[0])) == ArtifactStatus.READY
    finally:
        if organization_id is not None:
            with factory.begin() as db:
                db.execute(delete(Job).where(Job.device_id.in_(select(Device.device_id).where(Device.organization_id == organization_id))))
                db.execute(delete(Audit).where(Audit.organization_id == organization_id))
                db.execute(delete(Artifact).where(Artifact.organization_id == organization_id))
                db.execute(delete(Snapshot).where(Snapshot.organization_id == organization_id))
                db.execute(delete(Device).where(Device.organization_id == organization_id))
                db.execute(delete(User).where(User.organization_id == organization_id))
                db.execute(delete(Organization).where(Organization.organization_id == organization_id))
        engine.dispose()
