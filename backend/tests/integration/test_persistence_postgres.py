"""Opt-in PostgreSQL enforcement checks for the frozen persistence skeleton."""

import os
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.db.base import Base
from app.db.engine import create_database_engine
from app.db.models import (
    Artifact,
    ArtifactContentFamily,
    ArtifactEvidenceType,
    Audit,
    Device,
    Organization,
    Snapshot,
    SnapshotGroupingStatus,
    SnapshotSource,
)


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_PERSISTENCE_POSTGRES_TEST") != "1",
    reason="Set SIH_PERSISTENCE_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def application_counts(connection):
    return {
        name: connection.scalar(select(func.count()).select_from(table))
        for name, table in Base.metadata.tables.items()
    }


def test_postgresql_enforces_frozen_domain_constraints():
    engine = create_database_engine(get_settings())
    try:
        with engine.connect() as connection:
            assert connection.scalar(
                text("SELECT version_num FROM alembic_version")
            ) == "20260907_0006"
            before = application_counts(connection)
            connection.rollback()
            outer = connection.begin()
            factory = sessionmaker(
                bind=connection,
                join_transaction_mode="create_savepoint",
                autoflush=False,
                autocommit=False,
            )
            try:
                suffix = uuid4().hex
                with factory.begin() as db:
                    organization = Organization(
                        name="Persistence Verification",
                        slug=f"persistence-{suffix}",
                    )
                    db.add(organization)
                    db.flush()
                    device = Device(
                        organization_id=organization.organization_id,
                        display_name="Verification Device",
                    )
                    db.add(device)
                    db.flush()
                    snapshot = Snapshot(
                        organization_id=organization.organization_id,
                        device=device,
                        grouping_status=SnapshotGroupingStatus.AUTOMATIC,
                        snapshot_hash="a" * 64,
                        source=SnapshotSource.UPLOAD,
                    )
                    artifact = Artifact(
                        organization_id=organization.organization_id,
                        snapshot=snapshot,
                        original_filename="verification.conf",
                        storage_reference=(
                            f"organizations/{organization.organization_id}/"
                            f"artifacts/{uuid4()}"
                        ),
                        byte_size=0,
                        sha256="b" * 64,
                        content_family=ArtifactContentFamily.TEXT,
                        evidence_type=ArtifactEvidenceType.CONFIGURATION,
                    )
                    audit = Audit(
                        organization_id=organization.organization_id,
                        device=device,
                        snapshot=snapshot,
                        revision_number=1,
                        selected_frameworks=[],
                        version_refs={},
                        profile_resolution={},
                        verdict_counts={},
                        severity_counts={},
                        coverage={},
                    )
                    db.add_all([artifact, audit])
                    db.flush()
                    ids = (
                        organization.organization_id,
                        device.device_id,
                        snapshot.snapshot_id,
                        artifact.artifact_id,
                        audit.audit_id,
                    )

                with factory() as db:
                    assert db.get(Organization, ids[0]) is not None
                    assert db.get(Device, ids[1]) is not None
                    assert db.get(Snapshot, ids[2]) is not None
                    assert db.get(Artifact, ids[3]) is not None
                    assert db.get(Audit, ids[4]) is not None

                    rejected_updates = (
                        update(Device)
                        .where(Device.device_id == ids[1])
                        .values(organization_id=uuid4()),
                        text(
                            "UPDATE devices SET device_class = 'unsupported' "
                            "WHERE device_id = :device_id"
                        ).bindparams(device_id=ids[1]),
                        update(Snapshot)
                        .where(Snapshot.snapshot_id == ids[2])
                        .values(artifact_count=-1),
                        update(Artifact)
                        .where(Artifact.artifact_id == ids[3])
                        .values(byte_size=-1),
                        update(Artifact)
                        .where(Artifact.artifact_id == ids[3])
                        .values(validation_issues={}),
                        update(Audit)
                        .where(Audit.audit_id == ids[4])
                        .values(revision_number=0),
                    )
                    for statement in rejected_updates:
                        with pytest.raises(IntegrityError), db.begin_nested():
                            db.execute(statement)

                    duplicate = Audit(
                        organization_id=ids[0],
                        device_id=ids[1],
                        snapshot_id=ids[2],
                        revision_number=1,
                        selected_frameworks=[],
                        version_refs={},
                        profile_resolution={},
                        verdict_counts={},
                        severity_counts={},
                        coverage={},
                    )
                    with pytest.raises(IntegrityError), db.begin_nested():
                        db.add(duplicate)
                        db.flush()
            finally:
                outer.rollback()

        with engine.connect() as connection:
            assert application_counts(connection) == before
            assert connection.scalar(
                text("SELECT version_num FROM alembic_version")
            ) == "20260907_0006"
    finally:
        engine.dispose()
