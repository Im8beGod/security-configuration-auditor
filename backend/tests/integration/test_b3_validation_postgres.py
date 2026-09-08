import os
from hashlib import sha256
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app.cli.bootstrap_admin import bootstrap_admin
from app.db.engine import create_database_engine
from app.db.models import (
    Artifact, ArtifactContentFamily, ArtifactEvidenceType, ArtifactStatus, Device,
    EffectiveState, MappingStatus, SecurityFact, Snapshot, SnapshotGroupingStatus,
    SnapshotSource, SnapshotStatus, User,
)
from app.core.config import get_settings
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.training.dsl import MappingDefinition
from app.training.service import approve_mapping, create_mapping, execute_validation, publish_mapping, request_validation


pytestmark = pytest.mark.skipif(os.environ.get("SIH_TRAINING_POSTGRES_TEST") != "1", reason="Set SIH_TRAINING_POSTGRES_TEST=1 with development PostgreSQL settings")


def _ssh_definition() -> MappingDefinition:
    return MappingDefinition.model_validate({
        "profile_applicability": {"profile_version_ids": ["juniper.junos.18@1.0.0"]},
        "structural_match": {"operation": "xml_path", "command": "xml", "xml_path": {"path": [{"local_name": item, "occurrence": "exact"} for item in ["rpc-reply", "configuration", "system", "services", "ssh"]], "source": "presence", "capture": None, "value_type": "boolean", "start_mode": "document_root"}},
        "target_field_id": "management.remote.ssh.enabled",
        "value_extraction": {"operation": "boolean_from_presence", "capture": None, "output_type": "boolean"},
        "unit_conversion": {"operation": "none"}, "scope_resolution": {"strategy": "device"},
        "negation_behavior": {"operation": "unsupported"}, "removal_behavior": {"operation": "unsupported"}, "default_behavior": {"operation": "unknown"}, "examples": [],
    })


def test_junos_mapping_validation_is_executable_and_publishes_without_audit_persistence(tmp_path, monkeypatch):
    engine = create_database_engine(get_settings())
    connection = engine.connect(); outer = connection.begin()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False)
    try:
        organization_id, admin_id = bootstrap_admin(factory, "B3 validation", f"b3-{uuid4().hex}", f"b3-{uuid4().hex}@example.invalid", "b3-password")
        with factory() as db:
            admin = db.get(User, admin_id)
            device = Device(organization_id=organization_id, display_name="Juniper validation device")
            db.add(device); db.flush()
            snapshot = Snapshot(organization_id=organization_id, device_id=device.device_id, label="B3 development evidence", grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED, snapshot_hash=sha256(uuid4().bytes).hexdigest(), artifact_count=1, source=SnapshotSource.UPLOAD, status=SnapshotStatus.READY, created_by=admin_id)
            db.add(snapshot); db.flush()
            content = b"<rpc-reply><configuration><system><services><ssh/></services></system></configuration></rpc-reply>"
            storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
            artifact_id = uuid4()
            reference = storage.write(content, organization_id=organization_id, artifact_id=artifact_id)
            artifact = Artifact(artifact_id=artifact_id, organization_id=organization_id, snapshot_id=snapshot.snapshot_id, original_filename="b3-development.xml", storage_reference=reference, byte_size=len(content), sha256=sha256(content).hexdigest(), encoding="utf-8", content_family=ArtifactContentFamily.XML, evidence_type=ArtifactEvidenceType.STRUCTURED_EXPORT, status=ArtifactStatus.READY)
            db.add(artifact); db.flush()
            fact_count = db.scalar(select(func.count()).select_from(SecurityFact))
            state_count = db.scalar(select(func.count()).select_from(EffectiveState))
            mapping = create_mapping(db, admin, mapping_key="juniper.ssh", title="Juniper SSH", description="Validated development mapping", definition=_ssh_definition())
            mapping_id = mapping.mapping_version_id
        with factory() as db:
            admin = db.get(User, admin_id)
            run, _job = request_validation(db, admin, mapping_id, evidence_artifact_id=artifact_id)
            run_id = run.validation_run_id
        monkeypatch.setattr("app.ingestion.storage.get_artifact_storage", lambda: storage)
        with factory() as db:
            result = execute_validation(db, run_id, mapping_id, organization_id)
            assert result.status.value == "passed", result.results
            assert result.results["semantic"]["status"] == "matched"
            assert result.results["semantic"]["facts"][0]["field_id"] == "management.remote.ssh.enabled"
            assert result.results["semantic"]["facts"][0]["value"]["value"] is True
            assert result.results["semantic"]["effective_states"][0]["resolution_status"] == "resolved"
            assert db.scalar(select(func.count()).select_from(SecurityFact)) == fact_count
            assert db.scalar(select(func.count()).select_from(EffectiveState)) == state_count
            db.commit()
        with factory() as db:
            admin = db.get(User, admin_id)
            approved = approve_mapping(db, admin, mapping_id)
            assert approved.status == MappingStatus.APPROVED
            published, pack = publish_mapping(db, admin, mapping_id)
            assert published.status == MappingStatus.PUBLISHED
            assert str(mapping_id) in pack.mapping_version_ids
    finally:
        outer.rollback(); connection.close(); engine.dispose()
