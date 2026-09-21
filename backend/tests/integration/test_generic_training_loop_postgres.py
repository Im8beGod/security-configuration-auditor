"""Opt-in PostgreSQL proof for the generic CLI training and re-evaluation loop."""

import os
from hashlib import sha256
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.audit.pipeline import AuditPipelineCoordinator
from app.cli.bootstrap_admin import bootstrap_admin
from app.compliance.verdicts import FindingVerdict
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Artifact, ArtifactContentFamily, ArtifactEvidenceType, ArtifactStatus,
    Audit, AuditReevaluationReason, AuditStatus, Device, Finding,
    SecurityFact, Snapshot, SnapshotGroupingStatus,
    SnapshotSource, SnapshotStatus, UnresolvedBlock, User,
)
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.interpretation.service import load_active_published_knowledge_pack
from app.reevaluation.service import start as start_reevaluation
from app.snapshots.service import calculate_snapshot_hash
from app.training.dsl import MappingDefinition
from app.training.service import (
    approve_mapping, create_mapping, execute_validation, list_unresolved,
    publish_mapping, request_validation,
)


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_PHASE3_POSTGRES_TEST") != "1",
    reason="Set SIH_PHASE3_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def _definition() -> MappingDefinition:
    examples = []
    for family, command, scope, expected in (
        ("positive", "nebula-ssh", "device", True),
        ("alternate_values", "nebula-ssh", "device", True),
        ("negative", "hostname", "device", False),
        ("wrong_scope", "nebula-ssh", "interface", False),
        ("negation", "nebula-ssh", "device", True),
        ("conflict", "nebula-ssh", "device", True),
        ("regression", "login", "device", False),
    ):
        examples.append({
            "family": family,
            "node": {"command": command, "arguments": ["enable"], "scope_type": scope, "negated": family == "negation"},
            "expected_match": expected,
            "expected_value": True if expected else None,
        })
    return MappingDefinition.model_validate({
        "profile_applicability": {"profile_version_ids": ["generic.cli@1.0.0"]},
        "structural_match": {
            "command": "nebula-ssh", "scope_type": "device",
            "arguments": [{"operation": "literal", "value": "enable"}],
        },
        "target_field_id": "management.remote.ssh.enabled",
        "value_extraction": {"operation": "constant", "value": True, "output_type": "boolean"},
        "scope_resolution": {"strategy": "device"},
        "negation_behavior": {"operation": "emit_value"},
        "removal_behavior": {"operation": "remove_value"},
        "default_behavior": {"operation": "unknown"},
        "examples": examples,
    })


def test_unknown_upload_publish_and_reevaluate_without_redeployment(tmp_path, monkeypatch):
    engine = create_database_engine(get_settings())
    connection = engine.connect()
    outer = connection.begin()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint", autoflush=False, expire_on_commit=False)
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    monkeypatch.setattr("app.ingestion.storage.get_artifact_storage", lambda: storage)
    suffix = uuid4().hex
    try:
        organization_id, user_id = bootstrap_admin(factory, "P3", f"p3-{suffix}", f"p3-{suffix}@example.invalid", "test-only-password")
        other_organization_id, other_user_id = bootstrap_admin(factory, "P3 Other", f"p3-other-{suffix}", f"p3-other-{suffix}@example.invalid", "test-only-password")
        content = b"nebula-ssh enable\n"
        with factory.begin() as db:
            device = Device(organization_id=organization_id, display_name="Unknown CLI")
            db.add(device)
            db.flush()
            artifact_id = uuid4()
            artifact = Artifact(
                artifact_id=artifact_id, organization_id=organization_id,
                original_filename="unknown.cfg",
                storage_reference=storage.write(content, organization_id=organization_id, artifact_id=artifact_id),
                byte_size=len(content), sha256=sha256(content).hexdigest(), encoding="utf-8",
                content_family=ArtifactContentFamily.TEXT,
                evidence_type=ArtifactEvidenceType.CONFIGURATION,
                status=ArtifactStatus.READY, uploaded_by=user_id,
                source_metadata={"vendor_label": "Nebula Networks", "os_label": "StarOS"},
            )
            snapshot = Snapshot(
                organization_id=organization_id, device_id=device.device_id,
                grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
                snapshot_hash=calculate_snapshot_hash([artifact.sha256]), artifact_count=1,
                source=SnapshotSource.UPLOAD, status=SnapshotStatus.LOCKED, created_by=user_id,
            )
            db.add(snapshot)
            db.flush()
            artifact.snapshot_id = snapshot.snapshot_id
            db.add(artifact)
            audit = Audit(
                organization_id=organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id,
                revision_number=1, reevaluation_reason=AuditReevaluationReason.INITIAL,
                status=AuditStatus.QUEUED, selected_frameworks=[], version_refs={},
                profile_resolution={}, verdict_counts={}, severity_counts={}, coverage={}, created_by=user_id,
            )
            db.add(audit)
            db.flush()
            audit_id, device_id = audit.audit_id, device.device_id

        AuditPipelineCoordinator(factory, storage).run(audit_id, organization_id)
        with factory() as db:
            source = db.get(Audit, audit_id)
            assert source.profile_resolution["profile_version_id"] == "generic.cli@1.0.0"
            assert source.profile_resolution["metadata"]["administrator_labels"] == {"vendor": "Nebula Networks", "os": "StarOS"}
            findings = list(db.scalars(select(Finding).where(Finding.audit_id == audit_id)))
            assert findings and {item.verdict for item in findings} == {FindingVerdict.UNKNOWN}
            block = db.scalar(select(UnresolvedBlock).where(UnresolvedBlock.audit_id == audit_id))
            assert block.raw_text == "nebula-ssh enable"
            assert block.unknown_reason and block.evidence_refs
            assert block.evidence_refs[0]["artifact_id"] == str(artifact_id)
            admin = db.get(User, user_id)
            mapping = create_mapping(
                db, admin, mapping_key="generic.nebula-ssh", title="Nebula SSH",
                description="Administrator-approved SSH mapping", definition=_definition(),
                unresolved_block_id=block.unresolved_block_id,
            )
            validation, _job = request_validation(db, admin, mapping.mapping_version_id, evidence_artifact_id=artifact_id)
            mapping_version_id = mapping.mapping_version_id
            validation_run_id = validation.validation_run_id

        with factory.begin() as db:
            run = execute_validation(db, validation_run_id, mapping_version_id, organization_id)
            assert run.results["semantic"]["status"] == "matched"
        with factory() as db:
            admin = db.get(User, user_id)
            approve_mapping(db, admin, mapping_version_id)
            _mapping, pack = publish_mapping(db, admin, mapping_version_id)
            pack_id = pack.knowledge_pack_version_id
        future_content = b"nebula-ssh enable\r\n"
        with factory.begin() as db:
            future_artifact_id = uuid4()
            future_artifact = Artifact(
                artifact_id=future_artifact_id, organization_id=organization_id,
                original_filename="future-unknown.cfg",
                storage_reference=storage.write(
                    future_content, organization_id=organization_id,
                    artifact_id=future_artifact_id,
                ),
                byte_size=len(future_content), sha256=sha256(future_content).hexdigest(),
                encoding="utf-8", content_family=ArtifactContentFamily.TEXT,
                evidence_type=ArtifactEvidenceType.CONFIGURATION,
                status=ArtifactStatus.READY, uploaded_by=user_id,
                source_metadata={"vendor_label": "Nebula Networks", "os_label": "StarOS"},
            )
            future_snapshot = Snapshot(
                organization_id=organization_id, device_id=device_id,
                grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
                snapshot_hash=calculate_snapshot_hash([future_artifact.sha256]), artifact_count=1,
                source=SnapshotSource.UPLOAD, status=SnapshotStatus.LOCKED, created_by=user_id,
            )
            db.add(future_snapshot); db.flush()
            future_artifact.snapshot_id = future_snapshot.snapshot_id
            db.add(future_artifact)
            future_audit = Audit(
                organization_id=organization_id, device_id=device_id,
                snapshot_id=future_snapshot.snapshot_id, revision_number=3,
                reevaluation_reason=AuditReevaluationReason.INITIAL,
                status=AuditStatus.QUEUED, selected_frameworks=[], version_refs={},
                profile_resolution={}, verdict_counts={}, severity_counts={}, coverage={},
                created_by=user_id,
            )
            db.add(future_audit); db.flush()
            future_audit_id = future_audit.audit_id

        # Reconstruct the session/coordinator boundary to model a backend/worker restart.
        restarted_factory = sessionmaker(
            bind=connection, join_transaction_mode="create_savepoint",
            autoflush=False, expire_on_commit=False,
        )
        AuditPipelineCoordinator(restarted_factory, storage).run(future_audit_id, organization_id)
        with restarted_factory() as db:
            future = db.get(Audit, future_audit_id)
            assert future.version_refs["knowledge_pack_version_id"] == str(pack_id)
            ssh = db.scalar(select(Finding).where(
                Finding.audit_id == future_audit_id,
                Finding.rule_id == "management.ssh.enabled",
            ))
            assert ssh.verdict is FindingVerdict.PASS
            assert ssh.evidence_refs[0]["artifact_id"] == str(future_artifact_id)
        with factory() as db:
            other = db.get(User, other_user_id)
            assert list_unresolved(db, other) == []
            assert load_active_published_knowledge_pack(db, other_organization_id, "generic.cli@1.0.0") is None
            admin = db.get(User, user_id)
            revision, _job = start_reevaluation(db, admin, audit_id, pack_id)
            revision_id = revision.audit_id

        AuditPipelineCoordinator(factory, storage).run(revision_id, organization_id)
        with factory() as db:
            revision = db.get(Audit, revision_id)
            assert revision.previous_audit_id == audit_id
            assert revision.version_refs["knowledge_pack_version_id"] == str(pack_id)
            ssh = db.scalar(select(Finding).where(Finding.audit_id == revision_id, Finding.rule_id == "management.ssh.enabled"))
            assert ssh.verdict is FindingVerdict.PASS
            assert ssh.evidence_refs[0]["artifact_id"] == str(artifact_id)
            assert db.scalar(select(SecurityFact).where(SecurityFact.audit_id == revision_id)).mapping_version_id == mapping_version_id
            assert db.scalar(select(UnresolvedBlock).where(UnresolvedBlock.audit_id == revision_id)) is None
    finally:
        outer.rollback()
        connection.close()
        engine.dispose()
