"""Opt-in PostgreSQL FortiOS production-pipeline verification."""

import os
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text

from app.audit.pipeline import AuditPipelineCoordinator
from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Artifact,
    ArtifactContentFamily,
    ArtifactEvidenceType,
    ArtifactStatus,
    Audit,
    AuditReevaluationReason,
    AuditStatus,
    Device,
    EffectiveState,
    Finding,
    Organization,
    SecurityFact,
    Snapshot,
    SnapshotGroupingStatus,
    SnapshotSource,
    SnapshotStatus,
    UnresolvedBlock,
    User,
)
from app.db.session import create_session_factory
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.knowledge_packs.fortios_7 import FORTIOS_7_KNOWLEDGE_PACK
from app.snapshots.service import calculate_snapshot_hash


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_STEP13_POSTGRES_TEST") != "1",
    reason="Set SIH_STEP13_POSTGRES_TEST=1 with development PostgreSQL settings",
)

FORTIOS_CONFIG = (
    Path(__file__).parents[1] / "fixtures" / "fortios" / "secure.conf"
).read_bytes()
FORTIOS_VERSION = b"FortiOS v7.4.3,build2573\n"


def test_fortios_audit_reaches_terminal_pipeline_state(tmp_path, monkeypatch):
    settings = get_settings()
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    organization_id = None
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260909_0016"
        suffix = uuid4().hex
        organization_id, user_id = bootstrap_admin(
            factory, "FortiOS E2E", f"fortios-e2e-{suffix}",
            f"fortios-e2e-{suffix}@example.invalid", "test-only-password",
        )
        with factory.begin() as db:
            device = Device(organization_id=organization_id, display_name="FortiGate")
            db.add(device)
            db.flush()
            artifacts = []
            hashes = []
            for filename, content, evidence_type in (
                ("fortios.conf", FORTIOS_CONFIG, ArtifactEvidenceType.CONFIGURATION),
                ("version.txt", FORTIOS_VERSION, ArtifactEvidenceType.VERSION_OUTPUT),
            ):
                artifact_id = uuid4()
                reference = storage.write(content, organization_id=organization_id, artifact_id=artifact_id)
                digest = sha256(content).hexdigest()
                hashes.append(digest)
                artifacts.append(Artifact(
                    artifact_id=artifact_id, organization_id=organization_id,
                    original_filename=filename, storage_reference=reference,
                    byte_size=len(content), sha256=digest, encoding="utf-8",
                    content_family=ArtifactContentFamily.TEXT, evidence_type=evidence_type,
                    status=ArtifactStatus.READY, uploaded_by=user_id,
                ))
            snapshot = Snapshot(
                device_id=device.device_id, organization_id=organization_id,
                grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
                snapshot_hash=calculate_snapshot_hash(hashes), artifact_count=len(artifacts),
                source=SnapshotSource.UPLOAD, status=SnapshotStatus.LOCKED, created_by=user_id,
            )
            db.add(snapshot)
            db.flush()
            for artifact in artifacts:
                artifact.snapshot_id = snapshot.snapshot_id
            db.add_all(artifacts)
            audit = Audit(
                organization_id=organization_id, device_id=device.device_id,
                snapshot_id=snapshot.snapshot_id, revision_number=1,
                reevaluation_reason=AuditReevaluationReason.INITIAL, status=AuditStatus.QUEUED,
                selected_frameworks=[], version_refs={}, profile_resolution={},
                verdict_counts={}, severity_counts={}, coverage={}, created_by=user_id,
            )
            db.add(audit)
            db.flush()
            audit_id = audit.audit_id
            snapshot_id = snapshot.snapshot_id
            artifact_ids = {item.artifact_id for item in artifacts}
            original_hash = snapshot.snapshot_hash
            original_artifact_hashes = {item.artifact_id: item.sha256 for item in artifacts}
            if os.environ.get("SIH_B5_ACCEPTANCE_REPORT") == "1":
                config_artifact_id = next(
                    item.artifact_id for item in artifacts
                    if item.evidence_type == ArtifactEvidenceType.CONFIGURATION
                )
                print(
                    "B5_FORTIOS_PERSISTED_IDS "
                    f"artifact={config_artifact_id} snapshot={snapshot_id} audit={audit_id} job=direct-pipeline"
                )

        import app.interpretation.service as interpretation_service
        original_parse = interpretation_service.parse_artifact
        reader_ids = []

        def record_reader(*args, **kwargs):
            ir = original_parse(*args, **kwargs)
            reader_ids.append(ir.reader_id)
            return ir

        monkeypatch.setattr(interpretation_service, "parse_artifact", record_reader)
        result = AuditPipelineCoordinator(factory, storage).run(audit_id, organization_id)
        assert result.profile_resolution.selected_profile_version_id == "fortinet.fortios.7@1.0.0"
        assert reader_ids == ["fortios_cli.v1"]

        with factory() as db:
            persisted = db.get(Audit, audit_id)
            assert persisted.version_refs["knowledge_pack_version_id"] == str(FORTIOS_7_KNOWLEDGE_PACK.knowledge_pack_version_id)
            assert persisted.version_refs["device_profile_version_id"] == "fortinet.fortios.7@1.0.0"
            assert persisted.status == AuditStatus.COMPLETED_WITH_UNKNOWNS
            assert persisted.completed_at is not None
            facts = list(db.scalars(select(SecurityFact).where(SecurityFact.audit_id == audit_id)))
            assert {item.field_id for item in facts} >= {
                "management.remote.ssh.enabled", "management.remote.telnet.enabled",
                "management.session.idle_timeout", "logging.remote.destination", "time.ntp.server",
            }
            assert {item.knowledge_pack_version_id for item in facts} == {FORTIOS_7_KNOWLEDGE_PACK.knowledge_pack_version_id}
            assert all(str(item) in str(artifact_ids) for fact in facts for item in [fact.evidence_refs[0]["artifact_id"]])
            assert db.scalar(select(EffectiveState).where(EffectiveState.audit_id == audit_id)) is not None
            findings = list(db.scalars(select(Finding).where(Finding.audit_id == audit_id)))
            assert len(findings) == 8
            assert {item.rule_pack_version_id for item in findings} == {
                result.findings[0].rule_pack_version_id
            }
            assert all(item.observed_state is None or "Cisco" not in str(item.observed_state) for item in findings)
            assert db.scalar(select(UnresolvedBlock).where(UnresolvedBlock.audit_id == audit_id)) is not None
            unchanged_snapshot = db.get(Snapshot, snapshot_id)
            assert unchanged_snapshot.snapshot_hash == original_hash
            unchanged_artifacts = list(db.scalars(select(Artifact).where(Artifact.artifact_id.in_(artifact_ids))))
            assert {item.artifact_id: item.sha256 for item in unchanged_artifacts} == original_artifact_hashes
            assert storage.read(next(item.storage_reference for item in unchanged_artifacts if item.evidence_type == ArtifactEvidenceType.CONFIGURATION)).startswith(b"#config-version")
            assert b"Cisco IOS" not in FORTIOS_CONFIG
    finally:
        if organization_id is not None:
            with factory.begin() as db:
                audit_ids = select(Audit.audit_id).where(Audit.organization_id == organization_id)
                db.execute(delete(UnresolvedBlock).where(UnresolvedBlock.audit_id.in_(audit_ids)))
                db.execute(delete(Finding).where(Finding.audit_id.in_(audit_ids)))
                db.execute(delete(EffectiveState).where(EffectiveState.audit_id.in_(audit_ids)))
                db.execute(delete(SecurityFact).where(SecurityFact.audit_id.in_(audit_ids)))
                db.execute(delete(Audit).where(Audit.organization_id == organization_id))
                db.execute(delete(Artifact).where(Artifact.organization_id == organization_id))
                db.execute(delete(Snapshot).where(Snapshot.organization_id == organization_id))
                db.execute(delete(Device).where(Device.organization_id == organization_id))
                db.execute(delete(User).where(User.organization_id == organization_id))
                db.execute(delete(Organization).where(Organization.organization_id == organization_id))
        engine.dispose()
