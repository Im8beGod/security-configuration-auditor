"""Opt-in production PostgreSQL proof for immutable Step 12 re-evaluation."""
import os
from copy import deepcopy
from hashlib import sha256
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app.audit.pipeline import AuditPipelineCoordinator
from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (Artifact, ArtifactContentFamily, ArtifactEvidenceType, ArtifactStatus, Audit,
    AuditReevaluationReason, AuditStatus, Device, EffectiveState, Finding, SecurityFact, Snapshot,
    SnapshotGroupingStatus, SnapshotSource, SnapshotStatus, User)
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.jobs.handlers.audit import AuditJobHandler
from app.reevaluation.service import start
from app.snapshots.service import calculate_snapshot_hash
from app.training.service import approve_mapping, create_mapping, execute_validation, publish_mapping, request_validation
from app.training.dsl import MappingDefinition


pytestmark = pytest.mark.skipif(os.environ.get("SIH_STEP12_POSTGRES_TEST") != "1", reason="Set SIH_STEP12_POSTGRES_TEST=1 with development PostgreSQL settings")


def _definition() -> MappingDefinition:
    examples = []
    for family, command, expected in (("positive", "idle-timeout", True), ("alternate_values", "idle-timeout", True), ("negative", "hostname", False), ("wrong_scope", "idle-timeout", False), ("negation", "idle-timeout", True), ("conflict", "idle-timeout", True), ("regression", "login", False)):
        node = {"command": command, "arguments": ["5", "0"], "parent_command": "line" if family != "wrong_scope" else "interface", "scope_type": "vty_range", "negated": family == "negation"}
        examples.append({"family": family, "node": node, "expected_match": expected, "expected_value": 300.0 if expected else None})
    return MappingDefinition.model_validate({"profile_applicability": {"profile_version_ids": ["cisco.ios_xe.17@1.0.0"]}, "structural_match": {"command": "idle-timeout", "parent_command": "line", "scope_type": "vty_range", "arguments": [{"operation": "capture", "name": "minutes", "value_type": "integer"}, {"operation": "capture", "name": "seconds", "value_type": "integer"}]}, "target_field_id": "management.session.idle_timeout", "value_extraction": {"operation": "duration_from_parts", "parts": ["minutes", "seconds"], "output_type": "duration"}, "scope_resolution": {"strategy": "vty_range"}, "negation_behavior": {"operation": "reset_to_default"}, "removal_behavior": {"operation": "remove_value"}, "default_behavior": {"operation": "unknown"}, "examples": examples})


def test_postgres_same_evidence_reevaluation_unknown_to_pass(tmp_path):
    engine = create_database_engine(get_settings()); connection = engine.connect(); outer = connection.begin()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint", autoflush=False, expire_on_commit=False)
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    suffix = uuid4().hex
    try:
        organization_id, user_id = bootstrap_admin(factory, "Step 12", f"step12-{suffix}", f"step12-{suffix}@example.invalid", "test-only-password")
        config = b"line vty 0 4\n idle-timeout 5 0\n"
        version = b"Cisco IOS XE Software, Version 17.9.4a\n"
        with factory.begin() as db:
            device = Device(organization_id=organization_id, display_name="Step 12 router"); db.add(device); db.flush()
            artifacts = []
            for name, kind, content in (("version.txt", ArtifactEvidenceType.VERSION_OUTPUT, version), ("running.cfg", ArtifactEvidenceType.CONFIGURATION, config)):
                artifact_id = uuid4(); ref = storage.write(content, organization_id=organization_id, artifact_id=artifact_id)
                artifacts.append(Artifact(artifact_id=artifact_id, organization_id=organization_id, original_filename=name, storage_reference=ref, byte_size=len(content), sha256=sha256(content).hexdigest(), encoding="utf-8", content_family=ArtifactContentFamily.TEXT, evidence_type=kind, status=ArtifactStatus.READY, uploaded_by=user_id))
            snapshot = Snapshot(organization_id=organization_id, device_id=device.device_id, grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED, snapshot_hash=calculate_snapshot_hash([item.sha256 for item in artifacts]), artifact_count=len(artifacts), source=SnapshotSource.UPLOAD, status=SnapshotStatus.LOCKED, created_by=user_id)
            db.add(snapshot); db.flush()
            for artifact in artifacts: artifact.snapshot_id = snapshot.snapshot_id
            db.add_all(artifacts)
            source = Audit(organization_id=organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id, revision_number=1, reevaluation_reason=AuditReevaluationReason.INITIAL, status=AuditStatus.QUEUED, selected_frameworks=[], version_refs={}, profile_resolution={}, verdict_counts={}, severity_counts={}, coverage={}, created_by=user_id)
            db.add(source); db.flush(); source_id = source.audit_id; artifact_state = [(item.artifact_id, item.sha256) for item in artifacts]
        AuditPipelineCoordinator(factory, storage).run(source_id, organization_id)
        with factory() as db:
            source = db.get(Audit, source_id); assert source.status == AuditStatus.COMPLETED_WITH_UNKNOWNS
            unknown = db.scalar(select(Finding).where(Finding.audit_id == source_id, Finding.rule_id == "management.idle_timeout.maximum")); assert unknown and unknown.verdict.value == "unknown"
            block = next(item for item in db.scalars(select(__import__('app.db.models', fromlist=['UnresolvedBlock']).UnresolvedBlock).where(__import__('app.db.models', fromlist=['UnresolvedBlock']).UnresolvedBlock.audit_id == source_id)) if "idle-timeout" in item.raw_text)
            before = (deepcopy(source.version_refs), deepcopy(source.profile_resolution), deepcopy(source.verdict_counts), deepcopy(source.severity_counts), [(item.fact_id, deepcopy(item.value)) for item in db.scalars(select(SecurityFact).where(SecurityFact.audit_id == source_id))], [(item.effective_state_id, deepcopy(item.effective_value)) for item in db.scalars(select(EffectiveState).where(EffectiveState.audit_id == source_id))], [(item.finding_id, item.verdict.value) for item in db.scalars(select(Finding).where(Finding.audit_id == source_id))])
            admin = db.get(User, user_id); mapping = create_mapping(db, admin, mapping_key="iosxe.idle-timeout", title="Idle timeout", description="Reviewed alternate syntax", definition=_definition(), unresolved_block_id=block.unresolved_block_id); run, _ = request_validation(db, admin, mapping.mapping_version_id)
        with factory.begin() as db: execute_validation(db, run.validation_run_id, mapping.mapping_version_id, organization_id)
        with factory() as db:
            admin = db.get(User, user_id); approve_mapping(db, admin, mapping.mapping_version_id); _, pack = publish_mapping(db, admin, mapping.mapping_version_id); revision, job = start(db, admin, source_id, pack.knowledge_pack_version_id); revision_id = revision.audit_id
        AuditJobHandler(factory, storage)(job.job_id)
        with factory() as db:
            source = db.get(Audit, source_id); revision = db.get(Audit, revision_id)
            assert revision.snapshot_id == source.snapshot_id and revision.previous_audit_id == source_id and revision.revision_number == 2
            assert revision.version_refs["knowledge_pack_version_id"] == str(pack.knowledge_pack_version_id)
            assert revision.status == AuditStatus.COMPLETED_WITH_UNKNOWNS
            passed = db.scalar(select(Finding).where(Finding.audit_id == revision_id, Finding.rule_id == "management.idle_timeout.maximum")); assert passed and passed.verdict.value == "pass"
            assert [(item.artifact_id, item.sha256) for item in db.scalars(select(Artifact).where(Artifact.snapshot_id == source.snapshot_id))] == artifact_state
            assert (source.version_refs, source.profile_resolution, source.verdict_counts, source.severity_counts, [(item.fact_id, item.value) for item in db.scalars(select(SecurityFact).where(SecurityFact.audit_id == source_id))], [(item.effective_state_id, item.effective_value) for item in db.scalars(select(EffectiveState).where(EffectiveState.audit_id == source_id))], [(item.finding_id, item.verdict.value) for item in db.scalars(select(Finding).where(Finding.audit_id == source_id))]) == before
            terminal_completed_at = revision.completed_at
            revision_state = (revision.status, revision.completed_at)
            revision_finding_count = db.scalar(select(func.count()).select_from(Finding).where(Finding.audit_id == revision_id))
            revision_fact_count = db.scalar(select(func.count()).select_from(SecurityFact).where(SecurityFact.audit_id == revision_id))
            revision_state_count = db.scalar(select(func.count()).select_from(EffectiveState).where(EffectiveState.audit_id == revision_id))
        AuditJobHandler(factory, storage)(job.job_id)
        with factory() as db:
            source = db.get(Audit, source_id); revision = db.get(Audit, revision_id)
            assert source.status == AuditStatus.COMPLETED_WITH_UNKNOWNS
            assert (revision.status, revision.completed_at) == revision_state
            assert revision.completed_at == terminal_completed_at
            assert db.scalar(select(func.count()).select_from(Audit).where(Audit.snapshot_id == source.snapshot_id)) == 2
            assert db.scalar(select(func.count()).select_from(Finding).where(Finding.audit_id == revision_id)) == revision_finding_count
            assert db.scalar(select(func.count()).select_from(SecurityFact).where(SecurityFact.audit_id == revision_id)) == revision_fact_count
            assert db.scalar(select(func.count()).select_from(EffectiveState).where(EffectiveState.audit_id == revision_id)) == revision_state_count
    finally:
        outer.rollback(); connection.close(); engine.dispose()
