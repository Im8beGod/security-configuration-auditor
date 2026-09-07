"""Opt-in PostgreSQL concurrency and retry safety proof for Step 12."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from hashlib import sha256
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.orm import sessionmaker

from app.audit.errors import AuditWorkflowError
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
    Finding,
    Job,
    JobType,
    KnowledgePackRecord,
    KnowledgePackVersionRecord,
    MappingOrigin,
    MappingStatus,
    MappingVersion,
    Organization,
    SecurityFact,
    EffectiveState,
    Snapshot,
    SnapshotGroupingStatus,
    SnapshotSource,
    SnapshotStatus,
    User,
)
from app.db.models.common import utc_now
from app.jobs.errors import JobError
from app.reevaluation.service import start
from app.snapshots.service import calculate_snapshot_hash


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_STEP12_POSTGRES_TEST") != "1",
    reason="Set SIH_STEP12_POSTGRES_TEST=1 with development PostgreSQL settings",
)


PROFILE_VERSION_ID = "cisco.ios_xe.17@1.0.0"
FIELD_ID = "management.session.idle_timeout"


def _mapping_definition() -> dict:
    return {
        "profile_applicability": {"profile_version_ids": [PROFILE_VERSION_ID]},
        "structural_match": {
            "command": "exec-timeout",
            "arguments": [],
            "parent_command": "line",
            "scope_type": "vty_range",
        },
        "target_field_id": FIELD_ID,
        "value_extraction": {
            "operation": "duration_from_parts",
            "parts": ["minutes", "seconds"],
            "output_type": "duration",
        },
        "unit_conversion": {"operation": "none"},
        "scope_resolution": {"strategy": "vty_range"},
        "negation_behavior": {"operation": "reset_to_default"},
        "removal_behavior": {"operation": "remove_value"},
        "default_behavior": {"operation": "unknown"},
        "examples": [],
    }


def _seed(factory):
    suffix = uuid4().hex
    organization_id, user_id = bootstrap_admin(
        factory,
        "Step 12 concurrency",
        f"concurrency-{suffix}",
        f"concurrency-{suffix}@example.invalid",
        "test-only-password",
    )
    with factory.begin() as db:
        device = Device(organization_id=organization_id, display_name="Concurrency router")
        db.add(device)
        db.flush()
        content = b"immutable evidence\n"
        artifact = Artifact(
            artifact_id=uuid4(), organization_id=organization_id, snapshot_id=None,
            original_filename="running.cfg", storage_reference=f"test://{suffix}",
            byte_size=len(content), sha256=sha256(content).hexdigest(), encoding="utf-8",
            content_family=ArtifactContentFamily.TEXT, evidence_type=ArtifactEvidenceType.CONFIGURATION,
            status=ArtifactStatus.READY, uploaded_by=user_id,
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
        old_pack = KnowledgePackRecord(
            organization_id=organization_id, pack_key=f"old-{suffix}", name="Old pack"
        )
        target_pack = KnowledgePackRecord(
            organization_id=organization_id, pack_key=f"target-{suffix}", name="Target pack"
        )
        db.add_all((old_pack, target_pack))
        db.flush()
        old_version = KnowledgePackVersionRecord(
            knowledge_pack_id=old_pack.knowledge_pack_id, organization_id=organization_id,
            version=1, mapping_version_ids=[], published_by=user_id,
        )
        target_version_id = uuid4()
        mapping_version_id = uuid4()
        target_version = KnowledgePackVersionRecord(
            knowledge_pack_version_id=target_version_id,
            knowledge_pack_id=target_pack.knowledge_pack_id, organization_id=organization_id,
            version=1, mapping_version_ids=[str(mapping_version_id)], published_by=user_id,
        )
        db.add_all((old_version, target_version))
        db.flush()
        definition = _mapping_definition()
        mapping = MappingVersion(
            mapping_version_id=mapping_version_id,
            mapping_id=uuid4(), organization_id=organization_id, mapping_key=f"mapping-{suffix}",
            version=1, title="Target mapping", description="Concurrency test mapping",
            status=MappingStatus.PUBLISHED, profile_applicability=definition["profile_applicability"],
            structural_match=definition["structural_match"], target_field_id=FIELD_ID,
            value_extraction=definition["value_extraction"], unit_conversion=definition["unit_conversion"],
            scope_resolution=definition["scope_resolution"], negation_behavior=definition["negation_behavior"],
            removal_behavior=definition["removal_behavior"], default_behavior=definition["default_behavior"],
            examples=[], validation_results={}, origin=MappingOrigin.ADMINISTRATOR,
            created_by=user_id, knowledge_pack_version_id=target_version.knowledge_pack_version_id,
        )
        db.add(mapping)
        db.flush()
        source = Audit(
            organization_id=organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id,
            revision_number=1, reevaluation_reason=AuditReevaluationReason.INITIAL,
            status=AuditStatus.COMPLETED, selected_frameworks=[],
            version_refs={
                "device_profile_version_id": PROFILE_VERSION_ID,
                "knowledge_pack_version_id": str(old_version.knowledge_pack_version_id),
            },
            profile_resolution={"profile_version_id": PROFILE_VERSION_ID, "resolution_status": "resolved"},
            verdict_counts={"pass": 1}, severity_counts={}, coverage={}, created_by=user_id,
            completed_at=utc_now(),
        )
        db.add(source)
        db.flush()
        return {
            "organization_id": organization_id,
            "user_id": user_id,
            "source_id": source.audit_id,
            "target_pack_id": target_version.knowledge_pack_version_id,
            "snapshot_id": snapshot.snapshot_id,
            "artifact_id": artifact.artifact_id,
        }


def _cleanup(engine, organization_id):
    with engine.begin() as db:
        audit_ids = select(Audit.audit_id).where(Audit.organization_id == organization_id)
        snapshot_ids = select(Snapshot.snapshot_id).where(Snapshot.organization_id == organization_id)
        db.execute(delete(EffectiveState).where(EffectiveState.audit_id.in_(audit_ids)))
        db.execute(delete(SecurityFact).where(SecurityFact.audit_id.in_(audit_ids)))
        db.execute(delete(Finding).where(Finding.audit_id.in_(audit_ids)))
        db.execute(delete(Job).where(Job.audit_id.in_(audit_ids)))
        db.execute(delete(Audit).where(Audit.organization_id == organization_id))
        db.execute(delete(Artifact).where(Artifact.snapshot_id.in_(snapshot_ids)))
        db.execute(delete(Snapshot).where(Snapshot.organization_id == organization_id))
        db.execute(delete(Device).where(Device.organization_id == organization_id))


@pytest.fixture
def postgres_context():
    engine = create_database_engine(get_settings())
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    context = _seed(factory)
    try:
        yield engine, factory, context
    finally:
        _cleanup(engine, context["organization_id"])
        engine.dispose()


def _start_once(factory, context):
    with factory() as db:
        user = db.get(User, context["user_id"])
        try:
            revision, job = start(db, user, context["source_id"], context["target_pack_id"])
            return ("ok", revision.audit_id, job.job_id)
        except Exception as exc:  # Both the idempotent and conflict contracts are valid.
            return (type(exc).__name__, getattr(exc, "code", None), str(exc))


def test_concurrent_initiation_cannot_create_duplicate_revision(postgres_context):
    _engine, factory, context = postgres_context
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _item: _start_once(factory, context), (1, 2)))
    with factory() as db:
        revisions = list(db.scalars(select(Audit).where(Audit.snapshot_id == context["snapshot_id"]).order_by(Audit.revision_number)))
        jobs = list(db.scalars(select(Job).where(Job.audit_id.in_([item.audit_id for item in revisions]), Job.job_type == JobType.RE_EVALUATION)))
        assert [item.revision_number for item in revisions] == [1, 2]
        assert revisions[1].previous_audit_id == context["source_id"]
        assert len(jobs) == 1
        assert sum(result[0] == "ok" for result in results) >= 1


def test_revision_number_allocation_remains_coherent(postgres_context):
    _engine, factory, context = postgres_context
    with factory.begin() as db:
        source = db.get(Audit, context["source_id"])
        prior = Audit(
            organization_id=source.organization_id, device_id=source.device_id, snapshot_id=source.snapshot_id,
            revision_number=2, previous_audit_id=source.audit_id,
            reevaluation_reason=AuditReevaluationReason.KNOWLEDGE_PACK_UPDATE,
            status=AuditStatus.COMPLETED, selected_frameworks=[], version_refs=dict(source.version_refs),
            profile_resolution=dict(source.profile_resolution), verdict_counts={}, severity_counts={}, coverage={},
            created_by=source.created_by, completed_at=utc_now(),
        )
        db.add(prior)
    with factory() as db:
        revision, _job = start(db, db.get(User, context["user_id"]), prior.audit_id, context["target_pack_id"])
        assert revision.revision_number == 3
        assert revision.previous_audit_id == prior.audit_id
        assert db.scalar(select(func.count()).select_from(Audit).where(Audit.snapshot_id == context["snapshot_id"], Audit.revision_number == 3)) == 1


def test_repeated_initiation_is_idempotent_safe_and_does_not_duplicate_job(postgres_context):
    _engine, factory, context = postgres_context
    first = _start_once(factory, context)
    second = _start_once(factory, context)
    with factory() as db:
        revisions = list(db.scalars(select(Audit).where(Audit.snapshot_id == context["snapshot_id"])))
        jobs = list(db.scalars(select(Job).where(Job.job_type == JobType.RE_EVALUATION, Job.audit_id.in_([item.audit_id for item in revisions]))))
        assert len(revisions) == 2
        assert len(jobs) == 1
        assert first[0] == "ok"
        assert second[0] in {"ok", "AuditConflictError"}


def test_failed_new_revision_does_not_mutate_source_or_evidence(postgres_context):
    _engine, factory, context = postgres_context
    source_before = None
    evidence_before = None
    with factory() as db:
        source = db.get(Audit, context["source_id"])
        snapshot = db.get(Snapshot, context["snapshot_id"])
        artifact = db.get(Artifact, context["artifact_id"])
        source_before = (
            source.status, deepcopy(source.version_refs), deepcopy(source.profile_resolution),
            deepcopy(source.verdict_counts), deepcopy(source.severity_counts), source.completed_at,
        )
        evidence_before = (snapshot.snapshot_id, snapshot.status, snapshot.snapshot_hash, snapshot.artifact_count, artifact.artifact_id, artifact.sha256, artifact.storage_reference)
        _revision, job = start(db, db.get(User, context["user_id"]), context["source_id"], context["target_pack_id"])
    with patch("app.jobs.handlers.audit.AuditPipelineCoordinator.run", side_effect=AuditWorkflowError("controlled_failure", "controlled test failure")):
        from app.jobs.handlers.audit import AuditJobHandler
        with pytest.raises(JobError):
            AuditJobHandler(factory, object())(job.job_id)
    with factory() as db:
        source = db.get(Audit, context["source_id"])
        snapshot = db.get(Snapshot, context["snapshot_id"])
        artifact = db.get(Artifact, context["artifact_id"])
        assert (source.status, source.version_refs, source.profile_resolution, source.verdict_counts, source.severity_counts, source.completed_at) == source_before
        assert (snapshot.snapshot_id, snapshot.status, snapshot.snapshot_hash, snapshot.artifact_count, artifact.artifact_id, artifact.sha256, artifact.storage_reference) == evidence_before
