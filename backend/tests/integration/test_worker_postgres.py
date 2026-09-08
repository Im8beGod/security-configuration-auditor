"""Opt-in worker filtering verification against development PostgreSQL."""

import os
from datetime import timezone
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text

from app.audit.errors import AuditWorkflowError
from app.audit.pipeline import AuditPipelineCoordinator
from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Audit,
    AuditProcessingStage,
    AuditReevaluationReason,
    AuditStatus,
    Device,
    Job,
    JobStatus,
    JobType,
    Organization,
    Snapshot,
    SnapshotGroupingStatus,
    SnapshotSource,
    SnapshotStatus,
    User,
)
from app.db.session import create_session_factory
from app.ingestion.storage import create_artifact_storage
from app.jobs.handlers import AuditJobHandler
from app.jobs.runner import PRODUCTION_HANDLERS, WorkerRuntime
from app.jobs.service import enqueue_job
from app.profile_resolution import ProfileResolutionResult, ResolutionConfidence, ResolutionStatus


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_WORKER_POSTGRES_TEST") != "1",
    reason="Set SIH_WORKER_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def test_production_noop_and_controlled_failure_lifecycle(monkeypatch):
    settings = get_settings()
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    job_ids = []
    organization_id = None
    try:
        with factory.begin() as db:
            noop = enqueue_job(db, JobType.SYSTEM_NOOP, payload={"test_marker": "worker"})
            job_ids.append(noop.job_id)
            noop_id = noop.job_id

        suffix = uuid4().hex
        organization_id, user_id = bootstrap_admin(
            factory,
            "Worker Integration",
            f"worker-{suffix}",
            f"worker-{suffix}@example.invalid",
            "test-password",
        )
        with factory.begin() as db:
            device = Device(organization_id=organization_id, display_name="Worker Device")
            db.add(device)
            db.flush()
            snapshot = Snapshot(
                device_id=device.device_id,
                organization_id=organization_id,
                grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
                snapshot_hash="a" * 64,
                artifact_count=0,
                source=SnapshotSource.UPLOAD,
                status=SnapshotStatus.LOCKED,
                created_by=user_id,
            )
            db.add(snapshot)
            db.flush()
            audit_row = Audit(
                organization_id=organization_id,
                device_id=device.device_id,
                snapshot_id=snapshot.snapshot_id,
                revision_number=1,
                reevaluation_reason=AuditReevaluationReason.INITIAL,
                status=AuditStatus.QUEUED,
                processing_stage=None,
                selected_frameworks=[],
                version_refs={},
                profile_resolution={},
                verdict_counts={},
                severity_counts={},
                coverage={},
                created_by=user_id,
            )
            unrelated_audit = Audit(
                organization_id=organization_id,
                device_id=device.device_id,
                snapshot_id=snapshot.snapshot_id,
                revision_number=2,
                reevaluation_reason=AuditReevaluationReason.MANUAL_REEVALUATION,
                status=AuditStatus.QUEUED,
                processing_stage=None,
                selected_frameworks=[],
                version_refs={},
                profile_resolution={},
                verdict_counts={},
                severity_counts={},
                coverage={},
                created_by=user_id,
            )
            db.add_all([audit_row, unrelated_audit])
            db.flush()
            audit_job = enqueue_job(
                db,
                JobType.AUDIT,
                audit_id=audit_row.audit_id,
                device_id=device.device_id,
            )
            audit_id = audit_row.audit_id
            unrelated_audit_id = unrelated_audit.audit_id
            audit_job_id = audit_job.job_id
            job_ids.append(audit_job_id)

            handlers = dict(PRODUCTION_HANDLERS)
            handlers[JobType.AUDIT] = AuditJobHandler(
                factory, create_artifact_storage(settings)
            )
            runtime = WorkerRuntime(
                factory,
                handlers=handlers,
            poll_interval_seconds=settings.worker_poll_interval_seconds,
        )
        assert runtime.run_iteration() is True
        with factory() as db:
            completed = db.get(Job, noop_id)
            assert completed.status == JobStatus.COMPLETED
            assert completed.progress == 100
            assert completed.attempt_count == 1
            assert completed.started_at.tzinfo == timezone.utc
            assert completed.completed_at.tzinfo == timezone.utc
            audit = db.get(Job, audit_job_id)
            assert audit.status == JobStatus.QUEUED
            assert audit.attempt_count == 0
            assert audit.started_at is None

        resolved_profile = ProfileResolutionResult(
            vendor="Cisco",
            product_family="IOS XE",
            os="IOS XE",
            os_version="17.9.4a",
            model=None,
            serial_number=None,
            device_class=None,
            selected_profile_id="cisco.ios_xe.17",
            selected_profile_version_id="cisco.ios_xe.17@1.0.0",
            confidence=ResolutionConfidence.HIGH,
            resolution_status=ResolutionStatus.RESOLVED,
            supporting_signals=(),
            unresolved_reasons=(),
            conflicts=(),
        )

        monkeypatch.setattr(
            "app.audit.pipeline.resolve_audit_profile",
            lambda *_args, **_kwargs: resolved_profile,
        )

        def failing_load_audit_pack(self, audit_id, organization_id, profile_version_id):
            raise AuditWorkflowError("controlled_failure", "intentional integration verification failure")

        monkeypatch.setattr(AuditPipelineCoordinator, "_load_audit_pack", failing_load_audit_pack)
        assert runtime.run_iteration() is True

        with factory() as db:
            failed_job = db.get(Job, audit_job_id)
            failed_audit = db.get(Audit, audit_id)
            assert failed_job.status == JobStatus.FAILED
            assert failed_job.error_code == "handler_failed"
            assert failed_job.error_message == "Job handler execution failed"
            assert failed_audit.status == AuditStatus.FAILED
            assert failed_audit.processing_stage == AuditProcessingStage.IDENTIFYING
            assert failed_audit.completed_at is not None
            assert db.get(Job, noop_id).status == JobStatus.COMPLETED
            assert db.get(Audit, unrelated_audit_id).status == AuditStatus.QUEUED
            assert db.get(Audit, unrelated_audit_id).processing_stage is None

        with factory.begin() as db:
            failure = enqueue_job(db, JobType.SYSTEM_NOOP)
            failure_id = failure.job_id
            job_ids.append(failure_id)

        def failing_handler(_job_id):
            raise RuntimeError("password=must-not-be-persisted")

        failing_runtime = WorkerRuntime(
            factory,
            handlers={JobType.SYSTEM_NOOP: failing_handler},
            poll_interval_seconds=settings.worker_poll_interval_seconds,
        )
        assert failing_runtime.run_iteration() is True
        with factory() as db:
            failed = db.get(Job, failure_id)
            assert failed.status == JobStatus.FAILED
            assert failed.progress == 0
            assert failed.attempt_count == 1
            assert failed.started_at.tzinfo == timezone.utc
            assert failed.completed_at.tzinfo == timezone.utc
            assert failed.error_code == "handler_failed"
            assert failed.error_message == "Job handler execution failed"
    finally:
        if job_ids:
            with factory.begin() as db:
                db.execute(delete(Job).where(Job.job_id.in_(job_ids)))
                if organization_id is not None:
                    db.execute(delete(Audit).where(Audit.organization_id == organization_id))
                    db.execute(delete(Snapshot).where(Snapshot.organization_id == organization_id))
                    db.execute(delete(Device).where(Device.organization_id == organization_id))
                    db.execute(delete(User).where(User.organization_id == organization_id))
                    db.execute(delete(Organization).where(Organization.organization_id == organization_id))
        with factory() as db:
            assert not db.scalars(select(Job).where(Job.job_id.in_(job_ids))).all()
            assert db.scalar(text("SELECT version_num FROM alembic_version")) == "20260909_0014"
        engine.dispose()
