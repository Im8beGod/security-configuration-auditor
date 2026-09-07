"""Opt-in worker filtering verification against development PostgreSQL."""

import os
from datetime import timezone

import pytest
from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import Job, JobStatus, JobType
from app.db.session import create_session_factory
from app.jobs.runner import PRODUCTION_HANDLERS, WorkerRuntime
from app.jobs.service import enqueue_job


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_WORKER_POSTGRES_TEST") != "1",
    reason="Set SIH_WORKER_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def test_production_noop_and_controlled_failure_lifecycle():
    settings = get_settings()
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    job_ids = []
    try:
        with factory.begin() as db:
            audit = enqueue_job(db, JobType.AUDIT, payload={"test_marker": "worker"})
            noop = enqueue_job(db, JobType.SYSTEM_NOOP, payload={"test_marker": "worker"})
            job_ids.extend([audit.job_id, noop.job_id])
            audit_id, noop_id = audit.job_id, noop.job_id

        runtime = WorkerRuntime(
            factory,
            handlers=PRODUCTION_HANDLERS,
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
            audit = db.get(Job, audit_id)
            assert audit.status == JobStatus.QUEUED
            assert audit.attempt_count == 0
            assert audit.started_at is None

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
        with factory() as db:
            assert not db.scalars(select(Job).where(Job.job_id.in_(job_ids))).all()
            assert db.scalar(text("SELECT version_num FROM alembic_version")) == "20260907_0009"
        engine.dispose()
