"""Opt-in durable-queue verification against migrated development PostgreSQL."""

import os
from datetime import timezone

import pytest
from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import Job, JobStatus, JobType
from app.db.session import create_session_factory
from app.jobs.service import claim_next_job, complete_job, enqueue_job, fail_job


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_JOBS_POSTGRES_TEST") != "1",
    reason="Set SIH_JOBS_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def test_postgresql_skip_locked_and_lifecycle():
    engine = create_database_engine(get_settings())
    factory = create_session_factory(engine)
    job_ids = []
    session_a = session_b = None
    try:
        with factory.begin() as db:
            for ordinal in range(4):
                job = enqueue_job(
                    db, JobType.SYSTEM_NOOP, payload={"verification_ordinal": ordinal}
                )
                job_ids.append(job.job_id)

        session_a, session_b = factory(), factory()
        session_a.begin()
        first = claim_next_job(session_a, {JobType.SYSTEM_NOOP})
        assert first is not None

        session_b.begin()
        session_b.execute(text("SET LOCAL lock_timeout = '1s'"))
        second = claim_next_job(session_b, {JobType.SYSTEM_NOOP})
        assert second is not None and second.job_id != first.job_id
        first_id, second_id = first.job_id, second.job_id
        session_b.commit()
        session_a.commit()
        session_a.close()
        session_b.close()
        session_a = session_b = None

        with factory() as db:
            claimed = db.scalars(
                select(Job).where(Job.job_id.in_([first_id, second_id]))
            ).all()
            assert len(claimed) == 2
            assert all(job.status == JobStatus.PROCESSING for job in claimed)
            assert all(job.attempt_count == 1 for job in claimed)
            assert all(job.started_at is not None for job in claimed)

        with factory.begin() as db:
            success = claim_next_job(db, {JobType.SYSTEM_NOOP})
            assert success is not None
            success_id = success.job_id
        with factory.begin() as db:
            completed = complete_job(db, success_id)
            assert completed.status == JobStatus.COMPLETED
            assert completed.progress == 100
            assert completed.attempt_count == 1
            assert completed.started_at.tzinfo == timezone.utc
            assert completed.completed_at.tzinfo == timezone.utc
            assert completed.error_code is None and completed.error_message is None

        with factory.begin() as db:
            failure = claim_next_job(db, {JobType.SYSTEM_NOOP})
            assert failure is not None
            failure.progress = 41
            failure_id = failure.job_id
        with factory.begin() as db:
            failed = fail_job(
                db,
                failure_id,
                error_code="TEST_CONTROLLED_FAILURE",
                error_message="intentional integration verification failure",
            )
            assert failed.status == JobStatus.FAILED
            assert failed.progress == 41
            assert failed.attempt_count == 1
            assert failed.started_at.tzinfo == timezone.utc
            assert failed.completed_at.tzinfo == timezone.utc
            assert failed.error_code == "TEST_CONTROLLED_FAILURE"
            assert failed.error_message == "intentional integration verification failure"
    finally:
        if session_a is not None:
            session_a.rollback()
            session_a.close()
        if session_b is not None:
            session_b.rollback()
            session_b.close()
        if job_ids:
            with factory.begin() as db:
                db.execute(delete(Job).where(Job.job_id.in_(job_ids)))
        with factory() as db:
            assert not db.scalars(select(Job).where(Job.job_id.in_(job_ids))).all()
            assert db.scalar(text("SELECT version_num FROM alembic_version")) == "20260908_0011"
        engine.dispose()
