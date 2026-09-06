from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import CheckConstraint, Index, Uuid
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB

from app.db.base import Base
from app.db.models import Job, JobStatus, JobType
from app.jobs.errors import InvalidJobTransitionError, JobError, JobNotFoundError
from app.jobs.repository import next_queued_for_update_statement
from app.jobs.service import claim_next_job, complete_job, enqueue_job, fail_job


EXPECTED_TABLES = {
    "artifacts", "audits", "devices", "jobs", "organizations", "security_facts",
    "snapshots", "users"
}


def test_job_model_contract_and_database_constraints():
    table = Job.__table__
    columns = table.c
    check_names = {
        constraint.name
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }
    indexes = {index.name: tuple(index.columns.keys()) for index in table.indexes}

    assert set(Base.metadata.tables) == EXPECTED_TABLES
    assert table.name == "jobs"
    assert columns.job_id.primary_key and isinstance(columns.job_id.type, Uuid)
    assert columns.job_id.type.python_type is UUID
    assert [status.value for status in JobStatus] == [
        "queued", "processing", "completed", "failed"
    ]
    assert [job_type.value for job_type in JobType] == [
        "audit", "re_evaluation", "mapping_validation", "pdf_generation",
        "bulk_report_generation", "system_noop",
    ]
    assert columns.status.type.enums == [status.value for status in JobStatus]
    assert columns.job_type.type.enums == [job_type.value for job_type in JobType]
    assert columns.status.type.native is False
    assert columns.job_type.type.native is False
    assert {"ck_jobs_status", "ck_jobs_job_type", "ck_jobs_progress",
            "ck_jobs_attempt_count", "ck_jobs_payload"} <= check_names
    assert isinstance(columns.payload.type, JSONB) and not columns.payload.nullable
    assert columns.audit_id.nullable and columns.device_id.nullable
    assert next(iter(columns.audit_id.foreign_keys)).target_fullname == "audits.audit_id"
    assert next(iter(columns.device_id.foreign_keys)).target_fullname == "devices.device_id"
    assert next(iter(columns.audit_id.foreign_keys)).ondelete == "RESTRICT"
    assert next(iter(columns.device_id.foreign_keys)).ondelete == "RESTRICT"
    assert indexes["ix_jobs_queue_claim"] == ("status", "created_at", "job_id")
    assert indexes["ix_jobs_audit_id"] == ("audit_id",)
    assert indexes["ix_jobs_device_id"] == ("device_id",)
    assert all(columns[name].type.timezone for name in (
        "created_at", "started_at", "completed_at"
    ))
    assert set(columns.keys()) == {
        "job_id", "job_type", "status", "stage", "progress", "audit_id",
        "device_id", "payload", "attempt_count", "error_code", "error_message",
        "created_at", "started_at", "completed_at",
    }


def test_claim_statement_uses_postgresql_skip_locked_and_deterministic_order():
    statement = str(next_queued_for_update_statement().compile(
        dialect=postgresql.dialect()
    ))
    assert "FOR UPDATE SKIP LOCKED" in statement
    assert "ORDER BY jobs.created_at ASC, jobs.job_id ASC" in statement
    filtered = str(next_queued_for_update_statement({JobType.SYSTEM_NOOP}).compile(
        dialect=postgresql.dialect()
    ))
    assert "jobs.job_type IN" in filtered


def test_claim_filters_supported_types_before_transition(job_factory):
    with job_factory.begin() as db:
        audit_id = enqueue_job(db, JobType.AUDIT).job_id
        noop_id = enqueue_job(db, JobType.SYSTEM_NOOP).job_id
    with job_factory.begin() as db:
        claimed = claim_next_job(db, allowed_job_types={JobType.SYSTEM_NOOP})
        assert claimed.job_id == noop_id
        assert claimed.attempt_count == 1
    with job_factory() as db:
        audit = db.get(Job, audit_id)
        assert audit.status == JobStatus.QUEUED
        assert audit.attempt_count == 0


def test_empty_allowed_types_claim_nothing(job_factory):
    with job_factory.begin() as db:
        job_id = enqueue_job(db, JobType.SYSTEM_NOOP).job_id
    with job_factory.begin() as db:
        assert claim_next_job(db, allowed_job_types=set()) is None
    with job_factory() as db:
        job = db.get(Job, job_id)
        assert job.status == JobStatus.QUEUED and job.attempt_count == 0


def test_enqueue_and_complete_lifecycle(job_factory):
    with job_factory.begin() as db:
        job = enqueue_job(
            db, JobType.SYSTEM_NOOP, payload={"verification": True}, stage=" queued "
        )
        job_id = job.job_id
        assert job.status == JobStatus.QUEUED
        assert job.stage == "queued"
        assert job.progress == 0 and job.attempt_count == 0
        assert job.payload == {"verification": True}
        assert job.started_at is None and job.completed_at is None
        assert job.created_at.tzinfo is not None

    with job_factory.begin() as db:
        claimed = claim_next_job(db)
        assert claimed.job_id == job_id
        assert claimed.payload == {"verification": True}
        assert claimed.status == JobStatus.PROCESSING
        assert claimed.attempt_count == 1
        assert claimed.started_at.tzinfo is not None
        assert claimed.completed_at is None
        claimed.error_code = "STALE"
        claimed.error_message = "cleared on successful completion"

    with job_factory.begin() as db:
        completed = complete_job(db, job_id)
        assert completed.status == JobStatus.COMPLETED
        assert completed.progress == 100
        assert completed.completed_at.tzinfo is not None
        assert completed.started_at is not None
        assert completed.error_code is None and completed.error_message is None

    with job_factory.begin() as db:
        assert claim_next_job(db) is None  # Completed jobs cannot return to processing.
        with pytest.raises(InvalidJobTransitionError):
            complete_job(db, job_id)


def test_failure_lifecycle_preserves_progress_and_bounds_errors(job_factory):
    with job_factory.begin() as db:
        job_id = enqueue_job(db, JobType.SYSTEM_NOOP).job_id
        with pytest.raises(InvalidJobTransitionError):
            fail_job(db, job_id, error_code="SAFE_ERROR", error_message="safe failure")

    with job_factory.begin() as db:
        claimed = claim_next_job(db)
        claimed.progress = 37
        assert claimed.job_id == job_id

    with job_factory.begin() as db:
        with pytest.raises(JobError):
            fail_job(
                db, job_id, error_code="TRACE", error_message="Traceback:\ninternal"
            )
        with pytest.raises(JobError):
            fail_job(db, job_id, error_code="x" * 65, error_message="safe")
        failed = fail_job(
            db, job_id, error_code="CONTROLLED_FAILURE", error_message="safe failure"
        )
        assert failed.status == JobStatus.FAILED
        assert failed.progress == 37
        assert failed.error_code == "CONTROLLED_FAILURE"
        assert failed.error_message == "safe failure"
        assert failed.completed_at.tzinfo is not None

    with job_factory.begin() as db:
        persisted = db.get(Job, job_id)
        assert persisted.error_code == "CONTROLLED_FAILURE"
        assert persisted.error_message == "safe failure"
        assert persisted.completed_at is not None
        assert claim_next_job(db) is None  # Failed jobs do not retry automatically.
        with pytest.raises(InvalidJobTransitionError):
            complete_job(db, job_id)
        with pytest.raises(JobNotFoundError):
            complete_job(db, uuid4())


@pytest.mark.parametrize("field,value", [("progress", -1), ("progress", 101),
                                          ("attempt_count", -1)])
def test_numeric_database_constraints_reject_invalid_values(job_factory, field, value):
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError), job_factory.begin() as db:
        job = Job(job_type=JobType.SYSTEM_NOOP, payload={})
        setattr(job, field, value)
        db.add(job)
        db.flush()
