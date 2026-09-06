import re
from collections.abc import Collection, Mapping
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.models.common import utc_now
from app.db.models.job import Job
from app.jobs import repository
from app.jobs.enums import JobStatus, JobType
from app.jobs.errors import InvalidJobTransitionError, JobError, JobNotFoundError


ERROR_CODE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def enqueue_job(
    db: Session,
    job_type: JobType,
    *,
    payload: Mapping[str, Any] | None = None,
    audit_id: UUID | None = None,
    device_id: UUID | None = None,
    stage: str | None = None,
) -> Job:
    """Add a queued job and flush; the caller owns commit/rollback."""
    if not isinstance(job_type, JobType):
        raise JobError("Unsupported job type")
    if payload is not None and not isinstance(payload, Mapping):
        raise JobError("Job payload must be an object")
    if stage is not None and (not stage.strip() or len(stage.strip()) > 100):
        raise JobError("Job stage must contain 1 to 100 characters")
    job = Job(
        job_type=job_type,
        status=JobStatus.QUEUED,
        stage=stage.strip() if stage is not None else None,
        progress=0,
        audit_id=audit_id,
        device_id=device_id,
        payload=dict(payload or {}),
        attempt_count=0,
    )
    repository.add(db, job)
    db.flush()
    return job


def claim_next_job(
    db: Session, allowed_job_types: Collection[JobType] | None = None
) -> Job | None:
    """Lock and transition the oldest queued job; caller must commit atomically."""
    allowed = None if allowed_job_types is None else frozenset(allowed_job_types)
    if allowed is not None:
        if any(not isinstance(job_type, JobType) for job_type in allowed):
            raise JobError("Allowed job types must contain only JobType values")
        if not allowed:
            return None
    job = repository.next_queued_for_update(db, allowed)
    if job is None:
        return None
    job.status = JobStatus.PROCESSING
    job.attempt_count += 1
    job.started_at = utc_now()
    job.completed_at = None
    db.flush()
    return job


def complete_job(db: Session, job_id: UUID) -> Job:
    """Complete a locked processing job; the caller owns commit/rollback."""
    job = _processing_job_for_update(db, job_id)
    job.status = JobStatus.COMPLETED
    job.progress = 100
    job.completed_at = utc_now()
    job.error_code = None
    job.error_message = None
    db.flush()
    return job


def fail_job(
    db: Session, job_id: UUID, *, error_code: str, error_message: str
) -> Job:
    """Fail a locked processing job using bounded, caller-curated metadata."""
    normalized_code = error_code.strip()
    normalized_message = error_message.strip()
    if not ERROR_CODE_PATTERN.fullmatch(normalized_code):
        raise JobError("Invalid job error code")
    if (
        not normalized_message
        or len(normalized_message) > 1000
        or "\n" in normalized_message
        or "\r" in normalized_message
    ):
        raise JobError("Job error message must be a single line of 1 to 1000 characters")
    job = _processing_job_for_update(db, job_id)
    job.status = JobStatus.FAILED
    job.completed_at = utc_now()
    job.error_code = normalized_code
    job.error_message = normalized_message
    db.flush()
    return job


def _processing_job_for_update(db: Session, job_id: UUID) -> Job:
    job = repository.by_id_for_update(db, job_id)
    if job is None:
        raise JobNotFoundError("Job was not found")
    if job.status != JobStatus.PROCESSING:
        raise InvalidJobTransitionError(
            f"Job must be processing, not {job.status.value}"
        )
    return job
