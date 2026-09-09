import re
from collections.abc import Collection, Mapping
from datetime import datetime, timedelta, timezone
import math
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.models.common import utc_now
from app.db.models.job import Job
from app.jobs import repository
from app.jobs.enums import JobStatus, JobType
from app.jobs.errors import (
    InvalidJobTransitionError,
    JobError,
    JobLeaseLostError,
    JobNotFoundError,
)


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
    db: Session,
    allowed_job_types: Collection[JobType] | None = None,
    *,
    lease_owner: str,
    lease_seconds: float,
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
    now = utc_now()
    job.started_at = now
    job.completed_at = None
    job.lease_owner = _validated_lease_owner(lease_owner)
    job.heartbeat_at = now
    job.lease_expires_at = now + timedelta(seconds=_validated_lease_seconds(lease_seconds))
    db.flush()
    return job


def heartbeat_job(
    db: Session, job_id: UUID, *, lease_owner: str, lease_seconds: float
) -> Job:
    """Renew the active lease for its current owner."""
    job = _owned_processing_job_for_update(db, job_id, lease_owner)
    now = utc_now()
    _require_active_lease(job, now)
    job.heartbeat_at = now
    job.lease_expires_at = now + timedelta(seconds=_validated_lease_seconds(lease_seconds))
    db.flush()
    return job


def complete_job(db: Session, job_id: UUID, *, lease_owner: str) -> Job:
    """Complete a locked processing job; the caller owns commit/rollback."""
    job = _owned_processing_job_for_update(db, job_id, lease_owner)
    _require_active_lease(job, utc_now())
    job.status = JobStatus.COMPLETED
    job.progress = 100
    job.completed_at = utc_now()
    job.error_code = None
    job.error_message = None
    _clear_lease(job)
    db.flush()
    return job


def fail_job(
    db: Session,
    job_id: UUID,
    *,
    lease_owner: str,
    error_code: str,
    error_message: str,
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
    job = _owned_processing_job_for_update(db, job_id, lease_owner)
    _require_active_lease(job, utc_now())
    job.status = JobStatus.FAILED
    job.completed_at = utc_now()
    job.error_code = normalized_code
    job.error_message = normalized_message
    _clear_lease(job)
    db.flush()
    return job


def recover_stale_jobs(db: Session, *, limit: int = 100) -> list[Job]:
    """Fail expired or pre-lease processing jobs; never requeue or replay them."""
    if not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise JobError("Recovery batch size must be between 1 and 1000")
    now = utc_now()
    jobs = repository.stale_processing_for_update(db, now, limit=limit)
    for job in jobs:
        job.status = JobStatus.FAILED
        job.completed_at = now
        job.error_code = "worker_lease_expired"
        job.error_message = "Job worker lease expired before completion"
        _clear_lease(job)
    db.flush()
    return jobs


def _owned_processing_job_for_update(
    db: Session, job_id: UUID, lease_owner: str
) -> Job:
    job = repository.by_id_for_update(db, job_id)
    if job is None:
        raise JobNotFoundError("Job was not found")
    if job.status != JobStatus.PROCESSING:
        raise InvalidJobTransitionError(
            f"Job must be processing, not {job.status.value}"
        )
    if job.lease_owner != _validated_lease_owner(lease_owner):
        raise JobLeaseLostError("Job lease is not owned by this worker")
    return job


def _require_active_lease(job: Job, now: datetime) -> None:
    if job.lease_expires_at is None or _as_utc(job.lease_expires_at) <= _as_utc(now):
        raise JobLeaseLostError("Job lease has expired")


def _clear_lease(job: Job) -> None:
    job.lease_owner = None
    job.heartbeat_at = None
    job.lease_expires_at = None


def _validated_lease_owner(lease_owner: str) -> str:
    owner = lease_owner.strip()
    if not owner or len(owner) > 128:
        raise JobError("Job lease owner must contain 1 to 128 characters")
    return owner


def _validated_lease_seconds(lease_seconds: float) -> float:
    if not math.isfinite(lease_seconds) or not 0 < lease_seconds <= 3600:
        raise JobError("Job lease duration must be between 0 and 3600 seconds")
    return lease_seconds


def _as_utc(value: datetime) -> datetime:
    """Normalize SQLite's naive DateTime round-trips without weakening UTC use."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
