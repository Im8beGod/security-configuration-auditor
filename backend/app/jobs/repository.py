from collections.abc import Collection
from uuid import UUID

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.db.models.job import Job
from app.jobs.enums import JobStatus, JobType


def add(db: Session, job: Job) -> None:
    db.add(job)


def next_queued_for_update_statement(
    allowed_job_types: Collection[JobType] | None = None,
) -> Select[tuple[Job]]:
    statement = select(Job).where(Job.status == JobStatus.QUEUED)
    if allowed_job_types is not None:
        statement = statement.where(Job.job_type.in_(allowed_job_types))
    return (
        statement.order_by(Job.created_at.asc(), Job.job_id.asc())
        .limit(1)
        .with_for_update(skip_locked=True)
    )


def next_queued_for_update(
    db: Session, allowed_job_types: Collection[JobType] | None = None
) -> Job | None:
    return db.scalar(next_queued_for_update_statement(allowed_job_types))


def by_id_for_update(db: Session, job_id: UUID) -> Job | None:
    return db.scalar(select(Job).where(Job.job_id == job_id).with_for_update())
