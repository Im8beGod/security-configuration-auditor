from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.db.models import Audit, Job, User
from app.db.session import get_db
from app.jobs.enums import JobType
from app.jobs.schemas import JobResponse


router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("/{job_id}", response_model=JobResponse)
def get_job_endpoint(
    job_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Job:
    job = db.scalar(
        select(Job)
        .join(Audit, Job.audit_id == Audit.audit_id)
        .where(
            Job.job_id == job_id,
            Job.job_type == JobType.AUDIT,
            Audit.organization_id == user.organization_id,
        )
    )
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Job not found")
    return job
