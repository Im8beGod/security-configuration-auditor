from uuid import UUID

from app.db.models import Job
from app.db.session import get_session_factory
from app.training.service import execute_validation


def handle_mapping_validation(job_id: UUID) -> None:
    factory = get_session_factory()
    with factory.begin() as db:
        job = db.get(Job, job_id)
        if job is None:
            raise ValueError("Mapping validation job was not found")
        try:
            mapping_version_id = UUID(job.payload["mapping_version_id"])
            validation_run_id = UUID(job.payload["validation_run_id"])
            organization_id = UUID(job.payload["organization_id"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("Mapping validation job payload is invalid") from None
        execute_validation(db, validation_run_id, mapping_version_id, organization_id)
