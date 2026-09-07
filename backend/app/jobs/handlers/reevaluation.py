from uuid import UUID

from app.db.session import get_session_factory
from app.ingestion.storage import get_artifact_storage

from app.jobs.handlers.audit import AuditJobHandler


def handle_reevaluation(job_id: UUID) -> None:
    """Dispatch a durable re-evaluation without constructing runtime settings at import time."""
    AuditJobHandler(get_session_factory(), get_artifact_storage())(job_id)
