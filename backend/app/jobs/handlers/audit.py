from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.audit.errors import AuditWorkflowError
from app.audit.pipeline import AuditPipelineCoordinator
from app.db.models import Audit, Job, JobType
from app.ingestion.storage import ArtifactStorage
from app.interpretation import InterpretationWorkflowError
from app.jobs.errors import JobError


@dataclass(frozen=True)
class AuditJobHandler:
    """Thin Job adapter; all pipeline behavior remains in the Audit domain."""

    factory: sessionmaker[Session]
    storage: ArtifactStorage

    def __call__(self, job_id: UUID) -> None:
        with self.factory() as db:
            identity = db.execute(
                select(Job.job_type, Job.audit_id, Job.device_id).where(
                    Job.job_id == job_id
                )
            ).one_or_none()
            if (
                identity is None
                or identity.job_type != JobType.AUDIT
                or identity.audit_id is None
            ):
                raise JobError("Audit Job reference is invalid")
            audit_identity = db.execute(
                select(Audit.organization_id, Audit.device_id).where(
                    Audit.audit_id == identity.audit_id
                )
            ).one_or_none()
            if (
                audit_identity is None
                or identity.device_id != audit_identity.device_id
            ):
                raise JobError("Audit Job reference is inconsistent")
            audit_id = identity.audit_id
            organization_id = audit_identity.organization_id

        try:
            AuditPipelineCoordinator(self.factory, self.storage).run(
                audit_id, organization_id
            )
        except (AuditWorkflowError, InterpretationWorkflowError):
            raise JobError("Audit pipeline execution failed") from None
