from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.audit.errors import AuditWorkflowError
from app.audit.pipeline import AuditPipelineCoordinator
from app.compliance.service import ComplianceError
from app.db.models import Audit, AuditStatus, Job, JobType
from app.effective_state.exceptions import EffectiveStateError
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
                or identity.job_type not in {JobType.AUDIT, JobType.RE_EVALUATION}
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

            if audit_identity and db.scalar(select(Audit.status).where(Audit.audit_id == audit_id)) in {
                AuditStatus.COMPLETED, AuditStatus.COMPLETED_WITH_UNKNOWNS,
                AuditStatus.COMPLETED_WITH_ERRORS, AuditStatus.FAILED
            }:
                return

        coordinator = AuditPipelineCoordinator(self.factory, self.storage)
        try:
            coordinator.run(audit_id, organization_id)
        except (AuditWorkflowError, InterpretationWorkflowError, EffectiveStateError, ComplianceError):
            try:
                coordinator.mark_failed(audit_id, organization_id)
            except AuditWorkflowError:
                pass
            raise JobError("Audit pipeline execution failed") from None
