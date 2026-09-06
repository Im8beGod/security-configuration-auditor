from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.audit.errors import (
    AuditConflictError, AuditInfrastructureError, AuditNotFoundError,
    AuditValidationError,
)
from app.audit.schemas import AuditCreate
from app.db.models import (
    Artifact, Audit, AuditReevaluationReason, AuditStatus, Device, Job,
    Snapshot, SnapshotStatus, User,
)
from app.jobs.enums import JobType
from app.jobs.errors import JobError
from app.jobs.service import enqueue_job
from app.snapshots.service import ELIGIBLE_ARTIFACT_STATUSES, calculate_snapshot_hash


def create_audit(db: Session, user: User, request: AuditCreate) -> Audit:
    snapshot = db.scalar(select(Snapshot).where(
        Snapshot.snapshot_id == request.snapshot_id,
        Snapshot.organization_id == user.organization_id,
    ))
    if snapshot is None:
        raise AuditNotFoundError("snapshot_not_found", "Snapshot not found")
    if snapshot.status != SnapshotStatus.READY:
        raise AuditConflictError("snapshot_not_ready", "Snapshot must be ready")
    if db.scalar(select(Device.device_id).where(
        Device.device_id == snapshot.device_id,
        Device.organization_id == user.organization_id,
    )) is None:
        raise AuditValidationError("snapshot_identity_invalid", "Snapshot identity is inconsistent")
    _validate_snapshot_evidence(db, snapshot)
    if db.scalar(select(Audit.audit_id).where(
        Audit.snapshot_id == snapshot.snapshot_id, Audit.revision_number == 1
    )) is not None:
        raise AuditConflictError("initial_audit_exists", "Initial Audit already exists")

    audit = Audit(
        organization_id=user.organization_id,
        device_id=snapshot.device_id,
        snapshot_id=snapshot.snapshot_id,
        audit_batch_id=None,
        revision_number=1,
        previous_audit_id=None,
        reevaluation_reason=AuditReevaluationReason.INITIAL,
        status=AuditStatus.DRAFT,
        processing_stage=None,
        selected_frameworks=request.selected_frameworks,
        version_refs={},
        profile_resolution={},
        verdict_counts={},
        severity_counts={},
        coverage={},
        started_at=None,
        completed_at=None,
        created_by=user.user_id,
        schema_version="1.0.0",
    )
    db.add(audit)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise AuditConflictError("initial_audit_exists", "Initial Audit already exists") from None
    except SQLAlchemyError:
        db.rollback()
        raise AuditInfrastructureError("audit_persistence_failed", "Audit could not be created") from None
    db.refresh(audit)
    return audit


def list_audits(db: Session, user: User) -> list[Audit]:
    return list(db.scalars(select(Audit).where(
        Audit.organization_id == user.organization_id
    ).order_by(Audit.created_at.desc(), Audit.audit_id)))


def get_audit(db: Session, user: User, audit_id: UUID) -> Audit:
    audit = db.scalar(select(Audit).where(
        Audit.audit_id == audit_id, Audit.organization_id == user.organization_id
    ))
    if audit is None:
        raise AuditNotFoundError("audit_not_found", "Audit not found")
    return audit


def get_audit_job(db: Session, audit_id: UUID) -> Job | None:
    return db.scalar(select(Job).where(
        Job.audit_id == audit_id, Job.job_type == JobType.AUDIT
    ).order_by(Job.created_at.desc(), Job.job_id).limit(1))


def start_audit(db: Session, user: User, audit_id: UUID) -> tuple[Audit, Job]:
    audit = db.scalar(select(Audit).where(
        Audit.audit_id == audit_id, Audit.organization_id == user.organization_id
    ).with_for_update())
    if audit is None:
        raise AuditNotFoundError("audit_not_found", "Audit not found")
    if audit.status != AuditStatus.DRAFT:
        raise AuditConflictError("audit_not_draft", "Audit has already been submitted")
    snapshot = db.scalar(select(Snapshot).where(
        Snapshot.snapshot_id == audit.snapshot_id
    ).with_for_update())
    if snapshot is None or (
        snapshot.organization_id != audit.organization_id
        or snapshot.device_id != audit.device_id
    ):
        raise AuditValidationError("audit_snapshot_invalid", "Audit Snapshot is inconsistent")
    if snapshot.status != SnapshotStatus.READY:
        raise AuditConflictError("snapshot_not_ready", "Snapshot is no longer ready")
    _validate_snapshot_evidence(db, snapshot, lock=True)

    snapshot.status = SnapshotStatus.LOCKED
    audit.status = AuditStatus.QUEUED
    audit.processing_stage = None
    audit.started_at = None
    audit.completed_at = None
    try:
        job = enqueue_job(
            db, JobType.AUDIT, audit_id=audit.audit_id, device_id=audit.device_id
        )
        db.commit()
    except (JobError, SQLAlchemyError):
        db.rollback()
        raise AuditInfrastructureError(
            "audit_submission_failed", "Audit could not be submitted"
        ) from None
    db.refresh(audit)
    db.refresh(job)
    return audit, job


def _validate_snapshot_evidence(
    db: Session, snapshot: Snapshot, *, lock: bool = False
) -> list[Artifact]:
    statement = select(Artifact).where(
        Artifact.snapshot_id == snapshot.snapshot_id,
        Artifact.organization_id == snapshot.organization_id,
    ).order_by(Artifact.artifact_id)
    if lock:
        statement = statement.with_for_update()
    artifacts = list(db.scalars(statement))
    if not artifacts or any(
        artifact.status not in ELIGIBLE_ARTIFACT_STATUSES for artifact in artifacts
    ):
        raise AuditValidationError("snapshot_evidence_invalid", "Snapshot evidence is not eligible")
    expected_hash = calculate_snapshot_hash([artifact.sha256 for artifact in artifacts])
    if snapshot.artifact_count != len(artifacts) or snapshot.snapshot_hash != expected_hash:
        raise AuditValidationError("snapshot_evidence_incoherent", "Snapshot evidence metadata is inconsistent")
    return artifacts
