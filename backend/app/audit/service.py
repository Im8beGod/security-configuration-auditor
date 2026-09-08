from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.audit.errors import (
    AuditConflictError, AuditInfrastructureError, AuditNotFoundError,
    AuditValidationError,
)
from app.audit.schemas import AuditCreate, BatchAuditCreate
from app.db.models import (
    Artifact, Audit, AuditReevaluationReason, AuditStatus, Device, Job,
    Snapshot, SnapshotStatus, User,
)
from app.jobs.enums import JobType
from app.jobs.errors import JobError
from app.jobs.service import enqueue_job
from app.ingestion.storage import ArtifactStorage
from app.profile_resolution import (
    ProfileResolutionResult,
    aggregate_snapshot_evidence,
    resolve_profile,
)
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
    validate_snapshot_evidence(db, snapshot)
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


def create_batch_audits(db: Session, user: User, request: BatchAuditCreate) -> list[dict]:
    """Coordinate independent create/run operations without a batch persistence model."""
    results = []
    for item in request.items:
        try:
            snapshot = db.scalar(select(Snapshot).where(
                Snapshot.snapshot_id == item.snapshot_id,
                Snapshot.organization_id == user.organization_id,
            ))
            if snapshot is None:
                raise AuditNotFoundError("snapshot_not_found", "Snapshot not found")
            if snapshot.device_id != item.device_id:
                raise AuditValidationError(
                    "snapshot_device_mismatch", "Snapshot does not belong to device"
                )
            audit = create_audit(db, user, AuditCreate(
                snapshot_id=item.snapshot_id,
                selected_frameworks=item.selected_frameworks,
            ))
            queued, job = start_audit(db, user, audit.audit_id)
            results.append({
                "status": "accepted", "device_id": item.device_id,
                "snapshot_id": item.snapshot_id, "audit_id": queued.audit_id,
                "job_id": job.job_id,
            })
        except (
            AuditNotFoundError, AuditConflictError, AuditValidationError,
            AuditInfrastructureError,
        ) as error:
            results.append({
                "status": "rejected", "device_id": item.device_id,
                "snapshot_id": item.snapshot_id, "error_code": error.code,
                "error_message": error.message,
            })
    return results


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
    validate_snapshot_evidence(db, snapshot, lock=True)

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


def resolve_audit_profile(
    db: Session,
    storage: ArtifactStorage,
    audit_id: UUID,
    organization_id: UUID,
) -> ProfileResolutionResult:
    """Resolve one Audit's immutable Snapshot without holding locks during I/O."""
    audit = db.scalar(select(Audit).where(
        Audit.audit_id == audit_id,
        Audit.organization_id == organization_id,
    ))
    if audit is None:
        raise AuditNotFoundError("audit_not_found", "Audit not found")

    snapshot = db.scalar(select(Snapshot).where(
        Snapshot.snapshot_id == audit.snapshot_id
    ))
    device = db.scalar(select(Device).where(
        Device.device_id == audit.device_id
    ))
    if snapshot is None or device is None or (
        snapshot.organization_id != audit.organization_id
        or snapshot.device_id != audit.device_id
        or device.organization_id != audit.organization_id
    ):
        raise AuditValidationError(
            "audit_resource_inconsistent", "Audit resources are inconsistent"
        )
    if snapshot.status not in {SnapshotStatus.READY, SnapshotStatus.LOCKED}:
        raise AuditConflictError(
            "snapshot_not_resolvable", "Audit Snapshot is not ready for profile resolution"
        )

    artifacts = validate_snapshot_evidence(db, snapshot)
    expected_evidence = tuple(
        (artifact.artifact_id, artifact.sha256) for artifact in artifacts
    )
    for artifact in artifacts:
        db.expunge(artifact)
    snapshot_id = snapshot.snapshot_id
    device_id = device.device_id
    db.rollback()

    evidence = aggregate_snapshot_evidence(
        storage,
        snapshot_id=snapshot_id,
        organization_id=organization_id,
        device_id=device_id,
        artifacts=artifacts,
    )
    result = resolve_profile(evidence)
    try:
        audit = db.scalar(select(Audit).where(
            Audit.audit_id == audit_id,
            Audit.organization_id == organization_id,
        ).with_for_update())
        if audit is None:
            raise AuditNotFoundError("audit_not_found", "Audit not found")
        snapshot = db.scalar(select(Snapshot).where(
            Snapshot.snapshot_id == snapshot_id
        ).with_for_update())
        device = db.scalar(select(Device).where(
            Device.device_id == device_id
        ).with_for_update())
        if snapshot is None or device is None or (
            audit.snapshot_id != snapshot_id
            or audit.device_id != device_id
            or snapshot.organization_id != organization_id
            or snapshot.device_id != device_id
            or device.organization_id != organization_id
        ):
            raise AuditValidationError(
                "audit_resource_changed", "Audit resources changed during profile resolution"
            )
        current_artifacts = validate_snapshot_evidence(db, snapshot, lock=True)
        if tuple(
            (artifact.artifact_id, artifact.sha256) for artifact in current_artifacts
        ) != expected_evidence:
            raise AuditValidationError(
                "snapshot_evidence_changed",
                "Snapshot evidence changed during profile resolution",
            )
        pinned_profile = audit.version_refs.get("device_profile_version_id")
        if (
            pinned_profile is not None
            and pinned_profile != result.selected_profile_version_id
        ):
            raise AuditConflictError(
                "audit_profile_version_conflict",
                "Audit device-profile version is already pinned differently",
            )
        audit.profile_resolution = result.to_persisted()
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise AuditInfrastructureError(
            "profile_resolution_persistence_failed",
            "Audit profile resolution could not be persisted",
        ) from None
    db.refresh(audit)
    return result


def validate_snapshot_evidence(
    db: Session, snapshot: Snapshot, *, lock: bool = False
) -> list[Artifact]:
    statement = select(Artifact).where(
        Artifact.snapshot_id == snapshot.snapshot_id,
    ).order_by(Artifact.artifact_id)
    if lock:
        statement = statement.with_for_update()
    artifacts = list(db.scalars(statement))
    if not artifacts or any(
        artifact.organization_id != snapshot.organization_id
        or artifact.status not in ELIGIBLE_ARTIFACT_STATUSES
        for artifact in artifacts
    ):
        raise AuditValidationError("snapshot_evidence_invalid", "Snapshot evidence is not eligible")
    expected_hash = calculate_snapshot_hash([artifact.sha256 for artifact in artifacts])
    if snapshot.artifact_count != len(artifacts) or snapshot.snapshot_hash != expected_hash:
        raise AuditValidationError("snapshot_evidence_incoherent", "Snapshot evidence metadata is inconsistent")
    return artifacts
