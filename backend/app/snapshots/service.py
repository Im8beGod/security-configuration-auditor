from hashlib import sha256
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.models import (
    Artifact, ArtifactStatus, Device, Snapshot, SnapshotStatus, User,
)
from app.db.models.common import utc_now
from app.devices.errors import DeviceNotFoundError
from app.snapshots.errors import (
    SnapshotConflictError, SnapshotNotFoundError, SnapshotValidationError,
)
from app.snapshots.schemas import SnapshotCreate, SnapshotUpdate


EMPTY_SNAPSHOT_HASH = sha256(b"").hexdigest()
ELIGIBLE_ARTIFACT_STATUSES = frozenset({
    ArtifactStatus.VALIDATED,
    ArtifactStatus.READY,
    ArtifactStatus.PARTIALLY_SUPPORTED,
    ArtifactStatus.NEEDS_REVIEW,
})


def calculate_snapshot_hash(hashes: list[str]) -> str:
    """Hash the direct concatenation of sorted fixed-length SHA-256 hex values."""
    return sha256("".join(sorted(hashes)).encode("ascii")).hexdigest()


def create_snapshot(
    db: Session, user: User, device_id: UUID, request: SnapshotCreate
) -> Snapshot:
    device = db.scalar(select(Device).where(
        Device.device_id == device_id, Device.organization_id == user.organization_id
    ).with_for_update())
    if device is None:
        raise DeviceNotFoundError("device_not_found", "Device not found")
    now = utc_now()
    snapshot = Snapshot(
        device_id=device.device_id,
        organization_id=user.organization_id,
        status=SnapshotStatus.DRAFT,
        snapshot_hash=EMPTY_SNAPSHOT_HASH,
        artifact_count=0,
        created_by=user.user_id,
        ingested_at=now,
        schema_version="1.0.0",
        **request.model_dump(),
    )
    device.last_seen_at = now
    db.add(snapshot)
    db.commit()
    return get_snapshot(db, user, snapshot.snapshot_id)


def list_device_snapshots(db: Session, user: User, device_id: UUID) -> list[Snapshot]:
    if db.scalar(select(Device.device_id).where(
        Device.device_id == device_id, Device.organization_id == user.organization_id
    )) is None:
        raise DeviceNotFoundError("device_not_found", "Device not found")
    snapshots = list(db.scalars(
        select(Snapshot).options(selectinload(Snapshot.artifacts)).where(
            Snapshot.device_id == device_id,
            Snapshot.organization_id == user.organization_id,
        ).order_by(Snapshot.created_at.desc(), Snapshot.snapshot_id)
    ))
    for snapshot in snapshots:
        snapshot.artifacts.sort(key=lambda artifact: artifact.artifact_id)
    return snapshots


def get_snapshot(db: Session, user: User, snapshot_id: UUID) -> Snapshot:
    snapshot = db.scalar(select(Snapshot).options(selectinload(Snapshot.artifacts)).where(
        Snapshot.snapshot_id == snapshot_id,
        Snapshot.organization_id == user.organization_id,
    ))
    if snapshot is None:
        raise SnapshotNotFoundError("snapshot_not_found", "Snapshot not found")
    snapshot.artifacts.sort(key=lambda artifact: artifact.artifact_id)
    return snapshot


def update_snapshot(
    db: Session, user: User, snapshot_id: UUID, request: SnapshotUpdate
) -> Snapshot:
    snapshot = _lock_snapshot(db, user, snapshot_id)
    _require_draft(snapshot)
    for field, value in request.model_dump(exclude_unset=True).items():
        setattr(snapshot, field, value)
    db.commit()
    return get_snapshot(db, user, snapshot_id)


def add_artifact(db: Session, user: User, snapshot_id: UUID, artifact_id: UUID) -> Snapshot:
    snapshot = _lock_snapshot(db, user, snapshot_id)
    _require_draft(snapshot)
    artifact = db.scalar(select(Artifact).where(
        Artifact.artifact_id == artifact_id,
        Artifact.organization_id == user.organization_id,
    ).with_for_update())
    if artifact is None:
        raise SnapshotNotFoundError("artifact_not_found", "Artifact not found")
    if artifact.status not in ELIGIBLE_ARTIFACT_STATUSES:
        raise SnapshotValidationError("artifact_ineligible", "Artifact is not eligible for a Snapshot")
    if artifact.snapshot_id is not None and artifact.snapshot_id != snapshot.snapshot_id:
        raise SnapshotConflictError("artifact_already_assigned", "Artifact already belongs to another Snapshot")
    artifact.snapshot_id = snapshot.snapshot_id
    db.flush()
    _refresh_membership(db, snapshot)
    db.commit()
    return get_snapshot(db, user, snapshot_id)


def remove_artifact(db: Session, user: User, snapshot_id: UUID, artifact_id: UUID) -> Snapshot:
    snapshot = _lock_snapshot(db, user, snapshot_id)
    _require_draft(snapshot)
    artifact = db.scalar(select(Artifact).where(
        Artifact.artifact_id == artifact_id,
        Artifact.organization_id == user.organization_id,
    ).with_for_update())
    if artifact is None or artifact.snapshot_id != snapshot.snapshot_id:
        raise SnapshotNotFoundError("artifact_not_found", "Artifact not found in Snapshot")
    artifact.snapshot_id = None
    db.flush()
    _refresh_membership(db, snapshot)
    db.commit()
    return get_snapshot(db, user, snapshot_id)


def finalize_snapshot(db: Session, user: User, snapshot_id: UUID) -> Snapshot:
    snapshot = _lock_snapshot(db, user, snapshot_id)
    _require_draft(snapshot)
    artifacts = list(db.scalars(select(Artifact).where(
        Artifact.snapshot_id == snapshot.snapshot_id,
        Artifact.organization_id == user.organization_id,
    ).order_by(Artifact.artifact_id).with_for_update()))
    if not artifacts:
        raise SnapshotValidationError("empty_snapshot", "Snapshot requires at least one Artifact")
    if any(artifact.status not in ELIGIBLE_ARTIFACT_STATUSES for artifact in artifacts):
        raise SnapshotValidationError("artifact_ineligible", "Snapshot contains an ineligible Artifact")
    snapshot.artifact_count = len(artifacts)
    snapshot.snapshot_hash = calculate_snapshot_hash([item.sha256 for item in artifacts])
    snapshot.status = SnapshotStatus.READY
    db.commit()
    return get_snapshot(db, user, snapshot_id)


def _lock_snapshot(db: Session, user: User, snapshot_id: UUID) -> Snapshot:
    snapshot = db.scalar(select(Snapshot).where(
        Snapshot.snapshot_id == snapshot_id,
        Snapshot.organization_id == user.organization_id,
    ).with_for_update())
    if snapshot is None:
        raise SnapshotNotFoundError("snapshot_not_found", "Snapshot not found")
    return snapshot


def _require_draft(snapshot: Snapshot) -> None:
    if snapshot.status != SnapshotStatus.DRAFT:
        raise SnapshotConflictError("snapshot_not_draft", "Snapshot is no longer editable")


def _refresh_membership(db: Session, snapshot: Snapshot) -> None:
    hashes = list(db.scalars(select(Artifact.sha256).where(
        Artifact.snapshot_id == snapshot.snapshot_id
    )))
    snapshot.artifact_count = len(hashes)
    snapshot.snapshot_hash = calculate_snapshot_hash(hashes)
