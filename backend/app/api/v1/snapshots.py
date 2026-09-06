from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.db.models import Snapshot, User
from app.db.session import get_db
from app.snapshots.errors import (
    SnapshotConflictError, SnapshotNotFoundError, SnapshotValidationError,
)
from app.snapshots.schemas import SnapshotResponse, SnapshotUpdate
from app.snapshots.service import (
    add_artifact, finalize_snapshot, get_snapshot, remove_artifact, update_snapshot,
)


router = APIRouter(prefix="/snapshots", tags=["snapshots"])


def _translate(error: Exception) -> HTTPException:
    if isinstance(error, SnapshotNotFoundError):
        return HTTPException(status.HTTP_404_NOT_FOUND, error.message)
    if isinstance(error, SnapshotConflictError):
        return HTTPException(
            status.HTTP_409_CONFLICT,
            {"code": error.code, "message": error.message},
        )
    if isinstance(error, SnapshotValidationError):
        return HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            {"code": error.code, "message": error.message},
        )
    raise error


@router.get("/{snapshot_id}", response_model=SnapshotResponse)
def get_snapshot_endpoint(
    snapshot_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Snapshot:
    try:
        return get_snapshot(db, user, snapshot_id)
    except SnapshotNotFoundError as error:
        raise _translate(error) from None


@router.patch("/{snapshot_id}", response_model=SnapshotResponse)
def update_snapshot_endpoint(
    snapshot_id: UUID,
    request: SnapshotUpdate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Snapshot:
    try:
        return update_snapshot(db, user, snapshot_id, request)
    except (SnapshotNotFoundError, SnapshotConflictError) as error:
        raise _translate(error) from None


@router.post("/{snapshot_id}/artifacts/{artifact_id}", response_model=SnapshotResponse)
def add_artifact_endpoint(
    snapshot_id: UUID,
    artifact_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Snapshot:
    try:
        return add_artifact(db, user, snapshot_id, artifact_id)
    except (SnapshotNotFoundError, SnapshotConflictError, SnapshotValidationError) as error:
        raise _translate(error) from None


@router.delete(
    "/{snapshot_id}/artifacts/{artifact_id}", status_code=status.HTTP_204_NO_CONTENT
)
def remove_artifact_endpoint(
    snapshot_id: UUID,
    artifact_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    try:
        remove_artifact(db, user, snapshot_id, artifact_id)
    except (SnapshotNotFoundError, SnapshotConflictError) as error:
        raise _translate(error) from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{snapshot_id}/finalize", response_model=SnapshotResponse)
def finalize_snapshot_endpoint(
    snapshot_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Snapshot:
    try:
        return finalize_snapshot(db, user, snapshot_id)
    except (SnapshotNotFoundError, SnapshotConflictError, SnapshotValidationError) as error:
        raise _translate(error) from None
