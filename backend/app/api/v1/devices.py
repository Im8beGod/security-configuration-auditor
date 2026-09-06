from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.db.models import Device, User
from app.db.session import get_db
from app.devices.errors import DeviceNotFoundError
from app.devices.schemas import DeviceCreate, DeviceResponse, DeviceUpdate
from app.devices.service import create_device, get_device, list_devices, update_device
from app.snapshots.schemas import SnapshotCreate, SnapshotResponse
from app.snapshots.service import create_snapshot, list_device_snapshots


router = APIRouter(prefix="/devices", tags=["devices"])


def _not_found(error: DeviceNotFoundError) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, error.message)


@router.post("", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
def create_device_endpoint(
    request: DeviceCreate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Device:
    return create_device(db, user, request)


@router.get("", response_model=list[DeviceResponse])
def list_devices_endpoint(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> list[Device]:
    return list_devices(db, user)


@router.get("/{device_id}", response_model=DeviceResponse)
def get_device_endpoint(
    device_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Device:
    try:
        return get_device(db, user, device_id)
    except DeviceNotFoundError as error:
        raise _not_found(error) from None


@router.patch("/{device_id}", response_model=DeviceResponse)
def update_device_endpoint(
    device_id: UUID,
    request: DeviceUpdate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Device:
    try:
        return update_device(db, user, device_id, request)
    except DeviceNotFoundError as error:
        raise _not_found(error) from None


@router.post(
    "/{device_id}/snapshots",
    response_model=SnapshotResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_snapshot_endpoint(
    device_id: UUID,
    request: SnapshotCreate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    try:
        return create_snapshot(db, user, device_id, request)
    except DeviceNotFoundError as error:
        raise _not_found(error) from None


@router.get("/{device_id}/snapshots", response_model=list[SnapshotResponse])
def list_snapshots_endpoint(
    device_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    try:
        return list_device_snapshots(db, user, device_id)
    except DeviceNotFoundError as error:
        raise _not_found(error) from None
