from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Device, User
from app.db.models.common import utc_now
from app.devices.errors import DeviceNotFoundError
from app.devices.schemas import DeviceCreate, DeviceUpdate


def create_device(db: Session, user: User, request: DeviceCreate) -> Device:
    now = utc_now()
    device = Device(
        organization_id=user.organization_id,
        first_seen_at=now,
        last_seen_at=now,
        schema_version="1.0.0",
        **request.model_dump(),
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


def list_devices(db: Session, user: User) -> list[Device]:
    return list(db.scalars(
        select(Device).where(Device.organization_id == user.organization_id).order_by(
            Device.display_name, Device.device_id
        )
    ))


def get_device(db: Session, user: User, device_id: UUID) -> Device:
    device = db.scalar(select(Device).where(
        Device.device_id == device_id, Device.organization_id == user.organization_id
    ))
    if device is None:
        raise DeviceNotFoundError("device_not_found", "Device not found")
    return device


def update_device(
    db: Session, user: User, device_id: UUID, request: DeviceUpdate
) -> Device:
    device = get_device(db, user, device_id)
    for field, value in request.model_dump(exclude_unset=True).items():
        setattr(device, field, value)
    db.commit()
    db.refresh(device)
    return device
