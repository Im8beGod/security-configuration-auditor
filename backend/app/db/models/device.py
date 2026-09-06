from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Enum as SqlEnum, ForeignKey, String, Uuid, true
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.common import utc_now

if TYPE_CHECKING:
    from app.db.models.audit import Audit
    from app.db.models.snapshot import Snapshot


class DeviceClass(str, Enum):
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    SASE = "sase"
    LOAD_BALANCER = "load_balancer"
    WIRELESS = "wireless"
    CLOUD_NETWORK_CONTROL = "cloud_network_control"
    VIRTUAL_NETWORK_DEVICE = "virtual_network_device"
    UNKNOWN = "unknown"
    OTHER = "other"


class DeviceIdentityStatus(str, Enum):
    IDENTIFIED = "identified"
    PARTIALLY_IDENTIFIED = "partially_identified"
    UNRESOLVED = "unresolved"
    MANUALLY_CONFIRMED = "manually_confirmed"


class Device(Base):
    """Logical device identity without historical configuration truth."""

    __tablename__ = "devices"

    device_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"),
        nullable=False, index=True,
    )
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    latest_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    stable_serial_number: Mapped[str | None] = mapped_column(String(255), nullable=True)
    asset_tag: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_class: Mapped[DeviceClass] = mapped_column(
        SqlEnum(DeviceClass, name="ck_devices_device_class", native_enum=False,
                create_constraint=True, validate_strings=True,
                values_callable=lambda enum: [member.value for member in enum], length=32),
        nullable=False, default=DeviceClass.UNKNOWN, server_default=DeviceClass.UNKNOWN.value,
    )
    identity_status: Mapped[DeviceIdentityStatus] = mapped_column(
        SqlEnum(DeviceIdentityStatus, name="ck_devices_identity_status", native_enum=False,
                create_constraint=True, validate_strings=True,
                values_callable=lambda enum: [member.value for member in enum], length=32),
        nullable=False, default=DeviceIdentityStatus.UNRESOLVED,
        server_default=DeviceIdentityStatus.UNRESOLVED.value,
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=true())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )
    schema_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0.0", server_default="1.0.0"
    )

    snapshots: Mapped[list[Snapshot]] = relationship(back_populates="device")
    audits: Mapped[list[Audit]] = relationship(back_populates="device")
