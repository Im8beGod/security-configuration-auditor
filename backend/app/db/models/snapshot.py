from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, Enum as SqlEnum, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base import Base
from app.db.models.common import utc_now

if TYPE_CHECKING:
    from app.db.models.artifact import Artifact
    from app.db.models.audit import Audit
    from app.db.models.device import Device


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class SnapshotStatus(str, Enum):
    DRAFT = "draft"
    READY = "ready"
    LOCKED = "locked"
    ARCHIVED = "archived"


class SnapshotGroupingStatus(str, Enum):
    AUTOMATIC = "automatic"
    MANUALLY_CONFIRMED = "manually_confirmed"
    NEEDS_REVIEW = "needs_review"


class SnapshotSource(str, Enum):
    UPLOAD = "upload"
    API = "api"
    COLLECTOR = "collector"
    IMPORT = "import"


class Snapshot(Base):
    """Complete supplied evidence boundary for one logical device."""

    __tablename__ = "snapshots"
    __table_args__ = (
        CheckConstraint("artifact_count >= 0", name="ck_snapshots_artifact_count"),
        CheckConstraint("snapshot_hash ~ '^[0-9a-f]{64}$'", name="ck_snapshots_snapshot_hash"),
    )

    snapshot_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    device_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("devices.device_id", ondelete="RESTRICT"),
        nullable=False, index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"),
        nullable=False, index=True,
    )
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    captured_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    status: Mapped[SnapshotStatus] = mapped_column(
        SqlEnum(SnapshotStatus, name="ck_snapshots_status", native_enum=False,
                create_constraint=True, validate_strings=True,
                values_callable=lambda enum: [member.value for member in enum], length=32),
        nullable=False, default=SnapshotStatus.DRAFT, server_default=SnapshotStatus.DRAFT.value,
        index=True,
    )
    grouping_status: Mapped[SnapshotGroupingStatus] = mapped_column(
        SqlEnum(SnapshotGroupingStatus, name="ck_snapshots_grouping_status", native_enum=False,
                create_constraint=True, validate_strings=True,
                values_callable=lambda enum: [member.value for member in enum], length=32),
        nullable=False,
    )
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    source: Mapped[SnapshotSource] = mapped_column(
        SqlEnum(SnapshotSource, name="ck_snapshots_source", native_enum=False,
                create_constraint=True, validate_strings=True,
                values_callable=lambda enum: [member.value for member in enum], length=32),
        nullable=False,
    )
    created_by: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.user_id", ondelete="RESTRICT"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    schema_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0.0", server_default="1.0.0"
    )

    device: Mapped[Device] = relationship(back_populates="snapshots")
    artifacts: Mapped[list[Artifact]] = relationship(back_populates="snapshot")
    audits: Mapped[list[Audit]] = relationship(back_populates="snapshot")

    @validates("snapshot_hash")
    def normalize_snapshot_hash(self, _key: str, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("Snapshot hash must be 64 lowercase hexadecimal characters")
        return normalized
