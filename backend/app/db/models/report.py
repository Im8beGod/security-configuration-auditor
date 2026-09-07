from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, Enum as SqlEnum, ForeignKey, Integer, String, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.common import utc_now


class ReportStatus(str, Enum):
    PENDING = "pending"
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"


class Report(Base):
    """Immutable generated representation of a single persisted audit."""
    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint("report_type = 'device_compliance'", name="ck_reports_report_type"),
        CheckConstraint("format = 'pdf'", name="ck_reports_format"),
        CheckConstraint("byte_size IS NULL OR byte_size >= 0", name="ck_reports_byte_size"),
        CheckConstraint("sha256 IS NULL OR char_length(sha256) = 64", name="ck_reports_sha256"),
    )
    report_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False, index=True)
    device_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("devices.device_id", ondelete="RESTRICT"), nullable=False, index=True)
    audit_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("audits.audit_id", ondelete="RESTRICT"), nullable=False, index=True)
    report_type: Mapped[str] = mapped_column(String(32), nullable=False, default="device_compliance", server_default="device_compliance")
    format: Mapped[str] = mapped_column(String(16), nullable=False, default="pdf", server_default="pdf")
    status: Mapped[ReportStatus] = mapped_column(SqlEnum(ReportStatus, name="ck_reports_status", native_enum=False, create_constraint=True, validate_strings=True, values_callable=lambda enum: [item.value for item in enum], length=16), nullable=False, default=ReportStatus.PENDING, server_default=ReportStatus.PENDING.value, index=True)
    storage_reference: Mapped[str | None] = mapped_column(String(1024))
    sha256: Mapped[str | None] = mapped_column(String(64))
    byte_size: Mapped[int | None] = mapped_column(Integer)
    template_version: Mapped[str] = mapped_column(String(32), nullable=False)
    generator_version: Mapped[str] = mapped_column(String(32), nullable=False)
    audit_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    source_finding_ids: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    generated_by: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.user_id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(String(64))
    failure_message: Mapped[str | None] = mapped_column(String(1000))
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0", server_default="1.0.0")
