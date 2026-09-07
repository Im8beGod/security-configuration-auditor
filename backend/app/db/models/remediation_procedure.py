from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, Enum as SqlEnum, ForeignKey, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.common import utc_now


class RemediationProcedureStatus(str, Enum):
    DRAFT = "draft"; REVIEWED = "reviewed"; VALIDATED = "validated"; PUBLISHED = "published"; SUPERSEDED = "superseded"


class RemediationProcedure(Base):
    __tablename__ = "remediation_procedures"
    __table_args__ = (UniqueConstraint("procedure_key", "version"), CheckConstraint("version > 0", name="ck_remediation_procedures_version_positive"))
    procedure_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    procedure_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    previous_procedure_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("remediation_procedures.procedure_id", ondelete="RESTRICT"))
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    security_objective: Mapped[str] = mapped_column(String(1024), nullable=False)
    description: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[RemediationProcedureStatus] = mapped_column(SqlEnum(RemediationProcedureStatus, native_enum=False, length=16), nullable=False, index=True)
    profile_applicability: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    prerequisites: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    safety_warnings: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    required_parameters: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    configuration_context: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    ordered_steps: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    verification_steps: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    rollback_steps: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    validation_results: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    source_references: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
