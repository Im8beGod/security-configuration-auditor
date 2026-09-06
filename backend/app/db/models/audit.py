from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, Enum as SqlEnum, ForeignKey, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.common import utc_now

if TYPE_CHECKING:
    from app.db.models.device import Device
    from app.db.models.snapshot import Snapshot


class AuditReevaluationReason(str, Enum):
    INITIAL = "initial"
    KNOWLEDGE_PACK_UPDATE = "knowledge_pack_update"
    RULE_PACK_UPDATE = "rule_pack_update"
    POLICY_UPDATE = "policy_update"
    PROFILE_CORRECTION = "profile_correction"
    MANUAL_REEVALUATION = "manual_reevaluation"
    OTHER = "other"


class AuditStatus(str, Enum):
    DRAFT = "draft"
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    COMPLETED_WITH_UNKNOWNS = "completed_with_unknowns"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"


class AuditProcessingStage(str, Enum):
    VALIDATING = "validating"
    IDENTIFYING = "identifying"
    PARSING = "parsing"
    INTERPRETING = "interpreting"
    RESOLVING_STATE = "resolving_state"
    EVALUATING = "evaluating"
    FINALIZING = "finalizing"


class Audit(Base):
    """One immutable evaluation revision for exactly one snapshot."""

    __tablename__ = "audits"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "revision_number"),
        CheckConstraint("revision_number >= 1", name="ck_audits_revision_number"),
        CheckConstraint("jsonb_typeof(selected_frameworks) = 'array'", name="ck_audits_selected_frameworks"),
        CheckConstraint("jsonb_typeof(version_refs) = 'object'", name="ck_audits_version_refs"),
        CheckConstraint("jsonb_typeof(profile_resolution) = 'object'", name="ck_audits_profile_resolution"),
        CheckConstraint("jsonb_typeof(verdict_counts) = 'object'", name="ck_audits_verdict_counts"),
        CheckConstraint("jsonb_typeof(severity_counts) = 'object'", name="ck_audits_severity_counts"),
        CheckConstraint("jsonb_typeof(coverage) = 'object'", name="ck_audits_coverage"),
    )

    audit_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"),
        nullable=False, index=True,
    )
    device_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("devices.device_id", ondelete="RESTRICT"),
        nullable=False, index=True,
    )
    snapshot_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("snapshots.snapshot_id", ondelete="RESTRICT"),
        nullable=False, index=True,
    )
    audit_batch_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True, index=True)
    revision_number: Mapped[int] = mapped_column(Integer, nullable=False)
    previous_audit_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("audits.audit_id", ondelete="RESTRICT"), nullable=True
    )
    reevaluation_reason: Mapped[AuditReevaluationReason] = mapped_column(
        SqlEnum(AuditReevaluationReason, name="ck_audits_reevaluation_reason", native_enum=False,
                create_constraint=True, validate_strings=True,
                values_callable=lambda enum: [member.value for member in enum], length=32),
        nullable=False, default=AuditReevaluationReason.INITIAL,
        server_default=AuditReevaluationReason.INITIAL.value,
    )
    status: Mapped[AuditStatus] = mapped_column(
        SqlEnum(AuditStatus, name="ck_audits_status", native_enum=False,
                create_constraint=True, validate_strings=True,
                values_callable=lambda enum: [member.value for member in enum], length=32),
        nullable=False, default=AuditStatus.DRAFT, server_default=AuditStatus.DRAFT.value,
        index=True,
    )
    processing_stage: Mapped[AuditProcessingStage | None] = mapped_column(
        SqlEnum(AuditProcessingStage, name="ck_audits_processing_stage", native_enum=False,
                create_constraint=True, validate_strings=True,
                values_callable=lambda enum: [member.value for member in enum], length=32),
        nullable=True,
    )
    selected_frameworks: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    version_refs: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    profile_resolution: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    verdict_counts: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    severity_counts: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    coverage: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, index=True
    )
    created_by: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.user_id", ondelete="RESTRICT"), nullable=True
    )
    schema_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0.0", server_default="1.0.0"
    )

    device: Mapped[Device] = relationship(back_populates="audits")
    snapshot: Mapped[Snapshot] = relationship(back_populates="audits")
