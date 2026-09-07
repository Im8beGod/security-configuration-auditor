from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, Enum as SqlEnum, ForeignKey, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.common import utc_now


class UnresolvedReviewStatus(str, Enum):
    OPEN = "open"
    UNDER_REVIEW = "under_review"
    MAPPED = "mapped"
    DISMISSED = "dismissed"
    NOT_ACTIONABLE = "not_actionable"


class MappingStatus(str, Enum):
    SUGGESTED = "suggested"
    DRAFT = "draft"
    TESTING = "testing"
    APPROVED = "approved"
    PUBLISHED = "published"
    SUPERSEDED = "superseded"
    REJECTED = "rejected"


class MappingOrigin(str, Enum):
    BUILT_IN = "built_in"
    ADMINISTRATOR = "administrator"
    AI_ASSISTED = "ai_assisted"


class ValidationRunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"


class UnresolvedBlock(Base):
    __tablename__ = "unresolved_blocks"
    __table_args__ = (
        CheckConstraint("char_length(raw_text) <= 2048", name="ck_unresolved_blocks_raw_text_bounded"),
        CheckConstraint("char_length(surrounding_context) <= 4096", name="ck_unresolved_blocks_context_bounded"),
        CheckConstraint("char_length(fingerprint) = 64", name="ck_unresolved_blocks_fingerprint"),
        UniqueConstraint("audit_id", "fingerprint"),
    )

    unresolved_block_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False, index=True)
    audit_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("audits.audit_id", ondelete="RESTRICT"), nullable=False, index=True)
    device_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("devices.device_id", ondelete="RESTRICT"), nullable=False, index=True)
    snapshot_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("snapshots.snapshot_id", ondelete="RESTRICT"), nullable=False, index=True)
    profile_id: Mapped[str | None] = mapped_column(String(255))
    profile_version_id: Mapped[str | None] = mapped_column(String(255))
    source_ir_node_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    raw_text: Mapped[str] = mapped_column(String(2048), nullable=False)
    surrounding_context: Mapped[str] = mapped_column(String(4096), nullable=False, default="")
    unknown_reason: Mapped[str] = mapped_column(String(128), nullable=False)
    candidate_field_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    affected_rule_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    occurrence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    review_status: Mapped[UnresolvedReviewStatus] = mapped_column(SqlEnum(UnresolvedReviewStatus, name="ck_unresolved_blocks_review_status", native_enum=False, create_constraint=True, validate_strings=True, values_callable=lambda enum: [item.value for item in enum], length=32), nullable=False, default=UnresolvedReviewStatus.OPEN, server_default=UnresolvedReviewStatus.OPEN.value, index=True)
    assigned_mapping_version_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("mapping_versions.mapping_version_id", ondelete="RESTRICT"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0", server_default="1.0.0")


class MappingVersion(Base):
    __tablename__ = "mapping_versions"
    __table_args__ = (
        UniqueConstraint("mapping_id", "version"),
        CheckConstraint("version > 0", name="ck_mapping_versions_version_positive"),
    )

    mapping_version_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    mapping_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    organization_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False, index=True)
    mapping_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    previous_mapping_version_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("mapping_versions.mapping_version_id", ondelete="RESTRICT"))
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[MappingStatus] = mapped_column(SqlEnum(MappingStatus, name="ck_mapping_versions_status", native_enum=False, create_constraint=True, validate_strings=True, values_callable=lambda enum: [item.value for item in enum], length=32), nullable=False, index=True)
    profile_applicability: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    structural_match: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    target_field_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    value_extraction: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    unit_conversion: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    scope_resolution: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    negation_behavior: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    removal_behavior: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    default_behavior: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    examples: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    validation_results: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    origin: Mapped[MappingOrigin] = mapped_column(SqlEnum(MappingOrigin, name="ck_mapping_versions_origin", native_enum=False, create_constraint=True, validate_strings=True, values_callable=lambda enum: [item.value for item in enum], length=32), nullable=False)
    ai_suggestion_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_by: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.user_id", ondelete="RESTRICT"))
    approved_by: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.user_id", ondelete="RESTRICT"))
    knowledge_pack_version_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("knowledge_pack_versions.knowledge_pack_version_id", ondelete="RESTRICT"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0", server_default="1.0.0")


class MappingValidationRun(Base):
    __tablename__ = "mapping_validation_runs"
    validation_run_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False, index=True)
    mapping_version_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("mapping_versions.mapping_version_id", ondelete="RESTRICT"), nullable=False, index=True)
    status: Mapped[ValidationRunStatus] = mapped_column(SqlEnum(ValidationRunStatus, name="ck_mapping_validation_runs_status", native_enum=False, create_constraint=True, validate_strings=True, values_callable=lambda enum: [item.value for item in enum], length=16), nullable=False, default=ValidationRunStatus.PENDING, server_default=ValidationRunStatus.PENDING.value)
    results: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0", server_default="1.0.0")


class KnowledgePackRecord(Base):
    __tablename__ = "knowledge_packs"
    knowledge_pack_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False, index=True)
    pack_key: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0", server_default="1.0.0")
    __table_args__ = (UniqueConstraint("organization_id", "pack_key"),)


class KnowledgePackVersionRecord(Base):
    __tablename__ = "knowledge_pack_versions"
    __table_args__ = (UniqueConstraint("knowledge_pack_id", "version"), CheckConstraint("version > 0", name="ck_knowledge_pack_versions_version_positive"))
    knowledge_pack_version_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    knowledge_pack_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("knowledge_packs.knowledge_pack_id", ondelete="RESTRICT"), nullable=False, index=True)
    organization_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    previous_knowledge_pack_version_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("knowledge_pack_versions.knowledge_pack_version_id", ondelete="RESTRICT"))
    mapping_version_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    published_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.user_id", ondelete="RESTRICT"), nullable=False)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0", server_default="1.0.0")
