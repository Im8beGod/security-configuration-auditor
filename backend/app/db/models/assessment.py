from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.common import utc_now


class AssessmentPackVersion(Base):
    """Immutable, framework-neutral assessment scope metadata."""

    __tablename__ = "assessment_pack_versions"
    __table_args__ = (
        UniqueConstraint("organization_id", "pack_key", "version"),
        CheckConstraint("version > 0", name="ck_assessment_pack_versions_version_positive"),
        CheckConstraint("status IN ('available','published','retired')", name="ck_assessment_pack_versions_status"),
    )

    assessment_pack_version_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=True, index=True)
    pack_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    family: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    profile_version_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    source_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    source_version_label: Mapped[str] = mapped_column(String(255), nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    applicability: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="published", server_default="published", index=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0", server_default="1.0.0")


class AssessmentObligation(Base):
    """One immutable obligation within an AssessmentPackVersion."""

    __tablename__ = "assessment_obligations"
    __table_args__ = (UniqueConstraint("assessment_pack_version_id", "obligation_key"),)

    assessment_obligation_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    assessment_pack_version_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("assessment_pack_versions.assessment_pack_version_id", ondelete="RESTRICT"), nullable=False, index=True)
    obligation_key: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    applicability: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    assessment_method: Mapped[str] = mapped_column(String(16), nullable=False)
    implementation_status: Mapped[str] = mapped_column(String(16), nullable=False)
    evaluator_rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    policy_parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    source_reference: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class AuditAssessment(Base):
    """Exact assessment scope pinned to one immutable Audit."""

    __tablename__ = "audit_assessments"
    audit_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("audits.audit_id", ondelete="RESTRICT"), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False, index=True)
    assessment_pack_version_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("assessment_pack_versions.assessment_pack_version_id", ondelete="RESTRICT"), nullable=False, index=True)
    profile_version_id: Mapped[str] = mapped_column(String(255), nullable=False)
    pinned_identity: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class AssessmentResult(Base):
    """One deterministic result per audit obligation identity."""

    __tablename__ = "assessment_results"
    __table_args__ = (UniqueConstraint("audit_id", "result_identity"),)

    assessment_result_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    audit_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("audits.audit_id", ondelete="RESTRICT"), nullable=False, index=True)
    organization_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False, index=True)
    assessment_obligation_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("assessment_obligations.assessment_obligation_id", ondelete="RESTRICT"), nullable=False, index=True)
    technical_finding_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("findings.finding_id", ondelete="RESTRICT"), nullable=True)
    result_identity: Mapped[str] = mapped_column(String(512), nullable=False)
    applicability_status: Mapped[str] = mapped_column(String(32), nullable=False)
    assessment_method: Mapped[str] = mapped_column(String(16), nullable=False)
    implementation_status: Mapped[str] = mapped_column(String(16), nullable=False)
    verdict: Mapped[str | None] = mapped_column(String(16), nullable=True)
    policy_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    result_details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
