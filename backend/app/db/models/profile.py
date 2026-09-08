from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String, Uuid, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.common import utc_now


class ProfileManifestVersion(Base):
    __tablename__ = "profile_manifest_versions"
    __table_args__ = (UniqueConstraint("organization_id", "profile_version_id"),)

    profile_manifest_version_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=True, index=True)
    profile_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    profile_version_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    manifest_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="published", server_default="published", index=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ProfileResolutionDecision(Base):
    __tablename__ = "profile_resolution_decisions"

    decision_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False, index=True)
    snapshot_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("snapshots.snapshot_id", ondelete="CASCADE"), nullable=False, index=True)
    audit_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("audits.audit_id", ondelete="CASCADE"), nullable=False, index=True)
    resolution_status: Mapped[str] = mapped_column(String(32), nullable=False)
    selected_profile_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    selected_profile_version_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    applicability_status: Mapped[str] = mapped_column(String(32), nullable=False)
    identity_provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    evidence_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
