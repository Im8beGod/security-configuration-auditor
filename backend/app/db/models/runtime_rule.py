from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.common import utc_now


class RuntimeRuleVersion(Base):
    __tablename__ = "runtime_rule_versions"
    __table_args__ = (
        UniqueConstraint("organization_id", "rule_id", "version"),
        CheckConstraint("version > 0", name="ck_runtime_rule_versions_version_positive"),
        CheckConstraint("status IN ('published','retired')", name="ck_runtime_rule_versions_status"),
    )

    runtime_rule_version_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    profile_version_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    canonical_field: Mapped[str] = mapped_column(String(255), nullable=False)
    operator: Mapped[str] = mapped_column(String(64), nullable=False)
    condition: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    required_policy_parameters: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    security_domain: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    framework_references: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="published", server_default="published", index=True)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0", server_default="1.0.0")
