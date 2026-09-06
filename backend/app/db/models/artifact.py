from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Enum as SqlEnum
from sqlalchemy import ForeignKey, String, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base import Base
from app.db.models.common import utc_now

if TYPE_CHECKING:
    from app.db.models.snapshot import Snapshot


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ArtifactContentFamily(str, Enum):
    TEXT = "text"
    JSON = "json"
    XML = "xml"
    UNKNOWN = "unknown"


class ArtifactEvidenceType(str, Enum):
    CONFIGURATION = "configuration"
    VERSION_OUTPUT = "version_output"
    INVENTORY_OUTPUT = "inventory_output"
    OPERATIONAL_OUTPUT = "operational_output"
    STRUCTURED_EXPORT = "structured_export"
    UNKNOWN_EVIDENCE = "unknown_evidence"


class ArtifactStatus(str, Enum):
    UPLOADED = "uploaded"
    VALIDATING = "validating"
    VALIDATED = "validated"
    READY = "ready"
    PARTIALLY_SUPPORTED = "partially_supported"
    NEEDS_REVIEW = "needs_review"
    REJECTED = "rejected"


class Artifact(Base):
    """Immutable evidence metadata and abstraction-owned storage reference."""

    __tablename__ = "artifacts"
    __table_args__ = (
        CheckConstraint("byte_size >= 0", name="ck_artifacts_byte_size"),
        CheckConstraint(
            "sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_artifacts_sha256",
        ),
        CheckConstraint(
            "jsonb_typeof(validation_issues) = 'array'",
            name="ck_artifacts_validation_issues",
        ),
        CheckConstraint(
            "jsonb_typeof(source_metadata) = 'object'",
            name="ck_artifacts_source_metadata",
        ),
    )

    artifact_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organizations.organization_id", ondelete="RESTRICT"),
        nullable=False, index=True,
    )
    snapshot_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("snapshots.snapshot_id", ondelete="RESTRICT"),
        nullable=True, index=True,
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_reference: Mapped[str] = mapped_column(String(500), nullable=False)
    byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    mime_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    encoding: Mapped[str | None] = mapped_column(String(100), nullable=True)
    content_family: Mapped[ArtifactContentFamily] = mapped_column(
        SqlEnum(ArtifactContentFamily, name="ck_artifacts_content_family", native_enum=False,
                create_constraint=True, validate_strings=True,
                values_callable=lambda enum: [member.value for member in enum], length=32),
        nullable=False,
    )
    evidence_type: Mapped[ArtifactEvidenceType] = mapped_column(
        SqlEnum(ArtifactEvidenceType, name="ck_artifacts_evidence_type", native_enum=False,
                create_constraint=True, validate_strings=True,
                values_callable=lambda enum: [member.value for member in enum], length=32),
        nullable=False,
    )
    status: Mapped[ArtifactStatus] = mapped_column(
        SqlEnum(ArtifactStatus, name="ck_artifacts_status", native_enum=False,
                create_constraint=True, validate_strings=True,
                values_callable=lambda enum: [member.value for member in enum], length=32),
        nullable=False, default=ArtifactStatus.UPLOADED, server_default=ArtifactStatus.UPLOADED.value,
    )
    validation_issues: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    source_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    uploaded_by: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.user_id", ondelete="RESTRICT"),
        nullable=True, index=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    schema_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0.0", server_default="1.0.0"
    )

    snapshot: Mapped[Snapshot | None] = relationship(back_populates="artifacts")

    @validates("sha256")
    def normalize_sha256(self, _key: str, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("Artifact sha256 must be 64 lowercase hexadecimal characters")
        return normalized
