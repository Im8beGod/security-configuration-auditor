from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, Enum as SqlEnum, ForeignKey, String, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.common import utc_now


class FactState(str, Enum):
    EXPLICIT = "explicit"
    INHERITED = "inherited"
    DOCUMENTED_DEFAULT = "documented_default"
    DERIVED = "derived"
    UNKNOWN = "unknown"
    CONFLICTING = "conflicting"


class InterpretationMethod(str, Enum):
    DECLARATIVE_MAPPING = "declarative_mapping"
    DOCUMENTED_DEFAULT = "documented_default"
    DETERMINISTIC_DERIVATION = "deterministic_derivation"
    ADMINISTRATOR_VALIDATED_MAPPING = "administrator_validated_mapping"


class FactValidationStatus(str, Enum):
    VALIDATED = "validated"
    ADMINISTRATOR_VALIDATED = "administrator_validated"
    UNRESOLVED = "unresolved"
    CONFLICTING = "conflicting"


class InterpretationConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNRESOLVED = "unresolved"


class SecurityFact(Base):
    """Immutable canonical meaning extracted for one Audit revision."""

    __tablename__ = "security_facts"
    __table_args__ = (
        CheckConstraint("btrim(field_id) <> ''", name="ck_security_facts_field_id"),
        CheckConstraint("jsonb_typeof(value) = 'object'", name="ck_security_facts_value"),
        CheckConstraint("jsonb_typeof(scope) = 'object'", name="ck_security_facts_scope"),
        CheckConstraint(
            "jsonb_typeof(evidence_refs) = 'array'",
            name="ck_security_facts_evidence_refs",
        ),
        CheckConstraint(
            "jsonb_typeof(source_ir_node_ids) = 'array'",
            name="ck_security_facts_source_ir_node_ids",
        ),
        CheckConstraint(
            "jsonb_typeof(dependencies) = 'array'",
            name="ck_security_facts_dependencies",
        ),
    )

    fact_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    audit_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("audits.audit_id", ondelete="RESTRICT"),
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
    field_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    entity: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    state: Mapped[FactState] = mapped_column(
        SqlEnum(
            FactState, name="ck_security_facts_state", native_enum=False,
            create_constraint=True, validate_strings=True,
            values_callable=lambda enum: [member.value for member in enum], length=32,
        ),
        nullable=False,
    )
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    source_ir_node_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    extraction_method: Mapped[InterpretationMethod] = mapped_column(
        SqlEnum(
            InterpretationMethod, name="ck_security_facts_extraction_method",
            native_enum=False, create_constraint=True, validate_strings=True,
            values_callable=lambda enum: [member.value for member in enum], length=40,
        ),
        nullable=False,
    )
    mapping_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    mapping_version_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), nullable=True, index=True
    )
    knowledge_pack_version_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), nullable=False, index=True
    )
    validation_status: Mapped[FactValidationStatus] = mapped_column(
        SqlEnum(
            FactValidationStatus, name="ck_security_facts_validation_status",
            native_enum=False, create_constraint=True, validate_strings=True,
            values_callable=lambda enum: [member.value for member in enum], length=32,
        ),
        nullable=False,
    )
    dependencies: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    interpretation_confidence: Mapped[InterpretationConfidence] = mapped_column(
        SqlEnum(
            InterpretationConfidence, name="ck_security_facts_interpretation_confidence",
            native_enum=False, create_constraint=True, validate_strings=True,
            values_callable=lambda enum: [member.value for member in enum], length=32,
        ),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    schema_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0.0", server_default="1.0.0"
    )
