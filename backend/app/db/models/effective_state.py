from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, Enum as SqlEnum, ForeignKey, String, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.common import utc_now
from app.effective_state.contracts import ResolutionStatus, UnresolvedReason


class EffectiveState(Base):
    """One canonical resolved-or-unknown state for an Audit field and scope."""

    __tablename__ = "effective_states"
    __table_args__ = (
        UniqueConstraint("audit_id", "field_id", "scope_key"),
        CheckConstraint("btrim(field_id) <> ''", name="ck_effective_states_field_id"),
        CheckConstraint("btrim(scope_key) <> ''", name="ck_effective_states_scope_key"),
        CheckConstraint("jsonb_typeof(scope) = 'object'", name="ck_effective_states_scope"),
        CheckConstraint(
            "effective_value IS NULL OR jsonb_typeof(effective_value) = 'object'",
            name="ck_effective_states_effective_value",
        ),
        CheckConstraint(
            "jsonb_typeof(source_fact_ids) = 'array'",
            name="ck_effective_states_source_fact_ids",
        ),
        CheckConstraint(
            "jsonb_typeof(resolution_trace) = 'array'",
            name="ck_effective_states_resolution_trace",
        ),
        CheckConstraint(
            "inherited_from IS NULL OR jsonb_typeof(inherited_from) = 'object'",
            name="ck_effective_states_inherited_from",
        ),
        CheckConstraint(
            "jsonb_typeof(referenced_objects) = 'array'",
            name="ck_effective_states_referenced_objects",
        ),
        CheckConstraint(
            "jsonb_typeof(precedence_applied) = 'array'",
            name="ck_effective_states_precedence_applied",
        ),
        CheckConstraint(
            "(resolution_status = 'resolved' AND effective_value IS NOT NULL "
            "AND unresolved_reason IS NULL) OR "
            "(resolution_status = 'unknown' AND effective_value IS NULL "
            "AND unresolved_reason IS NOT NULL AND unresolved_reason <> 'conflicting_evidence') OR "
            "(resolution_status = 'conflicting' AND effective_value IS NULL "
            "AND unresolved_reason = 'conflicting_evidence')",
            name="ck_effective_states_resolution_invariants",
        ),
    )

    effective_state_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    audit_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("audits.audit_id", ondelete="RESTRICT"),
        nullable=False, index=True,
    )
    device_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("devices.device_id", ondelete="RESTRICT"),
        nullable=False, index=True,
    )
    field_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    scope_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    effective_value: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB(none_as_null=True), nullable=True
    )
    resolution_status: Mapped[ResolutionStatus] = mapped_column(
        SqlEnum(
            ResolutionStatus, name="ck_effective_states_resolution_status",
            native_enum=False, create_constraint=True, validate_strings=True,
            values_callable=lambda enum: [member.value for member in enum], length=16,
        ), nullable=False,
    )
    source_fact_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    resolution_trace: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    inherited_from: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB(none_as_null=True), nullable=True
    )
    default_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    referenced_objects: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    precedence_applied: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    unresolved_reason: Mapped[UnresolvedReason | None] = mapped_column(
        SqlEnum(
            UnresolvedReason, name="ck_effective_states_unresolved_reason",
            native_enum=False, create_constraint=True, validate_strings=True,
            values_callable=lambda enum: [member.value for member in enum], length=32,
        ), nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    schema_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0.0", server_default="1.0.0"
    )
