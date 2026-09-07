from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, Enum as SqlEnum, ForeignKey, String, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.compliance.verdicts import FindingSeverity, FindingVerdict
from app.db.base import Base
from app.db.models.common import utc_now
from app.effective_state.contracts import UnresolvedReason


class Finding(Base):
    """Immutable canonical compliance result for one Audit rule/scope identity."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("audit_id", "comparison_key"),
        CheckConstraint("btrim(comparison_key) <> ''", name="ck_findings_comparison_key"),
        CheckConstraint("btrim(rule_id) <> ''", name="ck_findings_rule_id"),
        CheckConstraint("btrim(title) <> ''", name="ck_findings_title"),
        CheckConstraint("btrim(security_domain) <> ''", name="ck_findings_security_domain"),
        CheckConstraint("expected_state IS NULL OR jsonb_typeof(expected_state) = 'object'", name="ck_findings_expected_state"),
        CheckConstraint("observed_state IS NULL OR jsonb_typeof(observed_state) = 'object'", name="ck_findings_observed_state"),
        CheckConstraint("affected_scope IS NULL OR jsonb_typeof(affected_scope) = 'object'", name="ck_findings_affected_scope"),
        CheckConstraint("jsonb_typeof(effective_state_refs) = 'array'", name="ck_findings_effective_state_refs"),
        CheckConstraint("jsonb_typeof(evidence_refs) = 'array'", name="ck_findings_evidence_refs"),
        CheckConstraint("jsonb_typeof(framework_references) = 'array'", name="ck_findings_framework_references"),
        CheckConstraint(
            "(verdict = 'unknown' AND unknown_reason IS NOT NULL) OR "
            "(verdict <> 'unknown' AND unknown_reason IS NULL)",
            name="ck_findings_unknown_invariants",
        ),
    )

    finding_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    audit_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("audits.audit_id", ondelete="RESTRICT"), nullable=False, index=True)
    device_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("devices.device_id", ondelete="RESTRICT"), nullable=False, index=True)
    comparison_key: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    rule_pack_version_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    security_domain: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    verdict: Mapped[FindingVerdict] = mapped_column(SqlEnum(FindingVerdict, name="ck_findings_verdict", native_enum=False, create_constraint=True, validate_strings=True, values_callable=lambda enum: [item.value for item in enum], length=32), nullable=False, index=True)
    severity: Mapped[FindingSeverity] = mapped_column(SqlEnum(FindingSeverity, name="ck_findings_severity", native_enum=False, create_constraint=True, validate_strings=True, values_callable=lambda enum: [item.value for item in enum], length=32), nullable=False, index=True)
    expected_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    observed_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    explanation: Mapped[str] = mapped_column(String(2048), nullable=False)
    affected_scope: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    effective_state_refs: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    unknown_reason: Mapped[UnresolvedReason | None] = mapped_column(SqlEnum(UnresolvedReason, name="ck_findings_unknown_reason", native_enum=False, create_constraint=True, validate_strings=True, values_callable=lambda enum: [item.value for item in enum], length=32), nullable=True)
    framework_references: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    remediation_procedure_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0", server_default="1.0.0")
