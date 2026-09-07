"""Add canonical Finding persistence.

Revision ID: 20260907_0007
Revises: 20260907_0006
Create Date: 2026-09-07
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260907_0007"
down_revision: str | Sequence[str] | None = "20260907_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("audit_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("comparison_key", sa.String(length=1024), nullable=False),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("rule_pack_version_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("security_domain", sa.String(length=128), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("expected_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("observed_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("explanation", sa.String(length=2048), nullable=False),
        sa.Column("affected_scope", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("effective_state_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("evidence_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("unknown_reason", sa.String(length=32), nullable=True),
        sa.Column("framework_references", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("remediation_procedure_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.String(length=32), server_default="1.0.0", nullable=False),
        sa.CheckConstraint("btrim(comparison_key) <> ''", name=op.f("ck_findings_comparison_key")),
        sa.CheckConstraint("btrim(rule_id) <> ''", name=op.f("ck_findings_rule_id")),
        sa.CheckConstraint("btrim(title) <> ''", name=op.f("ck_findings_title")),
        sa.CheckConstraint("btrim(security_domain) <> ''", name=op.f("ck_findings_security_domain")),
        sa.CheckConstraint("expected_state IS NULL OR jsonb_typeof(expected_state) = 'object'", name=op.f("ck_findings_expected_state")),
        sa.CheckConstraint("observed_state IS NULL OR jsonb_typeof(observed_state) = 'object'", name=op.f("ck_findings_observed_state")),
        sa.CheckConstraint("affected_scope IS NULL OR jsonb_typeof(affected_scope) = 'object'", name=op.f("ck_findings_affected_scope")),
        sa.CheckConstraint("jsonb_typeof(effective_state_refs) = 'array'", name=op.f("ck_findings_effective_state_refs")),
        sa.CheckConstraint("jsonb_typeof(evidence_refs) = 'array'", name=op.f("ck_findings_evidence_refs")),
        sa.CheckConstraint("jsonb_typeof(framework_references) = 'array'", name=op.f("ck_findings_framework_references")),
        sa.CheckConstraint("verdict IN ('pass', 'fail', 'unknown', 'manual_review', 'not_applicable', 'process_error')", name=op.f("ck_findings_verdict")),
        sa.CheckConstraint("severity IN ('critical', 'high', 'medium', 'low', 'informational')", name=op.f("ck_findings_severity")),
        sa.CheckConstraint("unknown_reason IS NULL OR unknown_reason IN ('unknown_syntax', 'unknown_semantics', 'missing_evidence', 'unsupported_feature', 'ambiguous_scope', 'unresolved_default', 'conflicting_evidence', 'unsupported_version', 'unsupported_profile')", name=op.f("ck_findings_unknown_reason")),
        sa.CheckConstraint("(verdict = 'unknown' AND unknown_reason IS NOT NULL) OR (verdict <> 'unknown' AND unknown_reason IS NULL)", name=op.f("ck_findings_unknown_invariants")),
        sa.ForeignKeyConstraint(["audit_id"], ["audits.audit_id"], name=op.f("fk_findings_audit_id_audits"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.device_id"], name=op.f("fk_findings_device_id_devices"), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("finding_id", name=op.f("pk_findings")),
        sa.UniqueConstraint("audit_id", "comparison_key", name=op.f("uq_findings_audit_id")),
    )
    for name, column in (("audit_id", "audit_id"), ("device_id", "device_id"), ("verdict", "verdict"), ("severity", "severity"), ("rule_id", "rule_id"), ("comparison_key", "comparison_key"), ("security_domain", "security_domain")):
        op.create_index(op.f(f"ix_findings_{name}"), "findings", [column])


def downgrade() -> None:
    for name in ("security_domain", "comparison_key", "rule_id", "severity", "verdict", "device_id", "audit_id"):
        op.drop_index(op.f(f"ix_findings_{name}"), table_name="findings")
    op.drop_table("findings")
