"""Add canonical EffectiveState persistence.

Revision ID: 20260907_0006
Revises: 20260907_0005
Create Date: 2026-09-07
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260907_0006"
down_revision: str | Sequence[str] | None = "20260907_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "effective_states",
        sa.Column("effective_state_id", sa.Uuid(), nullable=False),
        sa.Column("audit_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("field_id", sa.String(length=255), nullable=False),
        sa.Column("scope", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("scope_key", sa.String(length=1024), nullable=False),
        sa.Column("effective_value", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("resolution_status", sa.String(length=16), nullable=False),
        sa.Column("source_fact_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("resolution_trace", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("inherited_from", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("default_reference", sa.String(length=255), nullable=True),
        sa.Column("referenced_objects", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("precedence_applied", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("unresolved_reason", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "schema_version", sa.String(length=32), server_default="1.0.0", nullable=False
        ),
        sa.CheckConstraint("btrim(field_id) <> ''", name=op.f("ck_effective_states_field_id")),
        sa.CheckConstraint("btrim(scope_key) <> ''", name=op.f("ck_effective_states_scope_key")),
        sa.CheckConstraint("jsonb_typeof(scope) = 'object'", name=op.f("ck_effective_states_scope")),
        sa.CheckConstraint(
            "effective_value IS NULL OR jsonb_typeof(effective_value) = 'object'",
            name=op.f("ck_effective_states_effective_value"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(source_fact_ids) = 'array'",
            name=op.f("ck_effective_states_source_fact_ids"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(resolution_trace) = 'array'",
            name=op.f("ck_effective_states_resolution_trace"),
        ),
        sa.CheckConstraint(
            "inherited_from IS NULL OR jsonb_typeof(inherited_from) = 'object'",
            name=op.f("ck_effective_states_inherited_from"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(referenced_objects) = 'array'",
            name=op.f("ck_effective_states_referenced_objects"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(precedence_applied) = 'array'",
            name=op.f("ck_effective_states_precedence_applied"),
        ),
        sa.CheckConstraint(
            "(resolution_status = 'resolved' AND effective_value IS NOT NULL "
            "AND unresolved_reason IS NULL) OR "
            "(resolution_status = 'unknown' AND effective_value IS NULL "
            "AND unresolved_reason IS NOT NULL AND unresolved_reason <> 'conflicting_evidence') OR "
            "(resolution_status = 'conflicting' AND effective_value IS NULL "
            "AND unresolved_reason = 'conflicting_evidence')",
            name=op.f("ck_effective_states_resolution_invariants"),
        ),
        sa.CheckConstraint(
            "resolution_status IN ('resolved', 'unknown', 'conflicting')",
            name=op.f("ck_effective_states_resolution_status"),
        ),
        sa.CheckConstraint(
            "unresolved_reason IS NULL OR unresolved_reason IN ("
            "'unknown_syntax', 'unknown_semantics', 'missing_evidence', "
            "'unsupported_feature', 'ambiguous_scope', 'unresolved_default', "
            "'conflicting_evidence', 'unsupported_version', 'unsupported_profile')",
            name=op.f("ck_effective_states_unresolved_reason"),
        ),
        sa.ForeignKeyConstraint(
            ["audit_id"], ["audits.audit_id"],
            name=op.f("fk_effective_states_audit_id_audits"), ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.device_id"],
            name=op.f("fk_effective_states_device_id_devices"), ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("effective_state_id", name=op.f("pk_effective_states")),
        sa.UniqueConstraint(
            "audit_id", "field_id", "scope_key",
            name=op.f("uq_effective_states_audit_id"),
        ),
    )
    op.create_index(op.f("ix_effective_states_audit_id"), "effective_states", ["audit_id"])
    op.create_index(op.f("ix_effective_states_device_id"), "effective_states", ["device_id"])
    op.create_index(op.f("ix_effective_states_field_id"), "effective_states", ["field_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_effective_states_field_id"), table_name="effective_states")
    op.drop_index(op.f("ix_effective_states_device_id"), table_name="effective_states")
    op.drop_index(op.f("ix_effective_states_audit_id"), table_name="effective_states")
    op.drop_table("effective_states")
