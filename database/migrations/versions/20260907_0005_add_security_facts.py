"""Add canonical SecurityFact persistence.

Revision ID: 20260907_0005
Revises: 20260906_0004
Create Date: 2026-09-07
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260907_0005"
down_revision: str | Sequence[str] | None = "20260906_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "security_facts",
        sa.Column("fact_id", sa.Uuid(), nullable=False),
        sa.Column("audit_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("field_id", sa.String(length=255), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("entity", sa.String(length=255), nullable=True),
        sa.Column("scope", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("evidence_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("source_ir_node_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("extraction_method", sa.String(length=40), nullable=False),
        sa.Column("mapping_id", sa.Uuid(), nullable=True),
        sa.Column("mapping_version_id", sa.Uuid(), nullable=True),
        sa.Column("knowledge_pack_version_id", sa.Uuid(), nullable=False),
        sa.Column("validation_status", sa.String(length=32), nullable=False),
        sa.Column("dependencies", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("interpretation_confidence", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "schema_version", sa.String(length=32), server_default="1.0.0", nullable=False
        ),
        sa.CheckConstraint("btrim(field_id) <> ''", name=op.f("ck_security_facts_field_id")),
        sa.CheckConstraint(
            "jsonb_typeof(value) = 'object'", name=op.f("ck_security_facts_value")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(scope) = 'object'", name=op.f("ck_security_facts_scope")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(evidence_refs) = 'array'",
            name=op.f("ck_security_facts_evidence_refs"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(source_ir_node_ids) = 'array'",
            name=op.f("ck_security_facts_source_ir_node_ids"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(dependencies) = 'array'",
            name=op.f("ck_security_facts_dependencies"),
        ),
        sa.CheckConstraint(
            "state IN ('explicit', 'inherited', 'documented_default', 'derived', "
            "'unknown', 'conflicting')",
            name=op.f("ck_security_facts_state"),
        ),
        sa.CheckConstraint(
            "extraction_method IN ('declarative_mapping', 'documented_default', "
            "'deterministic_derivation', 'administrator_validated_mapping')",
            name=op.f("ck_security_facts_extraction_method"),
        ),
        sa.CheckConstraint(
            "validation_status IN ('validated', 'administrator_validated', "
            "'unresolved', 'conflicting')",
            name=op.f("ck_security_facts_validation_status"),
        ),
        sa.CheckConstraint(
            "interpretation_confidence IN ('high', 'medium', 'low', 'unresolved')",
            name=op.f("ck_security_facts_interpretation_confidence"),
        ),
        sa.ForeignKeyConstraint(
            ["audit_id"], ["audits.audit_id"],
            name=op.f("fk_security_facts_audit_id_audits"), ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.device_id"],
            name=op.f("fk_security_facts_device_id_devices"), ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id"], ["snapshots.snapshot_id"],
            name=op.f("fk_security_facts_snapshot_id_snapshots"), ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("fact_id", name=op.f("pk_security_facts")),
    )
    op.create_index(op.f("ix_security_facts_audit_id"), "security_facts", ["audit_id"])
    op.create_index(op.f("ix_security_facts_device_id"), "security_facts", ["device_id"])
    op.create_index(op.f("ix_security_facts_snapshot_id"), "security_facts", ["snapshot_id"])
    op.create_index(op.f("ix_security_facts_field_id"), "security_facts", ["field_id"])
    op.create_index(
        op.f("ix_security_facts_mapping_version_id"),
        "security_facts", ["mapping_version_id"],
    )
    op.create_index(
        op.f("ix_security_facts_knowledge_pack_version_id"),
        "security_facts", ["knowledge_pack_version_id"],
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_security_facts_knowledge_pack_version_id"), table_name="security_facts"
    )
    op.drop_index(op.f("ix_security_facts_mapping_version_id"), table_name="security_facts")
    op.drop_index(op.f("ix_security_facts_field_id"), table_name="security_facts")
    op.drop_index(op.f("ix_security_facts_snapshot_id"), table_name="security_facts")
    op.drop_index(op.f("ix_security_facts_device_id"), table_name="security_facts")
    op.drop_index(op.f("ix_security_facts_audit_id"), table_name="security_facts")
    op.drop_table("security_facts")
