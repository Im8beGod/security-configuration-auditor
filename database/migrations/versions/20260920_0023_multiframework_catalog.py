"""Add normalized catalog provenance and multi-framework audit pins."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260920_0023"
down_revision: str | Sequence[str] | None = "20260920_0022"
branch_labels = depends_on = None


def upgrade() -> None:
    for name, length in (("framework_version", 128), ("source_url", 2048), ("source_digest", 128), ("control_id", 255), ("severity", 32), ("scope", 512)):
        op.add_column("assessment_obligations", sa.Column(name, sa.String(length), nullable=True))
    op.execute("ALTER TABLE assessment_obligations DISABLE TRIGGER trg_assessment_obligations_immutable")
    op.execute(sa.text("""
        UPDATE assessment_obligations AS obligation
        SET framework_version = COALESCE(obligation.source_reference->>'catalog_version', obligation.source_reference->>'version', obligation.source_reference->>'iso_reference', pack.source_version_label),
            source_url = COALESCE(obligation.source_reference->>'official_source_url', obligation.source_reference->>'source_url', obligation.source_reference->>'iso_open_data_url', 'source unavailable'),
            source_digest = COALESCE(obligation.source_reference->>'source_sha256', obligation.source_reference->>'olir_sha3_256', pack.content_digest),
            control_id = COALESCE(obligation.source_reference->>'control_id', obligation.source_reference->>'v_number', obligation.source_reference->>'recommendation_id', obligation.source_reference->>'iso_annex_a_control_id', obligation.obligation_key),
            severity = COALESCE(obligation.source_reference->>'severity', 'not_assigned'),
            scope = COALESCE(obligation.source_reference->>'scope', pack.source_metadata->>'scope', obligation.applicability->>'scope_note', 'device configuration')
        FROM assessment_pack_versions AS pack
        WHERE pack.assessment_pack_version_id = obligation.assessment_pack_version_id
    """))
    for name in ("framework_version", "source_url", "source_digest", "control_id", "severity", "scope"):
        op.alter_column("assessment_obligations", name, nullable=False)
    op.execute("ALTER TABLE assessment_obligations ENABLE TRIGGER trg_assessment_obligations_immutable")
    op.create_table(
        "audit_framework_assessments",
        sa.Column("audit_framework_assessment_id", sa.Uuid(), primary_key=True),
        sa.Column("audit_id", sa.Uuid(), sa.ForeignKey("audits.audit_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("assessment_pack_version_id", sa.Uuid(), sa.ForeignKey("assessment_pack_versions.assessment_pack_version_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("profile_version_id", sa.String(255), nullable=False),
        sa.Column("pinned_identity", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("audit_id", "assessment_pack_version_id"),
    )
    op.create_index(op.f("ix_audit_framework_assessments_audit_id"), "audit_framework_assessments", ["audit_id"])
    op.create_index(op.f("ix_audit_framework_assessments_organization_id"), "audit_framework_assessments", ["organization_id"])
    op.create_index(op.f("ix_audit_framework_assessments_assessment_pack_version_id"), "audit_framework_assessments", ["assessment_pack_version_id"])


def downgrade() -> None:
    op.drop_table("audit_framework_assessments")
    for name in reversed(("framework_version", "source_url", "source_digest", "control_id", "severity", "scope")):
        op.drop_column("assessment_obligations", name)
