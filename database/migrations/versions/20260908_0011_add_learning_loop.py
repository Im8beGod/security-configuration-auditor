"""Add administrator-supervised mapping learning loop."""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260908_0011"
down_revision: str | Sequence[str] | None = "20260907_0010"
branch_labels = depends_on = None


def upgrade() -> None:
    op.create_table(
        "knowledge_packs",
        sa.Column("knowledge_pack_id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("pack_key", sa.String(255), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False, server_default="1.0.0"),
        sa.UniqueConstraint("organization_id", "pack_key"),
    )
    op.create_index("ix_knowledge_packs_organization_id", "knowledge_packs", ["organization_id"])
    op.create_table(
        "knowledge_pack_versions",
        sa.Column("knowledge_pack_version_id", sa.Uuid(), primary_key=True),
        sa.Column("knowledge_pack_id", sa.Uuid(), sa.ForeignKey("knowledge_packs.knowledge_pack_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("previous_knowledge_pack_version_id", sa.Uuid(), sa.ForeignKey("knowledge_pack_versions.knowledge_pack_version_id", ondelete="RESTRICT")),
        sa.Column("mapping_version_ids", postgresql.JSONB(), nullable=False),
        sa.Column("published_by", sa.Uuid(), sa.ForeignKey("users.user_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False, server_default="1.0.0"),
        sa.CheckConstraint("version > 0", name="ck_knowledge_pack_versions_version_positive"),
        sa.UniqueConstraint("knowledge_pack_id", "version"),
    )
    op.create_index("ix_knowledge_pack_versions_knowledge_pack_id", "knowledge_pack_versions", ["knowledge_pack_id"])
    op.create_index("ix_knowledge_pack_versions_organization_id", "knowledge_pack_versions", ["organization_id"])
    op.create_table(
        "mapping_versions",
        sa.Column("mapping_version_id", sa.Uuid(), primary_key=True),
        sa.Column("mapping_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("mapping_key", sa.String(255), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("previous_mapping_version_id", sa.Uuid(), sa.ForeignKey("mapping_versions.mapping_version_id", ondelete="RESTRICT")),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.String(2048), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("profile_applicability", postgresql.JSONB(), nullable=False),
        sa.Column("structural_match", postgresql.JSONB(), nullable=False),
        sa.Column("target_field_id", sa.String(255), nullable=False),
        sa.Column("value_extraction", postgresql.JSONB(), nullable=False),
        sa.Column("unit_conversion", postgresql.JSONB(), nullable=False),
        sa.Column("scope_resolution", postgresql.JSONB(), nullable=False),
        sa.Column("negation_behavior", postgresql.JSONB(), nullable=False),
        sa.Column("removal_behavior", postgresql.JSONB(), nullable=False),
        sa.Column("default_behavior", postgresql.JSONB(), nullable=False),
        sa.Column("examples", postgresql.JSONB(), nullable=False),
        sa.Column("validation_results", postgresql.JSONB(), nullable=False),
        sa.Column("origin", sa.String(32), nullable=False),
        sa.Column("ai_suggestion_metadata", postgresql.JSONB()),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.user_id", ondelete="RESTRICT")),
        sa.Column("approved_by", sa.Uuid(), sa.ForeignKey("users.user_id", ondelete="RESTRICT")),
        sa.Column("knowledge_pack_version_id", sa.Uuid(), sa.ForeignKey("knowledge_pack_versions.knowledge_pack_version_id", ondelete="RESTRICT")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("schema_version", sa.String(32), nullable=False, server_default="1.0.0"),
        sa.CheckConstraint("version > 0", name="ck_mapping_versions_version_positive"),
        sa.CheckConstraint("status IN ('suggested','draft','testing','approved','published','superseded','rejected')", name="ck_mapping_versions_status"),
        sa.CheckConstraint("origin IN ('built_in','administrator','ai_assisted')", name="ck_mapping_versions_origin"),
        sa.UniqueConstraint("mapping_id", "version"),
    )
    for column in ("mapping_id", "organization_id", "mapping_key", "status", "target_field_id", "knowledge_pack_version_id"):
        op.create_index(f"ix_mapping_versions_{column}", "mapping_versions", [column])
    op.create_table(
        "unresolved_blocks",
        sa.Column("unresolved_block_id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("audit_id", sa.Uuid(), sa.ForeignKey("audits.audit_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.device_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), sa.ForeignKey("snapshots.snapshot_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("profile_id", sa.String(255)),
        sa.Column("profile_version_id", sa.String(255)),
        sa.Column("source_ir_node_ids", postgresql.JSONB(), nullable=False),
        sa.Column("evidence_refs", postgresql.JSONB(), nullable=False),
        sa.Column("raw_text", sa.String(2048), nullable=False),
        sa.Column("surrounding_context", sa.String(4096), nullable=False),
        sa.Column("unknown_reason", sa.String(128), nullable=False),
        sa.Column("candidate_field_ids", postgresql.JSONB(), nullable=False),
        sa.Column("affected_rule_ids", postgresql.JSONB(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("occurrence", postgresql.JSONB(), nullable=False),
        sa.Column("review_status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("assigned_mapping_version_id", sa.Uuid(), sa.ForeignKey("mapping_versions.mapping_version_id", ondelete="RESTRICT")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False, server_default="1.0.0"),
        sa.CheckConstraint("char_length(raw_text) <= 2048", name="ck_unresolved_blocks_raw_text_bounded"),
        sa.CheckConstraint("char_length(surrounding_context) <= 4096", name="ck_unresolved_blocks_context_bounded"),
        sa.CheckConstraint("char_length(fingerprint) = 64", name="ck_unresolved_blocks_fingerprint"),
        sa.CheckConstraint("review_status IN ('open','under_review','mapped','dismissed','not_actionable')", name="ck_unresolved_blocks_review_status"),
        sa.UniqueConstraint("audit_id", "fingerprint"),
    )
    for column in ("organization_id", "audit_id", "device_id", "snapshot_id", "fingerprint", "review_status", "assigned_mapping_version_id"):
        op.create_index(f"ix_unresolved_blocks_{column}", "unresolved_blocks", [column])
    op.create_table(
        "mapping_validation_runs",
        sa.Column("validation_run_id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("mapping_version_id", sa.Uuid(), sa.ForeignKey("mapping_versions.mapping_version_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("results", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("schema_version", sa.String(32), nullable=False, server_default="1.0.0"),
        sa.CheckConstraint("status IN ('pending','running','passed','failed')", name="ck_mapping_validation_runs_status"),
    )
    op.create_index("ix_mapping_validation_runs_organization_id", "mapping_validation_runs", ["organization_id"])
    op.create_index("ix_mapping_validation_runs_mapping_version_id", "mapping_validation_runs", ["mapping_version_id"])

    op.execute("""
        CREATE FUNCTION prevent_published_mapping_mutation() RETURNS trigger AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            IF OLD.status IN ('published', 'superseded') THEN
              RAISE EXCEPTION 'published mapping versions are immutable';
            END IF;
            RETURN OLD;
          END IF;
          IF OLD.status IN ('published', 'superseded') AND
             (to_jsonb(NEW) - 'status') IS DISTINCT FROM (to_jsonb(OLD) - 'status') THEN
            RAISE EXCEPTION 'published mapping versions are immutable';
          END IF;
          RETURN NEW;
        END; $$ LANGUAGE plpgsql
    """)
    op.execute("CREATE TRIGGER trg_mapping_versions_immutable BEFORE UPDATE OR DELETE ON mapping_versions FOR EACH ROW EXECUTE FUNCTION prevent_published_mapping_mutation()")
    op.execute("""
        CREATE FUNCTION prevent_knowledge_pack_version_mutation() RETURNS trigger AS $$
        BEGIN RAISE EXCEPTION 'knowledge pack versions are immutable'; END;
        $$ LANGUAGE plpgsql
    """)
    op.execute("CREATE TRIGGER trg_knowledge_pack_versions_immutable BEFORE UPDATE OR DELETE ON knowledge_pack_versions FOR EACH ROW EXECUTE FUNCTION prevent_knowledge_pack_version_mutation()")


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_knowledge_pack_versions_immutable ON knowledge_pack_versions")
    op.execute("DROP FUNCTION IF EXISTS prevent_knowledge_pack_version_mutation")
    op.execute("DROP TRIGGER IF EXISTS trg_mapping_versions_immutable ON mapping_versions")
    op.execute("DROP FUNCTION IF EXISTS prevent_published_mapping_mutation")
    op.drop_table("mapping_validation_runs")
    op.drop_table("unresolved_blocks")
    op.drop_table("mapping_versions")
    op.drop_table("knowledge_pack_versions")
    op.drop_table("knowledge_packs")
