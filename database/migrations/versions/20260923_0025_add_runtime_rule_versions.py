from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260923_0025"
down_revision = "20260922_0024"
branch_labels = depends_on = None


def upgrade() -> None:
    op.create_table(
        "runtime_rule_versions",
        sa.Column("runtime_rule_version_id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("rule_id", sa.String(255), nullable=False), sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("profile_version_ids", postgresql.JSONB(), nullable=False), sa.Column("canonical_field", sa.String(255), nullable=False),
        sa.Column("operator", sa.String(64), nullable=False), sa.Column("condition", postgresql.JSONB(), nullable=False),
        sa.Column("required_policy_parameters", postgresql.JSONB(), nullable=False), sa.Column("title", sa.String(255), nullable=False),
        sa.Column("security_domain", sa.String(128), nullable=False), sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("framework_references", postgresql.JSONB(), nullable=False), sa.Column("content_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="published"), sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("schema_version", sa.String(32), nullable=False, server_default="1.0.0"),
        sa.UniqueConstraint("organization_id", "rule_id", "version"),
        sa.CheckConstraint("version > 0", name="ck_runtime_rule_versions_version_positive"),
        sa.CheckConstraint("status IN ('published','retired')", name="ck_runtime_rule_versions_status"),
    )
    op.create_index("ix_runtime_rule_versions_organization_id", "runtime_rule_versions", ["organization_id"])
    op.create_index("ix_runtime_rule_versions_rule_id", "runtime_rule_versions", ["rule_id"])
    op.create_index("ix_runtime_rule_versions_status", "runtime_rule_versions", ["status"])


def downgrade() -> None:
    op.drop_table("runtime_rule_versions")
