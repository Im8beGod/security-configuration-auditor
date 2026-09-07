"""Add immutable report persistence."""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260907_0010"
down_revision: str | Sequence[str] | None = "20260907_0009"
branch_labels = depends_on = None


def upgrade() -> None:
    op.create_table("reports", sa.Column("report_id", sa.Uuid(), primary_key=True), sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False), sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.device_id", ondelete="RESTRICT"), nullable=False), sa.Column("audit_id", sa.Uuid(), sa.ForeignKey("audits.audit_id", ondelete="RESTRICT"), nullable=False), sa.Column("report_type", sa.String(32), nullable=False, server_default="device_compliance"), sa.Column("format", sa.String(16), nullable=False, server_default="pdf"), sa.Column("status", sa.String(16), nullable=False, server_default="pending"), sa.Column("storage_reference", sa.String(1024)), sa.Column("sha256", sa.String(64)), sa.Column("byte_size", sa.Integer()), sa.Column("template_version", sa.String(32), nullable=False), sa.Column("generator_version", sa.String(32), nullable=False), sa.Column("audit_schema_version", sa.String(32), nullable=False), sa.Column("source_finding_ids", postgresql.JSONB(), nullable=False), sa.Column("generated_by", sa.Uuid(), sa.ForeignKey("users.user_id", ondelete="RESTRICT")), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("generated_at", sa.DateTime(timezone=True)), sa.Column("failure_code", sa.String(64)), sa.Column("failure_message", sa.String(1000)), sa.Column("schema_version", sa.String(32), nullable=False, server_default="1.0.0"), sa.CheckConstraint("report_type = 'device_compliance'", name="ck_reports_report_type"), sa.CheckConstraint("format = 'pdf'", name="ck_reports_format"), sa.CheckConstraint("status IN ('pending','generating','ready','failed')", name="ck_reports_status"), sa.CheckConstraint("byte_size IS NULL OR byte_size >= 0", name="ck_reports_byte_size"), sa.CheckConstraint("sha256 IS NULL OR char_length(sha256) = 64", name="ck_reports_sha256"))
    for column in ("organization_id", "audit_id", "device_id", "status"):
        op.create_index(f"ix_reports_{column}", "reports", [column])


def downgrade() -> None:
    op.drop_table("reports")
