"""Add the PostgreSQL-backed durable jobs queue.

Revision ID: 20260906_0004
Revises: 20260906_0003
Create Date: 2026-09-06
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260906_0004"
down_revision: str | Sequence[str] | None = "20260906_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "jobs",
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("job_type", sa.String(length=32), nullable=False),
        sa.Column(
            "status", sa.String(length=32), server_default="queued", nullable=False
        ),
        sa.Column("stage", sa.String(length=100), nullable=True),
        sa.Column("progress", sa.Integer(), server_default="0", nullable=False),
        sa.Column("audit_id", sa.Uuid(), nullable=True),
        sa.Column("device_id", sa.Uuid(), nullable=True),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.String(length=1000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "attempt_count >= 0", name=op.f("ck_jobs_attempt_count")
        ),
        sa.CheckConstraint(
            "job_type IN ('audit', 're_evaluation', 'mapping_validation', "
            "'pdf_generation', 'bulk_report_generation', 'system_noop')",
            name=op.f("ck_jobs_job_type"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(payload) = 'object'", name=op.f("ck_jobs_payload")
        ),
        sa.CheckConstraint(
            "progress >= 0 AND progress <= 100", name=op.f("ck_jobs_progress")
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'processing', 'completed', 'failed')",
            name=op.f("ck_jobs_status"),
        ),
        sa.ForeignKeyConstraint(
            ["audit_id"],
            ["audits.audit_id"],
            name=op.f("fk_jobs_audit_id_audits"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.device_id"],
            name=op.f("fk_jobs_device_id_devices"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("job_id", name=op.f("pk_jobs")),
    )
    op.create_index(op.f("ix_jobs_audit_id"), "jobs", ["audit_id"], unique=False)
    op.create_index(op.f("ix_jobs_device_id"), "jobs", ["device_id"], unique=False)
    op.create_index(
        "ix_jobs_queue_claim",
        "jobs",
        ["status", "created_at", "job_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_jobs_queue_claim", table_name="jobs")
    op.drop_index(op.f("ix_jobs_device_id"), table_name="jobs")
    op.drop_index(op.f("ix_jobs_audit_id"), table_name="jobs")
    op.drop_table("jobs")
