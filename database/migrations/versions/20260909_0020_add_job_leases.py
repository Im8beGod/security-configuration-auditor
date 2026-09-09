"""Add bounded worker leases for durable job recovery."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision = "20260909_0020"
down_revision: str | Sequence[str] | None = "20260909_0019"
branch_labels = depends_on = None


def upgrade() -> None:
    op.add_column("jobs", sa.Column("lease_owner", sa.String(length=128), nullable=True))
    op.add_column("jobs", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("jobs", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_jobs_stale_recovery", "jobs", ["status", "lease_expires_at"])


def downgrade() -> None:
    op.drop_index("ix_jobs_stale_recovery", table_name="jobs")
    op.drop_column("jobs", "lease_expires_at")
    op.drop_column("jobs", "heartbeat_at")
    op.drop_column("jobs", "lease_owner")
