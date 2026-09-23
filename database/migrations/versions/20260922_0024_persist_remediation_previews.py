"""Persist validated remediation previews for immutable report rendering."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260922_0024"
down_revision: str | Sequence[str] | None = "20260920_0023"
branch_labels = depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("remediation_preview", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_check_constraint(
        "ck_findings_remediation_preview", "findings",
        "jsonb_typeof(remediation_preview) = 'object'",
    )


def downgrade() -> None:
    op.drop_constraint("ck_findings_remediation_preview", "findings")
    op.drop_column("findings", "remediation_preview")
