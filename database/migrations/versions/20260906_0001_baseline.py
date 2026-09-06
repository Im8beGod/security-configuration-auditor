"""Establish the intentionally empty application migration baseline.

Revision ID: 20260906_0001
Revises:
Create Date: 2026-09-06
"""

from collections.abc import Sequence


revision: str = "20260906_0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create no schema because application ORM models do not exist yet."""

    pass


def downgrade() -> None:
    """Revert the no-op baseline without altering application schema."""

    pass
