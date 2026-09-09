"""Close deferred profile schema drift."""

from collections.abc import Sequence

from alembic import op


revision = "20260909_0019"
down_revision: str | Sequence[str] | None = "20260909_0018"
branch_labels = depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_profile_manifest_versions_organization_id",
        "profile_manifest_versions",
        ["organization_id"],
    )
    op.drop_constraint(
        "fk_profile_resolution_decisions_snapshot_id_snapshots",
        "profile_resolution_decisions",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_profile_resolution_decisions_snapshot_id_snapshots",
        "profile_resolution_decisions",
        "snapshots",
        ["snapshot_id"],
        ["snapshot_id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_profile_resolution_decisions_snapshot_id_snapshots",
        "profile_resolution_decisions",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_profile_resolution_decisions_snapshot_id_snapshots",
        "profile_resolution_decisions",
        "snapshots",
        ["snapshot_id"],
        ["snapshot_id"],
        ondelete="RESTRICT",
    )
    op.drop_index(
        "ix_profile_manifest_versions_organization_id",
        table_name="profile_manifest_versions",
    )
