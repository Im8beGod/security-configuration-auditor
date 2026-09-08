"""Add immutable profile manifests and resolution decisions."""
from datetime import datetime, timezone
from collections.abc import Sequence
import json
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260908_0013"
down_revision: str | Sequence[str] | None = "20260908_0012"
branch_labels = depends_on = None


def upgrade() -> None:
    op.create_table(
        "profile_manifest_versions",
        sa.Column("profile_manifest_version_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.organization_id", ondelete="RESTRICT")),
        sa.Column("profile_id", sa.String(255), nullable=False), sa.Column("profile_version_id", sa.String(255), nullable=False),
        sa.Column("manifest_schema_version", sa.String(32), nullable=False), sa.Column("manifest", postgresql.JSONB, nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="published"),
        sa.Column("published_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "profile_version_id"),
    )
    op.create_index("ix_profile_manifest_versions_profile_id", "profile_manifest_versions", ["profile_id"])
    op.create_index("ix_profile_manifest_versions_profile_version_id", "profile_manifest_versions", ["profile_version_id"])
    op.create_index("ix_profile_manifest_versions_status", "profile_manifest_versions", ["status"])
    op.execute(sa.text("""
        CREATE OR REPLACE FUNCTION reject_profile_manifest_mutation() RETURNS trigger AS $$
        BEGIN RAISE EXCEPTION 'profile manifest versions are immutable'; END; $$ LANGUAGE plpgsql;
        CREATE TRIGGER profile_manifest_versions_immutable_update BEFORE UPDATE OR DELETE ON profile_manifest_versions
        FOR EACH ROW EXECUTE FUNCTION reject_profile_manifest_mutation();
    """))
    op.create_table(
        "profile_resolution_decisions",
        sa.Column("decision_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("snapshot_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("snapshots.snapshot_id", ondelete="CASCADE"), nullable=False),
        sa.Column("audit_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("audits.audit_id", ondelete="CASCADE"), nullable=False),
        sa.Column("resolution_status", sa.String(32), nullable=False), sa.Column("selected_profile_id", sa.String(255)),
        sa.Column("selected_profile_version_id", sa.String(255)), sa.Column("applicability_status", sa.String(32), nullable=False),
        sa.Column("identity_provenance", postgresql.JSONB, nullable=False), sa.Column("evidence_summary", postgresql.JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for name, column in (("organization_id", "organization_id"), ("snapshot_id", "snapshot_id"), ("audit_id", "audit_id")):
        op.create_index(f"ix_profile_resolution_decisions_{name}", "profile_resolution_decisions", [column])
    now = datetime.now(timezone.utc)
    conn = op.get_bind()
    for profile_id, profile_version_id, manifest in (
        ("cisco.ios_xe.17", "cisco.ios_xe.17@1.0.0", {"vendor": "Cisco", "product_family": "IOS XE", "os": "IOS XE", "reader_id": "indentation_cli.v1", "version": {"major": [17]}}),
        ("fortinet.fortios.7", "fortinet.fortios.7@1.0.0", {"vendor": "Fortinet", "product_family": "FortiGate", "os": "FortiOS", "reader_id": "fortios_cli.v1", "version": {"major": [7]}}),
    ):
        conn.execute(sa.text("INSERT INTO profile_manifest_versions (profile_manifest_version_id, organization_id, profile_id, profile_version_id, manifest_schema_version, manifest, status, published_at, created_at) VALUES (:id, NULL, :profile_id, :profile_version_id, '1.0.0', CAST(:manifest AS jsonb), 'published', :now, :now)"), {"id": __import__("uuid").uuid4(), "profile_id": profile_id, "profile_version_id": profile_version_id, "manifest": json.dumps(manifest), "now": now})


def downgrade() -> None:
    op.execute(sa.text("DROP TRIGGER IF EXISTS profile_manifest_versions_immutable_update ON profile_manifest_versions"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS reject_profile_manifest_mutation()"))
    op.drop_table("profile_resolution_decisions")
    op.drop_table("profile_manifest_versions")
