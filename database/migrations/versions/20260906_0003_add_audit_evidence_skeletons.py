"""Add Artifact, Device, Snapshot, and Audit persistence skeletons.

Revision ID: 20260906_0003
Revises: 20260906_0002
Create Date: 2026-09-06
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260906_0003"
down_revision: str | Sequence[str] | None = "20260906_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("latest_hostname", sa.String(length=255), nullable=True),
        sa.Column("stable_serial_number", sa.String(length=255), nullable=True),
        sa.Column("asset_tag", sa.String(length=255), nullable=True),
        sa.Column("device_class", sa.String(length=32), server_default="unknown", nullable=False),
        sa.Column("identity_status", sa.String(length=32), server_default="unresolved", nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.String(length=32), server_default="1.0.0", nullable=False),
        sa.CheckConstraint(
            "device_class IN ('router', 'switch', 'firewall', 'sase', 'load_balancer', "
            "'wireless', 'cloud_network_control', 'virtual_network_device', 'unknown', 'other')",
            name=op.f("ck_devices_device_class"),
        ),
        sa.CheckConstraint(
            "identity_status IN ('identified', 'partially_identified', 'unresolved', 'manually_confirmed')",
            name=op.f("ck_devices_identity_status"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.organization_id"],
            name=op.f("fk_devices_organization_id_organizations"), ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("device_id", name=op.f("pk_devices")),
    )
    op.create_index(op.f("ix_devices_organization_id"), "devices", ["organization_id"], unique=False)

    op.create_table(
        "snapshots",
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=True),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="draft", nullable=False),
        sa.Column("grouping_status", sa.String(length=32), nullable=False),
        sa.Column("snapshot_hash", sa.String(length=64), nullable=False),
        sa.Column("artifact_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.String(length=32), server_default="1.0.0", nullable=False),
        sa.CheckConstraint("artifact_count >= 0", name=op.f("ck_snapshots_artifact_count")),
        sa.CheckConstraint(
            "grouping_status IN ('automatic', 'manually_confirmed', 'needs_review')",
            name=op.f("ck_snapshots_grouping_status"),
        ),
        sa.CheckConstraint("snapshot_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_snapshots_snapshot_hash")),
        sa.CheckConstraint("source IN ('upload', 'api', 'collector', 'import')", name=op.f("ck_snapshots_source")),
        sa.CheckConstraint("status IN ('draft', 'ready', 'locked', 'archived')", name=op.f("ck_snapshots_status")),
        sa.ForeignKeyConstraint(["created_by"], ["users.user_id"], name=op.f("fk_snapshots_created_by_users"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.device_id"], name=op.f("fk_snapshots_device_id_devices"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.organization_id"], name=op.f("fk_snapshots_organization_id_organizations"), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("snapshot_id", name=op.f("pk_snapshots")),
    )
    op.create_index(op.f("ix_snapshots_captured_at"), "snapshots", ["captured_at"], unique=False)
    op.create_index(op.f("ix_snapshots_device_id"), "snapshots", ["device_id"], unique=False)
    op.create_index(op.f("ix_snapshots_organization_id"), "snapshots", ["organization_id"], unique=False)
    op.create_index(op.f("ix_snapshots_status"), "snapshots", ["status"], unique=False)

    op.create_table(
        "artifacts",
        sa.Column("artifact_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=True),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("storage_reference", sa.String(length=500), nullable=False),
        sa.Column("byte_size", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("mime_type", sa.String(length=255), nullable=True),
        sa.Column("encoding", sa.String(length=100), nullable=True),
        sa.Column("content_family", sa.String(length=32), nullable=False),
        sa.Column("evidence_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="uploaded", nullable=False),
        sa.Column("validation_issues", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("source_metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("uploaded_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("schema_version", sa.String(length=32), server_default="1.0.0", nullable=False),
        sa.CheckConstraint("byte_size >= 0", name=op.f("ck_artifacts_byte_size")),
        sa.CheckConstraint("content_family IN ('text', 'json', 'xml', 'unknown')", name=op.f("ck_artifacts_content_family")),
        sa.CheckConstraint("evidence_type IN ('configuration', 'version_output', 'inventory_output', 'operational_output', 'structured_export', 'unknown_evidence')", name=op.f("ck_artifacts_evidence_type")),
        sa.CheckConstraint("jsonb_typeof(source_metadata) = 'object'", name=op.f("ck_artifacts_source_metadata")),
        sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name=op.f("ck_artifacts_sha256")),
        sa.CheckConstraint("status IN ('uploaded', 'validating', 'validated', 'ready', 'partially_supported', 'needs_review', 'rejected')", name=op.f("ck_artifacts_status")),
        sa.CheckConstraint("jsonb_typeof(validation_issues) = 'array'", name=op.f("ck_artifacts_validation_issues")),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.organization_id"], name=op.f("fk_artifacts_organization_id_organizations"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["snapshots.snapshot_id"], name=op.f("fk_artifacts_snapshot_id_snapshots"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["uploaded_by"], ["users.user_id"], name=op.f("fk_artifacts_uploaded_by_users"), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("artifact_id", name=op.f("pk_artifacts")),
    )
    op.create_index(op.f("ix_artifacts_organization_id"), "artifacts", ["organization_id"], unique=False)
    op.create_index(op.f("ix_artifacts_sha256"), "artifacts", ["sha256"], unique=False)
    op.create_index(op.f("ix_artifacts_snapshot_id"), "artifacts", ["snapshot_id"], unique=False)
    op.create_index(op.f("ix_artifacts_uploaded_by"), "artifacts", ["uploaded_by"], unique=False)

    op.create_table(
        "audits",
        sa.Column("audit_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("audit_batch_id", sa.Uuid(), nullable=True),
        sa.Column("revision_number", sa.Integer(), nullable=False),
        sa.Column("previous_audit_id", sa.Uuid(), nullable=True),
        sa.Column("reevaluation_reason", sa.String(length=32), server_default="initial", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="draft", nullable=False),
        sa.Column("processing_stage", sa.String(length=32), nullable=True),
        sa.Column("selected_frameworks", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("version_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("profile_resolution", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("verdict_counts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("severity_counts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("coverage", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("schema_version", sa.String(length=32), server_default="1.0.0", nullable=False),
        sa.CheckConstraint("jsonb_typeof(coverage) = 'object'", name=op.f("ck_audits_coverage")),
        sa.CheckConstraint("jsonb_typeof(profile_resolution) = 'object'", name=op.f("ck_audits_profile_resolution")),
        sa.CheckConstraint("processing_stage IN ('validating', 'identifying', 'parsing', 'interpreting', 'resolving_state', 'evaluating', 'finalizing')", name=op.f("ck_audits_processing_stage")),
        sa.CheckConstraint("reevaluation_reason IN ('initial', 'knowledge_pack_update', 'rule_pack_update', 'policy_update', 'profile_correction', 'manual_reevaluation', 'other')", name=op.f("ck_audits_reevaluation_reason")),
        sa.CheckConstraint("revision_number >= 1", name=op.f("ck_audits_revision_number")),
        sa.CheckConstraint("jsonb_typeof(selected_frameworks) = 'array'", name=op.f("ck_audits_selected_frameworks")),
        sa.CheckConstraint("jsonb_typeof(severity_counts) = 'object'", name=op.f("ck_audits_severity_counts")),
        sa.CheckConstraint("status IN ('draft', 'queued', 'processing', 'completed', 'completed_with_unknowns', 'completed_with_errors', 'failed')", name=op.f("ck_audits_status")),
        sa.CheckConstraint("jsonb_typeof(verdict_counts) = 'object'", name=op.f("ck_audits_verdict_counts")),
        sa.CheckConstraint("jsonb_typeof(version_refs) = 'object'", name=op.f("ck_audits_version_refs")),
        sa.ForeignKeyConstraint(["created_by"], ["users.user_id"], name=op.f("fk_audits_created_by_users"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.device_id"], name=op.f("fk_audits_device_id_devices"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.organization_id"], name=op.f("fk_audits_organization_id_organizations"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["previous_audit_id"], ["audits.audit_id"], name=op.f("fk_audits_previous_audit_id_audits"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["snapshots.snapshot_id"], name=op.f("fk_audits_snapshot_id_snapshots"), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("audit_id", name=op.f("pk_audits")),
        sa.UniqueConstraint("snapshot_id", "revision_number", name=op.f("uq_audits_snapshot_id")),
    )
    op.create_index(op.f("ix_audits_audit_batch_id"), "audits", ["audit_batch_id"], unique=False)
    op.create_index(op.f("ix_audits_created_at"), "audits", ["created_at"], unique=False)
    op.create_index(op.f("ix_audits_device_id"), "audits", ["device_id"], unique=False)
    op.create_index(op.f("ix_audits_organization_id"), "audits", ["organization_id"], unique=False)
    op.create_index(op.f("ix_audits_snapshot_id"), "audits", ["snapshot_id"], unique=False)
    op.create_index(op.f("ix_audits_status"), "audits", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_audits_status"), table_name="audits")
    op.drop_index(op.f("ix_audits_snapshot_id"), table_name="audits")
    op.drop_index(op.f("ix_audits_organization_id"), table_name="audits")
    op.drop_index(op.f("ix_audits_device_id"), table_name="audits")
    op.drop_index(op.f("ix_audits_created_at"), table_name="audits")
    op.drop_index(op.f("ix_audits_audit_batch_id"), table_name="audits")
    op.drop_table("audits")
    op.drop_index(op.f("ix_artifacts_uploaded_by"), table_name="artifacts")
    op.drop_index(op.f("ix_artifacts_snapshot_id"), table_name="artifacts")
    op.drop_index(op.f("ix_artifacts_sha256"), table_name="artifacts")
    op.drop_index(op.f("ix_artifacts_organization_id"), table_name="artifacts")
    op.drop_table("artifacts")
    op.drop_index(op.f("ix_snapshots_status"), table_name="snapshots")
    op.drop_index(op.f("ix_snapshots_organization_id"), table_name="snapshots")
    op.drop_index(op.f("ix_snapshots_device_id"), table_name="snapshots")
    op.drop_index(op.f("ix_snapshots_captured_at"), table_name="snapshots")
    op.drop_table("snapshots")
    op.drop_index(op.f("ix_devices_organization_id"), table_name="devices")
    op.drop_table("devices")
