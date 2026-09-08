"""Add immutable framework-neutral assessment pack infrastructure."""
from collections.abc import Sequence
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260908_0012"
down_revision: str | Sequence[str] | None = "20260908_0011"
branch_labels = depends_on = None

PACK_A = "8b1d2f0d-4c28-5c7d-9b7d-0000000000a1"
PACK_B = "8b1d2f0d-4c28-5c7d-9b7d-0000000000b1"
OBLIGATION_A_AUTO = "8b1d2f0d-4c28-5c7d-9b7d-0000000000a2"
OBLIGATION_A_MANUAL = "8b1d2f0d-4c28-5c7d-9b7d-0000000000a3"
OBLIGATION_A_UNIMPLEMENTED = "8b1d2f0d-4c28-5c7d-9b7d-0000000000a4"
OBLIGATION_B_AUTO = "8b1d2f0d-4c28-5c7d-9b7d-0000000000b2"
OBLIGATION_B_MANUAL = "8b1d2f0d-4c28-5c7d-9b7d-0000000000b3"
OBLIGATION_B_UNIMPLEMENTED = "8b1d2f0d-4c28-5c7d-9b7d-0000000000b4"

PROFILES = ["cisco.ios_xe.17@1.0.0", "fortinet.fortios.7@1.0.0"]
SOURCE = {"kind": "synthetic", "notice": "TEST/INFRASTRUCTURE ONLY; not CIS/NIST/STIG/ISO"}


def _obligation(obligation_id, pack_id, key, title, method, implementation, rule, parameters):
    return {
        "assessment_obligation_id": obligation_id,
        "assessment_pack_version_id": pack_id,
        "obligation_key": key,
        "title": title,
        "applicability": {"profile_version_ids": PROFILES},
        "assessment_method": method,
        "implementation_status": implementation,
        "evaluator_rule_id": rule,
        "policy_parameters": parameters,
        "source_reference": SOURCE,
    }


def upgrade() -> None:
    op.create_table(
        "assessment_pack_versions",
        sa.Column("assessment_pack_version_id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.organization_id", ondelete="RESTRICT")),
        sa.Column("pack_key", sa.String(255), nullable=False),
        sa.Column("family", sa.String(128), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("profile_version_ids", postgresql.JSONB(), nullable=False),
        sa.Column("source_metadata", postgresql.JSONB(), nullable=False),
        sa.Column("source_version_label", sa.String(255), nullable=False),
        sa.Column("content_digest", sa.String(64), nullable=False),
        sa.Column("applicability", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="published"),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False, server_default="1.0.0"),
        sa.CheckConstraint("version > 0", name="ck_assessment_pack_versions_version_positive"),
        sa.CheckConstraint("status IN ('available','published','retired')", name="ck_assessment_pack_versions_status"),
        sa.UniqueConstraint("organization_id", "pack_key", "version"),
    )
    op.create_index("ix_assessment_pack_versions_organization_id", "assessment_pack_versions", ["organization_id"])
    op.create_index("ix_assessment_pack_versions_pack_key", "assessment_pack_versions", ["pack_key"])
    op.create_index("ix_assessment_pack_versions_status", "assessment_pack_versions", ["status"])
    op.create_table(
        "assessment_obligations",
        sa.Column("assessment_obligation_id", sa.Uuid(), primary_key=True),
        sa.Column("assessment_pack_version_id", sa.Uuid(), sa.ForeignKey("assessment_pack_versions.assessment_pack_version_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("obligation_key", sa.String(255), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("applicability", postgresql.JSONB(), nullable=False),
        sa.Column("assessment_method", sa.String(16), nullable=False),
        sa.Column("implementation_status", sa.String(16), nullable=False),
        sa.Column("evaluator_rule_id", sa.String(255)),
        sa.Column("policy_parameters", postgresql.JSONB(), nullable=False),
        sa.Column("source_reference", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("assessment_pack_version_id", "obligation_key"),
    )
    op.create_index("ix_assessment_obligations_assessment_pack_version_id", "assessment_obligations", ["assessment_pack_version_id"])
    op.create_table(
        "audit_assessments",
        sa.Column("audit_id", sa.Uuid(), sa.ForeignKey("audits.audit_id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("assessment_pack_version_id", sa.Uuid(), sa.ForeignKey("assessment_pack_versions.assessment_pack_version_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("profile_version_id", sa.String(255), nullable=False),
        sa.Column("pinned_identity", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_assessments_organization_id", "audit_assessments", ["organization_id"])
    op.create_index("ix_audit_assessments_assessment_pack_version_id", "audit_assessments", ["assessment_pack_version_id"])
    op.create_table(
        "assessment_results",
        sa.Column("assessment_result_id", sa.Uuid(), primary_key=True),
        sa.Column("audit_id", sa.Uuid(), sa.ForeignKey("audits.audit_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.organization_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("assessment_obligation_id", sa.Uuid(), sa.ForeignKey("assessment_obligations.assessment_obligation_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("technical_finding_id", sa.Uuid(), sa.ForeignKey("findings.finding_id", ondelete="RESTRICT")),
        sa.Column("result_identity", sa.String(512), nullable=False),
        sa.Column("applicability_status", sa.String(32), nullable=False),
        sa.Column("assessment_method", sa.String(16), nullable=False),
        sa.Column("implementation_status", sa.String(16), nullable=False),
        sa.Column("verdict", sa.String(16)),
        sa.Column("policy_digest", sa.String(64), nullable=False),
        sa.Column("result_details", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("audit_id", "result_identity"),
    )
    for column in ("audit_id", "organization_id", "assessment_obligation_id"):
        op.create_index(f"ix_assessment_results_{column}", "assessment_results", [column])

    op.execute(sa.text("""
        CREATE FUNCTION prevent_assessment_pack_mutation() RETURNS trigger AS $$
        BEGIN RAISE EXCEPTION 'assessment pack versions are immutable'; END;
        $$ LANGUAGE plpgsql
    """))
    op.execute(sa.text("""
        CREATE TRIGGER trg_assessment_pack_versions_immutable
        BEFORE UPDATE OR DELETE ON assessment_pack_versions
        FOR EACH ROW EXECUTE FUNCTION prevent_assessment_pack_mutation()
    """))
    op.execute(sa.text("""
        CREATE FUNCTION prevent_assessment_obligation_mutation() RETURNS trigger AS $$
        BEGIN RAISE EXCEPTION 'assessment obligations are immutable'; END;
        $$ LANGUAGE plpgsql
    """))
    op.execute(sa.text("""
        CREATE TRIGGER trg_assessment_obligations_immutable
        BEFORE UPDATE OR DELETE ON assessment_obligations
        FOR EACH ROW EXECUTE FUNCTION prevent_assessment_obligation_mutation()
    """))

    now = datetime.now(timezone.utc)
    op.bulk_insert(
        sa.table(
            "assessment_pack_versions",
            sa.column("assessment_pack_version_id", sa.Uuid()),
            sa.column("organization_id", sa.Uuid()), sa.column("pack_key", sa.String()),
            sa.column("family", sa.String()), sa.column("name", sa.String()), sa.column("version", sa.Integer()),
            sa.column("profile_version_ids", postgresql.JSONB()), sa.column("source_metadata", postgresql.JSONB()),
            sa.column("source_version_label", sa.String()), sa.column("content_digest", sa.String()),
            sa.column("applicability", postgresql.JSONB()), sa.column("status", sa.String()),
            sa.column("published_at", sa.DateTime()), sa.column("created_at", sa.DateTime()),
        ),
        [
            {"assessment_pack_version_id": PACK_A, "organization_id": None, "pack_key": "synthetic_management_baseline_a", "family": "TEST/INFRASTRUCTURE", "name": "Synthetic Management Baseline A", "version": 1, "profile_version_ids": PROFILES, "source_metadata": SOURCE, "source_version_label": "synthetic-a@1", "content_digest": "a" * 64, "applicability": {"profile_version_ids": PROFILES}, "status": "published", "published_at": now, "created_at": now},
            {"assessment_pack_version_id": PACK_B, "organization_id": None, "pack_key": "synthetic_management_baseline_b", "family": "TEST/INFRASTRUCTURE", "name": "Synthetic Management Baseline B", "version": 1, "profile_version_ids": PROFILES, "source_metadata": SOURCE, "source_version_label": "synthetic-b@1", "content_digest": "b" * 64, "applicability": {"profile_version_ids": PROFILES}, "status": "published", "published_at": now, "created_at": now},
        ],
    )
    op.bulk_insert(
        sa.table(
            "assessment_obligations", sa.column("assessment_obligation_id", sa.Uuid()),
            sa.column("assessment_pack_version_id", sa.Uuid()), sa.column("obligation_key", sa.String()),
            sa.column("title", sa.String()), sa.column("applicability", postgresql.JSONB()),
            sa.column("assessment_method", sa.String()), sa.column("implementation_status", sa.String()),
            sa.column("evaluator_rule_id", sa.String()), sa.column("policy_parameters", postgresql.JSONB()),
            sa.column("source_reference", postgresql.JSONB()), sa.column("created_at", sa.DateTime()),
        ),
        [
            {**_obligation(OBLIGATION_A_AUTO, PACK_A, "synthetic.management.ssh.enabled", "Synthetic SSH management enabled", "automatic", "implemented", "management.ssh.enabled", {"expected": True}), "created_at": now},
            {**_obligation(OBLIGATION_A_MANUAL, PACK_A, "synthetic.management.crypto.review", "Synthetic management crypto review", "manual", "manual", None, {}), "created_at": now},
            {**_obligation(OBLIGATION_A_UNIMPLEMENTED, PACK_A, "synthetic.management.context", "Synthetic management context", "automatic", "unimplemented", None, {}), "created_at": now},
            {**_obligation(OBLIGATION_B_AUTO, PACK_B, "synthetic.management.ssh.disabled", "Synthetic SSH management disabled", "automatic", "implemented", "management.ssh.enabled", {"expected": False}), "created_at": now},
            {**_obligation(OBLIGATION_B_MANUAL, PACK_B, "synthetic.management.crypto.review", "Synthetic management crypto review", "manual", "manual", None, {}), "created_at": now},
            {**_obligation(OBLIGATION_B_UNIMPLEMENTED, PACK_B, "synthetic.management.context", "Synthetic management context", "automatic", "unimplemented", None, {}), "created_at": now},
        ],
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_assessment_obligations_immutable ON assessment_obligations")
    op.execute("DROP FUNCTION IF EXISTS prevent_assessment_obligation_mutation")
    op.execute("DROP TRIGGER IF EXISTS trg_assessment_pack_versions_immutable ON assessment_pack_versions")
    op.execute("DROP FUNCTION IF EXISTS prevent_assessment_pack_mutation")
    op.drop_table("assessment_results")
    op.drop_table("audit_assessments")
    op.drop_table("assessment_obligations")
    op.drop_table("assessment_pack_versions")
