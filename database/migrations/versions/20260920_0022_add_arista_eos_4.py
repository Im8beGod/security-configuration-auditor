"""Add immutable Arista EOS 4 assessment and remediation records."""

from collections.abc import Sequence
from datetime import datetime, timezone
import json

from alembic import op
import sqlalchemy as sa


revision = "20260920_0022"
down_revision: str | Sequence[str] | None = "20260920_0021"
branch_labels = depends_on = None

PROFILE = "arista.eos.4@1.0.0"
PACKS = (
    ("9c1d2f0d-4c28-5c7d-9b7d-0000000000b6", "a4600000-0000-5000-8000-000000000001", "2b3f55fa35a8c89cbdd832f92d567f109b73cc4ee1e0aa8f2f720f22f63fd7a8"),
    ("9c1d2f0d-4c28-5c7d-9b7d-0000000000b7", "a4600000-0000-5000-8000-000000000002", "370d490c7646f4e137462cc16019f5fe1f91893295349ce84a52009a04754024"),
    ("9c1d2f0d-4c28-5c7d-9b7d-0000000000b9", "a4600000-0000-5000-8000-000000000003", "87a8636f2315ce369c43fa080a13f0327a8ad89dd9fdd071a00a654b7513c2e1"),
)
PROCEDURE_IDS = (
    "a4500000-0000-5000-8000-000000000001",
    "a4500000-0000-5000-8000-000000000002",
)
WARNING = "Guidance preview only; no device connection or execution occurs."


def _procedure_table():
    return sa.table(
        "remediation_procedures",
        sa.column("procedure_id", sa.Uuid()), sa.column("procedure_key", sa.String()),
        sa.column("version", sa.Integer()), sa.column("previous_procedure_id", sa.Uuid()),
        sa.column("rule_id", sa.String()), sa.column("title", sa.String()),
        sa.column("security_objective", sa.String()), sa.column("description", sa.String()),
        sa.column("status", sa.String()), sa.column("profile_applicability", sa.JSON()),
        sa.column("prerequisites", sa.JSON()), sa.column("safety_warnings", sa.JSON()),
        sa.column("required_parameters", sa.JSON()), sa.column("configuration_context", sa.JSON()),
        sa.column("ordered_steps", sa.JSON()), sa.column("verification_steps", sa.JSON()),
        sa.column("rollback_steps", sa.JSON()), sa.column("validation_results", sa.JSON()),
        sa.column("source_references", sa.JSON()), sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("reviewed_at", sa.DateTime(timezone=True)), sa.column("validated_at", sa.DateTime(timezone=True)),
        sa.column("published_at", sa.DateTime(timezone=True)), sa.column("schema_version", sa.String()),
    )


def upgrade() -> None:
    now = datetime.now(timezone.utc)
    for old_id, new_id, digest in PACKS:
        op.execute(sa.text("""
            INSERT INTO assessment_pack_versions (
                assessment_pack_version_id, organization_id, pack_key, family, name,
                version, profile_version_ids, source_metadata, source_version_label,
                content_digest, applicability, status, published_at, created_at, schema_version
            )
            SELECT CAST(:new_id AS uuid), organization_id, pack_key, family, name,
                2, profile_version_ids || CAST(:profile_json AS jsonb),
                source_metadata || jsonb_build_object('phase2_extension', :profile),
                source_version_label, :digest,
                jsonb_set(applicability, '{profile_version_ids}',
                    (applicability->'profile_version_ids') || CAST(:profile_json AS jsonb)),
                status, :now, :now, schema_version
            FROM assessment_pack_versions
            WHERE assessment_pack_version_id = CAST(:old_id AS uuid)
        """).bindparams(
            old_id=old_id, new_id=new_id, profile=PROFILE,
            profile_json=f'["{PROFILE}"]', digest=digest, now=now,
        ))
        op.execute(sa.text("""
            INSERT INTO assessment_obligations (
                assessment_obligation_id, assessment_pack_version_id, obligation_key,
                title, applicability, assessment_method, implementation_status,
                evaluator_rule_id, policy_parameters, source_reference, created_at
            )
            SELECT CAST(md5(:new_id || ':' || obligation_key) AS uuid), CAST(:new_id AS uuid),
                obligation_key, title,
                jsonb_set(applicability, '{profile_version_ids}',
                    (applicability->'profile_version_ids') || CAST(:profile_json AS jsonb)),
                assessment_method, implementation_status, evaluator_rule_id,
                policy_parameters, source_reference, :now
            FROM assessment_obligations
            WHERE assessment_pack_version_id = CAST(:old_id AS uuid)
        """).bindparams(
            old_id=old_id, new_id=new_id,
            profile_json=f'["{PROFILE}"]', now=now,
        ))

    profile = {"profile_version_ids": [PROFILE]}
    source = [{
        "title": "Arista EOS Session Management Commands",
        "url": "https://www.arista.com/en/um-eos/eos-session-management-commands",
        "accessed_at": "2026-09-20",
    }]
    common = {
        "version": 1, "previous_procedure_id": None, "status": "PUBLISHED",
        "profile_applicability": profile,
        "prerequisites": [{"text": "Capture current configuration and maintain alternate access."}],
        "safety_warnings": [WARNING], "validation_results": [{"review": "passed", "parameter_validation": True}],
        "source_references": source, "created_at": now, "reviewed_at": now,
        "validated_at": now, "published_at": now, "schema_version": "1.0.0",
    }
    rows = [
        {**common, "procedure_id": PROCEDURE_IDS[0], "procedure_key": "arista.eos.4.disable-telnet",
         "rule_id": "management.telnet.disabled", "title": "Disable Arista EOS Telnet management",
         "security_objective": "Disable clear-text Telnet management access.",
         "description": "Reviewed bounded EOS Telnet shutdown guidance.", "required_parameters": [],
         "configuration_context": ["global configuration mode", "Telnet management configuration mode"],
         "ordered_steps": [{"text": item} for item in ("configure terminal", "management telnet", "shutdown", "end")],
         "verification_steps": [{"text": "show running-config section management telnet"}],
         "rollback_steps": [{"text": "Rollback requires reviewed use of no shutdown in management telnet mode."}]},
        {**common, "procedure_id": PROCEDURE_IDS[1], "procedure_key": "arista.eos.4.remote-logging-host",
         "rule_id": "logging.remote.destination.configured", "title": "Configure an Arista EOS remote logging host",
         "security_objective": "Send EOS system messages to an approved remote logging destination.",
         "description": "Reviewed bounded EOS remote logging destination guidance.",
         "required_parameters": [{"name": "destination", "label": "Logging host", "type": "hostname", "required": True}],
         "configuration_context": ["global configuration mode"],
         "ordered_steps": [{"text": item} for item in ("configure terminal", "logging host {destination}", "end")],
         "verification_steps": [{"text": "show running-config | include logging host"}],
         "rollback_steps": [{"text": item} for item in ("configure terminal", "no logging host {destination}", "end")]},
    ]
    statement = sa.text("""
        INSERT INTO remediation_procedures (
            procedure_id, procedure_key, version, previous_procedure_id, rule_id,
            title, security_objective, description, status, profile_applicability,
            prerequisites, safety_warnings, required_parameters, configuration_context,
            ordered_steps, verification_steps, rollback_steps, validation_results,
            source_references, created_at, reviewed_at, validated_at, published_at, schema_version
        ) VALUES (
            CAST(:procedure_id AS uuid), :procedure_key, :version,
            CAST(:previous_procedure_id AS uuid), :rule_id,
            :title, :security_objective, :description, :status,
            CAST(:profile_applicability AS jsonb), CAST(:prerequisites AS jsonb),
            CAST(:safety_warnings AS jsonb), CAST(:required_parameters AS jsonb),
            CAST(:configuration_context AS jsonb), CAST(:ordered_steps AS jsonb),
            CAST(:verification_steps AS jsonb), CAST(:rollback_steps AS jsonb),
            CAST(:validation_results AS jsonb), CAST(:source_references AS jsonb),
            :created_at, :reviewed_at, :validated_at, :published_at, :schema_version
        )
    """)
    json_fields = {
        "profile_applicability", "prerequisites", "safety_warnings",
        "required_parameters", "configuration_context", "ordered_steps",
        "verification_steps", "rollback_steps", "validation_results",
        "source_references",
    }
    for row in rows:
        op.execute(statement.bindparams(**{
            key: json.dumps(value, sort_keys=True) if key in json_fields else value
            for key, value in row.items()
        }))


def downgrade() -> None:
    op.execute("ALTER TABLE remediation_procedures DISABLE TRIGGER trg_remediation_published_immutable")
    op.execute(sa.text("DELETE FROM remediation_procedures WHERE procedure_id IN (CAST(:one AS uuid), CAST(:two AS uuid))").bindparams(one=PROCEDURE_IDS[0], two=PROCEDURE_IDS[1]))
    op.execute("ALTER TABLE remediation_procedures ENABLE TRIGGER trg_remediation_published_immutable")
    op.execute("ALTER TABLE assessment_obligations DISABLE TRIGGER trg_assessment_obligations_immutable")
    op.execute("ALTER TABLE assessment_pack_versions DISABLE TRIGGER trg_assessment_pack_versions_immutable")
    for _old_id, new_id, _digest in reversed(PACKS):
        op.execute(sa.text("DELETE FROM assessment_obligations WHERE assessment_pack_version_id = CAST(:pack_id AS uuid)").bindparams(pack_id=new_id))
        op.execute(sa.text("DELETE FROM assessment_pack_versions WHERE assessment_pack_version_id = CAST(:pack_id AS uuid)").bindparams(pack_id=new_id))
    op.execute("ALTER TABLE assessment_obligations ENABLE TRIGGER trg_assessment_obligations_immutable")
    op.execute("ALTER TABLE assessment_pack_versions ENABLE TRIGGER trg_assessment_pack_versions_immutable")
