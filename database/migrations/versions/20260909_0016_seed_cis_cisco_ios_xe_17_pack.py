"""Seed the scoped CIS Cisco IOS XE 17.x AssessmentPack."""
from collections.abc import Sequence
from datetime import datetime, timezone
from hashlib import sha256
import json

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260909_0016"
down_revision: str | Sequence[str] | None = "20260909_0015"
branch_labels = depends_on = None

PACK_ID = "9c1d2f0d-4c28-5c7d-9b7d-0000000000b8"
PROFILES = ["cisco.ios_xe.17@1.0.0"]
SOURCE_URL = "https://www.cisecurity.org/benchmark/cisco"
SOURCE_SHA256 = "e5330afdf64cc7a44ba051733e7b3a5b835d7d341610dddb5d5292eabe126b25"
SOURCE = {
    "framework": "CIS Cisco IOS XE 17.x Benchmark",
    "benchmark_title": "CIS Cisco IOS XE 17.x Benchmark",
    "version": "2.2.1", "release_date": "2025-07-17", "retrieved_at": "2026-09-09",
    "official_source_url": SOURCE_URL,
    "source_artifact": "CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf",
    "source_sha256": SOURCE_SHA256,
    "source_access": "Authorized local official PDF; not redistributed.",
    "scope": "Scoped technical prototype subset; not full CIS Benchmark coverage, CIS-CAT, or certification.",
}


def _digest() -> str:
    payload = {"pack_key": "cis_cisco_ios_xe_17_v2_2_1_scoped_technical", "version": 1, "profiles": PROFILES, "source": SOURCE, "obligation_keys": [item["obligation_key"] for item in OBLIGATIONS]}
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _reference(recommendation_id: str, level: str, source_status: str, page: int, rationale: str) -> dict[str, object]:
    return {**SOURCE, "recommendation_id": recommendation_id, "cis_level": level, "cis_assessment_status": source_status, "source_page": page, "implementation_rationale": rationale}


def _obligation(number: int, key: str, title: str, method: str, implementation: str, evaluator: str | None, fields: list[str], source: tuple[str, str, str, int], rationale: str, parameters: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "assessment_obligation_id": f"9c1d2f0d-4c28-5c7d-9b7d-{number:012d}",
        "assessment_pack_version_id": PACK_ID, "obligation_key": key, "title": title,
        "applicability": {"profile_version_ids": PROFILES, "scope_note": "Evaluate native EffectiveState scope only; missing, conflicting, or multiple scopes are UNKNOWN."},
        "assessment_method": method, "implementation_status": implementation,
        "evaluator_rule_id": evaluator,
        "policy_parameters": {"required_canonical_fields": fields, **(parameters or {})},
        "source_reference": _reference(*source, rationale),
    }


OBLIGATIONS = [
    _obligation(801, "cis-1.2.2.vty-secure-transport-review", "VTY secure-transport review", "manual", "manual", None, [], ("1.2.2", "Level 1", "Automated", 41), "The current single-field evaluator cannot prove complete secure transport across all VTY contexts."),
    _obligation(802, "cis-1.2.5.vty-source-restriction", "VTY source restriction configured", "automatic", "implemented", "management.source.restriction.configured", ["management.remote.source.restriction.configured"], ("1.2.5", "Level 1", "Automated", 47), "Direct bounded evidence of an explicit Cisco VTY source restriction."),
    _obligation(803, "cis-1.2.8.vty-idle-timeout", "VTY administrative idle timeout at or below ten minutes", "automatic", "implemented", "management.idle_timeout.maximum", ["management.session.idle_timeout"], ("1.2.8", "Level 1", "Automated", 53), "Direct bounded evidence for the configured VTY timeout threshold.", {"maximum_admin_idle_timeout_seconds": 600}),
    _obligation(804, "cis-2.1.1.2.ssh-version-review", "SSH protocol version review", "manual", "manual", None, [], ("2.1.1.2", "Level 1", "Manual", 107), "The source classification is manual and remains manual in this prototype."),
    _obligation(805, "cis-2.2.1.logging-enabled", "System logging explicitly enabled", "automatic", "implemented", "logging.enabled", ["logging.enabled"], ("2.2.1", "Level 1", "Automated", 122), "Direct bounded evidence of explicit logging enablement."),
    _obligation(806, "cis-2.2.4.remote-logging-host", "Remote logging destination configured", "automatic", "implemented", "logging.remote.destination.configured", ["logging.remote.destination"], ("2.2.4", "Level 1", "Automated", 128), "Direct bounded evidence of at least one configured remote logging destination."),
    _obligation(807, "cis-2.3.1.1.ntp-authentication", "NTP authentication enabled", "automatic", "implemented", "time.ntp.authentication.enabled", ["time.ntp.authentication.enabled"], ("2.3.1.1", "Level 1", "Automated", 139), "Direct bounded evidence of explicit NTP authentication enablement."),
    _obligation(808, "cis-2.3.1.2.ntp-authentication-key-review", "NTP authentication-key review", "manual", "manual", None, ["time.ntp.authentication.key_id"], ("2.3.1.2", "Level 1", "Automated", 141), "Canonical key identifiers intentionally exclude secrets and the generic evaluator cannot safely assess key material."),
    _obligation(809, "cis-2.3.1.3.ntp-trusted-key-review", "NTP trusted-key review", "manual", "manual", None, ["time.ntp.authentication.trusted_key_id"], ("2.3.1.3", "Level 1", "Automated", 143), "Canonical key identifiers intentionally exclude secrets and the generic evaluator cannot safely assess trust semantics."),
    _obligation(810, "cis-2.3.1.4.ntp-server-key-review", "NTP server-to-key relationship review", "manual", "manual", None, [], ("2.3.1.4", "Level 2", "Manual", 145), "Available canonical evidence does not prove every configured server is bound to an appropriate key."),
    _obligation(811, "cis-2.3.2.ntp-server", "NTP server configured", "automatic", "implemented", "time.ntp.server.configured", ["time.ntp.server"], ("2.3.2", "Level 1", "Automated", 147), "Direct bounded evidence of at least one configured NTP server."),
]


def upgrade() -> None:
    now = datetime.now(timezone.utc)
    op.bulk_insert(sa.table("assessment_pack_versions", sa.column("assessment_pack_version_id", sa.Uuid()), sa.column("organization_id", sa.Uuid()), sa.column("pack_key", sa.String()), sa.column("family", sa.String()), sa.column("name", sa.String()), sa.column("version", sa.Integer()), sa.column("profile_version_ids", postgresql.JSONB()), sa.column("source_metadata", postgresql.JSONB()), sa.column("source_version_label", sa.String()), sa.column("content_digest", sa.String()), sa.column("applicability", postgresql.JSONB()), sa.column("status", sa.String()), sa.column("published_at", sa.DateTime()), sa.column("created_at", sa.DateTime())), [{"assessment_pack_version_id": PACK_ID, "organization_id": None, "pack_key": "cis_cisco_ios_xe_17_v2_2_1_scoped_technical", "family": "CIS Benchmark", "name": "CIS Cisco IOS XE 17.x Benchmark v2.2.1 Scoped Technical Prototype", "version": 1, "profile_version_ids": PROFILES, "source_metadata": SOURCE, "source_version_label": "CIS-Cisco-IOS-XE-17.x-v2.2.1", "content_digest": _digest(), "applicability": {"profile_version_ids": PROFILES}, "status": "published", "published_at": now, "created_at": now}])
    op.bulk_insert(sa.table("assessment_obligations", sa.column("assessment_obligation_id", sa.Uuid()), sa.column("assessment_pack_version_id", sa.Uuid()), sa.column("obligation_key", sa.String()), sa.column("title", sa.String()), sa.column("applicability", postgresql.JSONB()), sa.column("assessment_method", sa.String()), sa.column("implementation_status", sa.String()), sa.column("evaluator_rule_id", sa.String()), sa.column("policy_parameters", postgresql.JSONB()), sa.column("source_reference", postgresql.JSONB()), sa.column("created_at", sa.DateTime())), [{**item, "created_at": now} for item in OBLIGATIONS])


def downgrade() -> None:
    op.execute("ALTER TABLE assessment_obligations DISABLE TRIGGER trg_assessment_obligations_immutable")
    op.execute("ALTER TABLE assessment_pack_versions DISABLE TRIGGER trg_assessment_pack_versions_immutable")
    op.execute(sa.text("DELETE FROM assessment_obligations WHERE assessment_pack_version_id = :pack_id").bindparams(pack_id=PACK_ID))
    op.execute(sa.text("DELETE FROM assessment_pack_versions WHERE assessment_pack_version_id = :pack_id").bindparams(pack_id=PACK_ID))
    op.execute("ALTER TABLE assessment_obligations ENABLE TRIGGER trg_assessment_obligations_immutable")
    op.execute("ALTER TABLE assessment_pack_versions ENABLE TRIGGER trg_assessment_pack_versions_immutable")
