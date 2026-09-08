"""Seed the scoped DISA Network Device Management SRG AssessmentPack."""
from collections.abc import Sequence
from datetime import datetime, timezone
from hashlib import sha256
import json

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260909_0015"
down_revision: str | Sequence[str] | None = "20260909_0014"
branch_labels = depends_on = None

PACK_ID = "9c1d2f0d-4c28-5c7d-9b7d-0000000000b7"
PROFILES = ["cisco.ios_xe.17@1.0.0", "fortinet.fortios.7@1.0.0", "juniper.junos.18@1.0.0"]
SOURCE_URL = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_NDM_V5R5_SRG.zip"
SOURCE_SHA256 = "d6f4415ed5cb4d4c5e589b3e8060203f43742b490aa30be479c774c6ef292a92"
SOURCE = {
    "framework": "DISA Network Device Management SRG",
    "benchmark_title": "Network Device Management Security Requirements Guide",
    "benchmark_id": "Network_Device_Management_SRG",
    "version": "5", "release": "5", "release_date": "2026-07-10",
    "retrieved_at": "2026-09-09", "official_source_url": SOURCE_URL,
    "source_artifact": "U_NDM_V5R5_SRG.zip",
    "xccdf_artifact": "U_NDM_SRG_V5R5_Manual-xccdf.xml",
    "source_sha256": SOURCE_SHA256,
    "scope": "Scoped technical prototype subset; not full DISA STIG/SRG compliance or DoD certification.",
}


def _digest() -> str:
    payload = {"pack_key": "disa_ndm_srg_v5r5_scoped_technical", "version": 1, "profiles": PROFILES, "source": SOURCE, "obligation_keys": [
        "v-202074.idle-timeout", "v-213467.logging-enabled", "v-213467.remote-log-destination",
        "v-202112.ntp-authentication", "v-264307.ntp-configured", "v-264308.ntp-server",
        "v-202118.remote-session-crypto-review", "v-202039.audit-clock-review",
    ]}
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _reference(v_number: str, rule_id: str, srg_id: str, severity: str, cat: str, rationale: str) -> dict[str, str]:
    return {**SOURCE, "v_number": v_number, "rule_id": rule_id, "srg_id": srg_id, "severity": severity, "cat": cat, "implementation_rationale": rationale}


def _obligation(obligation_id: str, key: str, title: str, method: str, implementation: str,
                evaluator: str | None, fields: list[str], source: tuple[str, str, str, str, str], rationale: str,
                extra: dict | None = None) -> dict:
    parameters = {"required_canonical_fields": fields}
    if extra:
        parameters.update(extra)
    return {
        "assessment_obligation_id": obligation_id, "assessment_pack_version_id": PACK_ID,
        "obligation_key": key, "title": title,
        "applicability": {"profile_version_ids": PROFILES, "scope_note": "Evaluate native EffectiveState scope only; missing, conflicting, or multiple scopes are UNKNOWN."},
        "assessment_method": method, "implementation_status": implementation,
        "evaluator_rule_id": evaluator, "policy_parameters": parameters,
        "source_reference": _reference(*source, rationale),
    }


V202074 = ("V-202074", "SV-202074r961068_rule", "SRG-APP-000190-NDM-000267", "high", "CAT I")
V213467 = ("V-213467", "SV-213467r1137890_rule", "SRG-APP-000516-NDM-000350", "high", "CAT I")
V202112 = ("V-202112", "SV-202112r961506_rule", "SRG-APP-000395-NDM-000347", "medium", "CAT II")
V264307 = ("V-264307", "SV-264307r984162_rule", "SRG-APP-000920-NDM-000320", "medium", "CAT II")
V264308 = ("V-264308", "SV-264308r984165_rule", "SRG-APP-000925-NDM-000330", "medium", "CAT II")
V202118 = ("V-202118", "SV-202118r961557_rule", "SRG-APP-000412-NDM-000331", "high", "CAT I")
V202039 = ("V-202039", "SV-202039r960927_rule", "SRG-APP-000116-NDM-000234", "medium", "CAT II")

OBLIGATIONS = [
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000701", "v-202074.idle-timeout", "Administrative idle timeout at or below five minutes", "automatic", "implemented", "management.idle_timeout.maximum", ["management.session.idle_timeout"], V202074, "Bounded configuration evidence for the five-minute inactivity threshold; documented mission exceptions are outside this pack.", {"maximum_admin_idle_timeout_seconds": 300}),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000702", "v-213467.logging-enabled", "Logging explicitly enabled", "automatic", "implemented", "logging.enabled", ["logging.enabled"], V213467, "Bounded configuration prerequisite for generating data to forward; it does not prove alert delivery."),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000703", "v-213467.remote-log-destination", "At least one remote log destination configured", "automatic", "implemented", "logging.remote.destination.configured", ["logging.remote.destination"], V213467, "Bounded configuration evidence for at least one remote destination; central-server role and boundary-device redundancy remain outside scope."),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000704", "v-202112.ntp-authentication", "Cryptographic NTP source authentication enabled", "automatic", "implemented", "time.ntp.authentication.enabled", ["time.ntp.authentication.enabled"], V202112, "Direct check of explicit NTP authentication configuration where the vendor semantic is supported."),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000705", "v-264307.ntp-configured", "Time synchronization configuration present", "automatic", "implemented", "time.ntp.configured", ["time.ntp.configured"], V264307, "Bounded configuration indicator only; synchronization health is not asserted."),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000706", "v-264308.ntp-server", "Configured NTP time source present", "automatic", "implemented", "time.ntp.server.configured", ["time.ntp.server"], V264308, "Bounded source-configuration indicator only; authority and comparison frequency are not asserted."),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000707", "v-202118.remote-session-crypto-review", "FIPS-approved remote-session cryptography review", "manual", "manual", None, [], V202118, "SSH/Telnet state cannot prove FIPS-approved cryptographic mechanisms or remote-maintenance context."),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000708", "v-202039.audit-clock-review", "Audit timestamp clock-use review", "manual", "manual", None, [], V202039, "NTP configuration cannot prove that audit records use the internal system clock."),
]


def upgrade() -> None:
    now = datetime.now(timezone.utc)
    op.bulk_insert(sa.table("assessment_pack_versions", sa.column("assessment_pack_version_id", sa.Uuid()), sa.column("organization_id", sa.Uuid()), sa.column("pack_key", sa.String()), sa.column("family", sa.String()), sa.column("name", sa.String()), sa.column("version", sa.Integer()), sa.column("profile_version_ids", postgresql.JSONB()), sa.column("source_metadata", postgresql.JSONB()), sa.column("source_version_label", sa.String()), sa.column("content_digest", sa.String()), sa.column("applicability", postgresql.JSONB()), sa.column("status", sa.String()), sa.column("published_at", sa.DateTime()), sa.column("created_at", sa.DateTime())), [{"assessment_pack_version_id": PACK_ID, "organization_id": None, "pack_key": "disa_ndm_srg_v5r5_scoped_technical", "family": "DISA SRG", "name": "DISA Network Device Management SRG Scoped Technical Pack", "version": 1, "profile_version_ids": PROFILES, "source_metadata": SOURCE, "source_version_label": "NDM-SRG-V5R5", "content_digest": _digest(), "applicability": {"profile_version_ids": PROFILES}, "status": "published", "published_at": now, "created_at": now}])
    op.bulk_insert(sa.table("assessment_obligations", sa.column("assessment_obligation_id", sa.Uuid()), sa.column("assessment_pack_version_id", sa.Uuid()), sa.column("obligation_key", sa.String()), sa.column("title", sa.String()), sa.column("applicability", postgresql.JSONB()), sa.column("assessment_method", sa.String()), sa.column("implementation_status", sa.String()), sa.column("evaluator_rule_id", sa.String()), sa.column("policy_parameters", postgresql.JSONB()), sa.column("source_reference", postgresql.JSONB()), sa.column("created_at", sa.DateTime())), [{**item, "created_at": now} for item in OBLIGATIONS])


def downgrade() -> None:
    op.execute("ALTER TABLE assessment_obligations DISABLE TRIGGER trg_assessment_obligations_immutable")
    op.execute("ALTER TABLE assessment_pack_versions DISABLE TRIGGER trg_assessment_pack_versions_immutable")
    op.execute(sa.text("DELETE FROM assessment_obligations WHERE assessment_pack_version_id = :pack_id").bindparams(pack_id=PACK_ID))
    op.execute(sa.text("DELETE FROM assessment_pack_versions WHERE assessment_pack_version_id = :pack_id").bindparams(pack_id=PACK_ID))
    op.execute("ALTER TABLE assessment_obligations ENABLE TRIGGER trg_assessment_obligations_immutable")
    op.execute("ALTER TABLE assessment_pack_versions ENABLE TRIGGER trg_assessment_pack_versions_immutable")
