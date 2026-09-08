"""Seed the scoped, immutable NIST SP 800-53 Rev. 5 technical AssessmentPack."""
from collections.abc import Sequence
from datetime import datetime, timezone
from hashlib import sha256
import json

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260909_0014"
down_revision: str | Sequence[str] | None = "20260908_0013"
branch_labels = depends_on = None

PACK_ID = "9c1d2f0d-4c28-5c7d-9b7d-0000000000b6"
PROFILES = ["cisco.ios_xe.17@1.0.0", "fortinet.fortios.7@1.0.0", "juniper.junos.18@1.0.0"]
SOURCE_URL = "https://raw.githubusercontent.com/usnistgov/oscal-content/78650f02ad9321bb7b817846f8fbd4f2bcd620de/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
SOURCE_SHA256 = "01f37cf90ea99d92242c936cbfbdebcc338eef1f71454e2acac36cc56e9bc062"
SOURCE = {
    "framework": "NIST SP 800-53",
    "revision": "Rev. 5",
    "catalog_version": "5.2.0",
    "catalog_last_modified": "2026-05-11T16:01:09.00000-00:00",
    "retrieved_at": "2026-09-09",
    "official_source_url": SOURCE_URL,
    "source_commit": "78650f02ad9321bb7b817846f8fbd4f2bcd620de",
    "source_sha256": SOURCE_SHA256,
    "source_artifact": "NIST_SP-800-53_rev5_catalog.json",
    "scope": "Scoped device-configuration technical evidence only; not a full control assessment.",
}


def _digest() -> str:
    payload = {
        "pack_key": "nist_sp80053_rev5_scoped_technical",
        "version": 1,
        "profiles": PROFILES,
        "source": SOURCE,
        "obligation_keys": [
            "ac-17.remote-ssh-enabled", "ac-17.telnet-disabled", "ac-17.ssh-v2",
            "ac-11.idle-timeout", "au-12.logging-enabled", "au-12.remote-logging",
            "au-8.ntp-configured", "au-8.ntp-server", "ac-17.authorization-review",
            "au-12.audit-event-review",
        ],
    }
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _reference(control_id: str, control_title: str, rationale: str) -> dict[str, str]:
    return {**SOURCE, "control_id": control_id, "control_title": control_title, "implementation_rationale": rationale}


def _obligation(obligation_id: str, key: str, title: str, method: str, implementation: str, rule: str | None,
                fields: list[str], control_id: str, control_title: str, rationale: str,
                extra: dict | None = None) -> dict:
    parameters = {"required_canonical_fields": fields}
    if extra:
        parameters.update(extra)
    return {
        "assessment_obligation_id": obligation_id,
        "assessment_pack_version_id": PACK_ID,
        "obligation_key": key,
        "title": title,
        "applicability": {"profile_version_ids": PROFILES, "scope_note": "Evaluate only the native EffectiveState scope; multiple scopes are UNKNOWN rather than flattened."},
        "assessment_method": method,
        "implementation_status": implementation,
        "evaluator_rule_id": rule,
        "policy_parameters": parameters,
        "source_reference": _reference(control_id, control_title, rationale),
    }


OBLIGATIONS = [
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000601", "ac-17.remote-ssh-enabled", "Remote administrative SSH explicitly enabled", "automatic", "implemented", "management.ssh.enabled", ["management.remote.ssh.enabled"], "AC-17", "Remote Access", "Bounded configuration evidence that an SSH management transport is explicitly enabled."),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000602", "ac-17.telnet-disabled", "Telnet administrative access explicitly disabled", "automatic", "implemented", "management.telnet.disabled", ["management.remote.telnet.enabled"], "AC-17", "Remote Access", "Bounded configuration evidence that the observed Telnet management transport is disabled."),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000603", "ac-17.ssh-v2", "Configured SSH protocol version is version 2", "automatic", "implemented", "management.ssh.version_2", ["management.remote.ssh.version"], "AC-17", "Remote Access", "Bounded configuration evidence for the explicitly configured SSH protocol version."),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000604", "ac-11.idle-timeout", "Administrative idle timeout is within the selected maximum", "automatic", "implemented", "management.idle_timeout.maximum", ["management.session.idle_timeout"], "AC-11", "Device Lock", "Bounded timeout evidence; this does not establish all device-lock behavior.", {"maximum_admin_idle_timeout_seconds": 600}),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000605", "au-12.logging-enabled", "Configuration logging explicitly enabled", "automatic", "implemented", "logging.enabled", ["logging.enabled"], "AU-12", "Audit Record Generation", "Bounded evidence that device logging is explicitly enabled; it does not establish event selection."),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000606", "au-12.remote-logging", "Remote logging destination configured", "automatic", "implemented", "logging.remote.destination.configured", ["logging.remote.destination"], "AU-12", "Audit Record Generation", "Bounded evidence that a remote logging destination is configured; transport and delivery are outside scope."),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000607", "au-8.ntp-configured", "NTP configuration explicitly present", "automatic", "implemented", "time.ntp.configured", ["time.ntp.configured"], "AU-8", "Time Stamps", "Bounded evidence that NTP configuration is present; synchronization health is outside scope."),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000608", "au-8.ntp-server", "NTP server configured", "automatic", "implemented", "time.ntp.server.configured", ["time.ntp.server"], "AU-8", "Time Stamps", "Bounded evidence that an NTP server is configured; trusted time quality is outside scope."),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000609", "ac-17.authorization-review", "Remote-access authorization and monitoring review", "manual", "manual", None, [], "AC-17", "Remote Access", "Requires organizational authorization and monitoring evidence outside device configuration."),
    _obligation("9c1d2f0d-4c28-5c7d-9b7d-000000000610", "au-12.audit-event-review", "Audit event selection and review process", "manual", "manual", None, [], "AU-12", "Audit Record Generation", "Requires organizational event-selection and review evidence outside device configuration."),
]


def upgrade() -> None:
    now = datetime.now(timezone.utc)
    op.bulk_insert(
        sa.table("assessment_pack_versions", sa.column("assessment_pack_version_id", sa.Uuid()), sa.column("organization_id", sa.Uuid()), sa.column("pack_key", sa.String()), sa.column("family", sa.String()), sa.column("name", sa.String()), sa.column("version", sa.Integer()), sa.column("profile_version_ids", postgresql.JSONB()), sa.column("source_metadata", postgresql.JSONB()), sa.column("source_version_label", sa.String()), sa.column("content_digest", sa.String()), sa.column("applicability", postgresql.JSONB()), sa.column("status", sa.String()), sa.column("published_at", sa.DateTime()), sa.column("created_at", sa.DateTime())),
        [{"assessment_pack_version_id": PACK_ID, "organization_id": None, "pack_key": "nist_sp80053_rev5_scoped_technical", "family": "NIST SP 800-53", "name": "NIST SP 800-53 Rev. 5 Scoped Technical Pack", "version": 1, "profile_version_ids": PROFILES, "source_metadata": SOURCE, "source_version_label": "NIST-SP-800-53-Rev5.2.0", "content_digest": _digest(), "applicability": {"profile_version_ids": PROFILES}, "status": "published", "published_at": now, "created_at": now}],
    )
    op.bulk_insert(
        sa.table("assessment_obligations", sa.column("assessment_obligation_id", sa.Uuid()), sa.column("assessment_pack_version_id", sa.Uuid()), sa.column("obligation_key", sa.String()), sa.column("title", sa.String()), sa.column("applicability", postgresql.JSONB()), sa.column("assessment_method", sa.String()), sa.column("implementation_status", sa.String()), sa.column("evaluator_rule_id", sa.String()), sa.column("policy_parameters", postgresql.JSONB()), sa.column("source_reference", postgresql.JSONB()), sa.column("created_at", sa.DateTime())),
        [{**item, "created_at": now} for item in OBLIGATIONS],
    )


def downgrade() -> None:
    op.execute("ALTER TABLE assessment_obligations DISABLE TRIGGER trg_assessment_obligations_immutable")
    op.execute("ALTER TABLE assessment_pack_versions DISABLE TRIGGER trg_assessment_pack_versions_immutable")
    op.execute(sa.text("DELETE FROM assessment_obligations WHERE assessment_pack_version_id = :pack_id").bindparams(pack_id=PACK_ID))
    op.execute(sa.text("DELETE FROM assessment_pack_versions WHERE assessment_pack_version_id = :pack_id").bindparams(pack_id=PACK_ID))
    op.execute("ALTER TABLE assessment_obligations ENABLE TRIGGER trg_assessment_obligations_immutable")
    op.execute("ALTER TABLE assessment_pack_versions ENABLE TRIGGER trg_assessment_pack_versions_immutable")
