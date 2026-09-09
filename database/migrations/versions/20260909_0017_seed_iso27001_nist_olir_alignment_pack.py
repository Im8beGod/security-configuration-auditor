"""Seed the ISO/IEC 27001:2022 NIST OLIR-derived alignment pack."""
from collections.abc import Sequence
from datetime import datetime, timezone
from hashlib import sha256
import json
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "20260909_0017"
down_revision: str | Sequence[str] | None = "20260909_0016"
branch_labels = depends_on = None
PACK_ID = "9c1d2f0d-4c28-5c7d-9b7d-0000000000b9"
PROFILES = ["cisco.ios_xe.17@1.0.0", "fortinet.fortios.7@1.0.0", "juniper.junos.18@1.0.0"]
OLIR_URL = "https://csrc.nist.gov/projects/olir/informative-reference-catalog/details?referenceId=155"
OLIR_DIGEST = "E631DE234A1FAC057991773F015C221226940540F5602E1B70A3768EAFF5CBD9"
SOURCE = {"framework": "ISO/IEC 27001:2022 NIST OLIR-Derived Technical Alignment", "iso_open_data_url": "https://www.iso.org/open-data.html", "iso_reference": "ISO/IEC 27001:2022", "iso_edition": 3, "iso_publication_date": "2022-10-25", "iso_status": "published", "amendment_reference": "ISO/IEC 27001:2022/Amd 1:2024", "amendment_status": "published; outside this technical subset", "olir_name": "800-53-Rev5-to-ISO 27001-2022 Informative Reference", "olir_version": "1.0.0", "focal_document_version": "SP 800-53 Rev 5.1.1", "official_source_url": OLIR_URL, "olir_artifact": "sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx", "olir_sha3_256": OLIR_DIGEST, "retrieved_at": "2026-09-09", "relationship_disclaimer": "NIST OLIR is an informative crosswalk; mappings do not establish control equivalence or ISO conformity."}
RELATIONSHIPS = {"AC-11": ("AC-11", "A.7.7"), "AC-17": ("AC-17", "A.5.14"), "AU-8": ("AU-08", "A.8.17"), "AU-12": ("AU-12", "A.8.15")}

def _digest() -> str:
    return sha256(json.dumps({"pack_key": "iso27001_2022_nist_olir_technical_alignment", "version": 1, "profiles": PROFILES, "source": SOURCE, "obligation_keys": [x["obligation_key"] for x in OBLIGATIONS]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def _obligation(number, b6_key, title, method, implementation, evaluator, parameters, nist_control):
    focal, iso_id = RELATIONSHIPS[nist_control]
    return {"assessment_obligation_id": f"9c1d2f0d-4c28-5c7d-9b7d-{number:012d}", "assessment_pack_version_id": PACK_ID, "obligation_key": f"iso27001-{iso_id.lower()}-{b6_key}", "title": title, "applicability": {"profile_version_ids": PROFILES, "scope_note": "Reuse native EffectiveState scope only; missing, conflicting, or multiple scopes are UNKNOWN."}, "assessment_method": method, "implementation_status": implementation, "evaluator_rule_id": evaluator, "policy_parameters": parameters, "source_reference": {**SOURCE, "nist_control_id": nist_control, "olir_focal_element_id": focal, "iso_annex_a_control_id": iso_id, "local_alignment_label": title}}

OBLIGATIONS = [
    _obligation(901, "remote-ssh-enabled", "Local technical alignment: remote SSH evidence", "automatic", "implemented", "management.ssh.enabled", {"required_canonical_fields": ["management.remote.ssh.enabled"]}, "AC-17"),
    _obligation(902, "telnet-disabled", "Local technical alignment: insecure remote access disabled", "automatic", "implemented", "management.telnet.disabled", {"required_canonical_fields": ["management.remote.telnet.enabled"]}, "AC-17"),
    _obligation(903, "ssh-v2", "Local technical alignment: supported SSH protocol version", "automatic", "implemented", "management.ssh.version_2", {"required_canonical_fields": ["management.remote.ssh.version"]}, "AC-17"),
    _obligation(904, "idle-timeout", "Local technical alignment: administrative idle timeout", "automatic", "implemented", "management.idle_timeout.maximum", {"required_canonical_fields": ["management.session.idle_timeout"], "maximum_admin_idle_timeout_seconds": 900}, "AC-11"),
    _obligation(905, "logging-enabled", "Local technical alignment: logging enabled", "automatic", "implemented", "logging.enabled", {"required_canonical_fields": ["logging.enabled"]}, "AU-12"),
    _obligation(906, "remote-logging", "Local technical alignment: remote logging destination", "automatic", "implemented", "logging.remote.destination.configured", {"required_canonical_fields": ["logging.remote.destination"]}, "AU-12"),
    _obligation(907, "ntp-configured", "Local technical alignment: time configuration", "automatic", "implemented", "time.ntp.configured", {"required_canonical_fields": ["time.ntp.configured"]}, "AU-8"),
    _obligation(908, "ntp-server", "Local technical alignment: configured time source", "automatic", "implemented", "time.ntp.server.configured", {"required_canonical_fields": ["time.ntp.server"]}, "AU-8"),
    _obligation(909, "authorization-review", "Local technical alignment: remote-access authorization review", "manual", "manual", None, {"required_canonical_fields": []}, "AC-17"),
    _obligation(910, "audit-event-review", "Local technical alignment: audit-event review", "manual", "manual", None, {"required_canonical_fields": []}, "AU-12"),
]

def upgrade() -> None:
    now = datetime.now(timezone.utc)
    op.bulk_insert(sa.table("assessment_pack_versions", sa.column("assessment_pack_version_id", sa.Uuid()), sa.column("organization_id", sa.Uuid()), sa.column("pack_key", sa.String()), sa.column("family", sa.String()), sa.column("name", sa.String()), sa.column("version", sa.Integer()), sa.column("profile_version_ids", postgresql.JSONB()), sa.column("source_metadata", postgresql.JSONB()), sa.column("source_version_label", sa.String()), sa.column("content_digest", sa.String()), sa.column("applicability", postgresql.JSONB()), sa.column("status", sa.String()), sa.column("published_at", sa.DateTime()), sa.column("created_at", sa.DateTime())), [{"assessment_pack_version_id": PACK_ID, "organization_id": None, "pack_key": "iso27001_2022_nist_olir_technical_alignment", "family": "ISO/IEC 27001 Alignment", "name": "ISO/IEC 27001:2022 — NIST OLIR-Derived Technical Alignment", "version": 1, "profile_version_ids": PROFILES, "source_metadata": SOURCE, "source_version_label": "ISO27001:2022-OLIR-1.0.0", "content_digest": _digest(), "applicability": {"profile_version_ids": PROFILES}, "status": "published", "published_at": now, "created_at": now}])
    op.bulk_insert(sa.table("assessment_obligations", sa.column("assessment_obligation_id", sa.Uuid()), sa.column("assessment_pack_version_id", sa.Uuid()), sa.column("obligation_key", sa.String()), sa.column("title", sa.String()), sa.column("applicability", postgresql.JSONB()), sa.column("assessment_method", sa.String()), sa.column("implementation_status", sa.String()), sa.column("evaluator_rule_id", sa.String()), sa.column("policy_parameters", postgresql.JSONB()), sa.column("source_reference", postgresql.JSONB()), sa.column("created_at", sa.DateTime())), [{**x, "created_at": now} for x in OBLIGATIONS])

def downgrade() -> None:
    op.execute("ALTER TABLE assessment_obligations DISABLE TRIGGER trg_assessment_obligations_immutable"); op.execute("ALTER TABLE assessment_pack_versions DISABLE TRIGGER trg_assessment_pack_versions_immutable")
    op.execute(sa.text("DELETE FROM assessment_obligations WHERE assessment_pack_version_id = :pack_id").bindparams(pack_id=PACK_ID)); op.execute(sa.text("DELETE FROM assessment_pack_versions WHERE assessment_pack_version_id = :pack_id").bindparams(pack_id=PACK_ID))
    op.execute("ALTER TABLE assessment_obligations ENABLE TRIGGER trg_assessment_obligations_immutable"); op.execute("ALTER TABLE assessment_pack_versions ENABLE TRIGGER trg_assessment_pack_versions_immutable")
