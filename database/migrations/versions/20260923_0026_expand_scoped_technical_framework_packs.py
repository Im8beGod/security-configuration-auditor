"""Publish immutable Stage 6 NIST and ISO scoped technical pack versions."""

from collections.abc import Sequence
from datetime import datetime, timezone
from hashlib import sha256
import json

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260923_0026"
down_revision: str | Sequence[str] | None = "20260923_0025"
branch_labels = depends_on = None

NIST_PREVIOUS_ID = "a4600000-0000-5000-8000-000000000001"
ISO_PREVIOUS_ID = "a4600000-0000-5000-8000-000000000003"
NIST_PACK_ID = "a4600000-0000-5000-8000-000000000011"
ISO_PACK_ID = "a4600000-0000-5000-8000-000000000012"
NIST_URL = "https://raw.githubusercontent.com/usnistgov/oscal-content/78650f02ad9321bb7b817846f8fbd4f2bcd620de/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
NIST_DIGEST = "01f37cf90ea99d92242c936cbfbdebcc338eef1f71454e2acac36cc56e9bc062"
OLIR_URL = "https://csrc.nist.gov/projects/olir/informative-reference-catalog/details?referenceId=155"
OLIR_DIGEST = "E631DE234A1FAC057991773F015C221226940540F5602E1B70A3768EAFF5CBD9"


def _digest(previous_pack_version_id: str, additions: list[dict]) -> str:
    return sha256(json.dumps({"previous_pack_version_id": previous_pack_version_id, "additions": additions}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


NIST_ADDITIONS = [
    {"id": "a4600000-0000-5001-8000-000000000011", "key": "ac-17.management-source-restriction", "title": "Management source restriction explicitly configured", "rule": "management.source.restriction.configured", "field": "management.remote.source.restriction.configured", "profiles": ["cisco.ios_xe.17@1.0.0", "fortinet.fortios.7@1.0.0", "arista.eos.4@1.0.0"], "severity": "not_assigned"},
    {"id": "a4600000-0000-5001-8000-000000000012", "key": "ac-17.http-disabled", "title": "HTTP management access explicitly disabled", "rule": "management.http.disabled", "field": "management.remote.http.enabled", "profiles": ["cisco.ios_xe.17@1.0.0", "fortinet.fortios.7@1.0.0"], "severity": "not_assigned"},
    {"id": "a4600000-0000-5001-8000-000000000013", "key": "ac-17.https-enabled", "title": "HTTPS management access explicitly enabled", "rule": "management.https.enabled", "field": "management.remote.https.enabled", "profiles": ["fortinet.fortios.7@1.0.0"], "severity": "not_assigned"},
    {"id": "a4600000-0000-5001-8000-000000000014", "key": "ac-17.tls-minimum-1-2", "title": "Administrative TLS minimum version is 1.2 or later", "rule": "management.tls.minimum_1_2", "field": "management.remote.tls.minimum_version", "profiles": ["fortinet.fortios.7@1.0.0"], "severity": "not_assigned"},
]

ISO_ADDITIONS = [
    {**item, "id": item["id"].replace("5001", "5002"), "key": f"iso27001-a.5.14-{item['key'].removeprefix('ac-17.')}", "title": f"Local technical alignment: {item['title'].lower()}"}
    for item in NIST_ADDITIONS
]


def _pack_table():
    return sa.table("assessment_pack_versions", sa.column("assessment_pack_version_id", sa.Uuid()), sa.column("organization_id", sa.Uuid()), sa.column("pack_key", sa.String()), sa.column("family", sa.String()), sa.column("name", sa.String()), sa.column("version", sa.Integer()), sa.column("profile_version_ids", postgresql.JSONB()), sa.column("source_metadata", postgresql.JSONB()), sa.column("source_version_label", sa.String()), sa.column("content_digest", sa.String()), sa.column("applicability", postgresql.JSONB()), sa.column("status", sa.String()), sa.column("published_at", sa.DateTime()), sa.column("created_at", sa.DateTime()), sa.column("schema_version", sa.String()))


def _obligation_table():
    return sa.table("assessment_obligations", sa.column("assessment_obligation_id", sa.Uuid()), sa.column("assessment_pack_version_id", sa.Uuid()), sa.column("obligation_key", sa.String()), sa.column("title", sa.String()), sa.column("framework_version", sa.String()), sa.column("source_url", sa.String()), sa.column("source_digest", sa.String()), sa.column("control_id", sa.String()), sa.column("severity", sa.String()), sa.column("scope", sa.String()), sa.column("applicability", postgresql.JSONB()), sa.column("assessment_method", sa.String()), sa.column("implementation_status", sa.String()), sa.column("evaluator_rule_id", sa.String()), sa.column("policy_parameters", postgresql.JSONB()), sa.column("source_reference", postgresql.JSONB()), sa.column("created_at", sa.DateTime()))


def _clone(previous_id: str, pack_id: str, digest: str, now: datetime) -> None:
    op.execute(sa.text("""
        INSERT INTO assessment_pack_versions (
            assessment_pack_version_id, organization_id, pack_key, family, name, version,
            profile_version_ids, source_metadata, source_version_label, content_digest,
            applicability, status, published_at, created_at, schema_version
        )
        SELECT CAST(:pack_id AS uuid), organization_id, pack_key, family, name, 3,
            profile_version_ids,
            source_metadata || jsonb_build_object('stage6_technical_extension', true),
            source_version_label, :digest, applicability, status, :now, :now, schema_version
        FROM assessment_pack_versions
        WHERE assessment_pack_version_id = CAST(:previous_id AS uuid)
    """).bindparams(pack_id=pack_id, previous_id=previous_id, digest=digest, now=now))
    op.execute(sa.text("""
        INSERT INTO assessment_obligations (
            assessment_obligation_id, assessment_pack_version_id, obligation_key, title,
            framework_version, source_url, source_digest, control_id, severity, scope,
            applicability, assessment_method, implementation_status, evaluator_rule_id,
            policy_parameters, source_reference, created_at
        )
        SELECT CAST(md5(:pack_id || ':' || obligation_key) AS uuid), CAST(:pack_id AS uuid),
            obligation_key, title, framework_version, source_url, source_digest, control_id,
            severity, scope, applicability, assessment_method, implementation_status,
            evaluator_rule_id, policy_parameters, source_reference, :now
        FROM assessment_obligations
        WHERE assessment_pack_version_id = CAST(:previous_id AS uuid)
    """).bindparams(pack_id=pack_id, previous_id=previous_id, now=now))


def _new_rows(pack_id: str, additions: list[dict], *, iso: bool) -> list[dict]:
    rows = []
    for item in additions:
        if iso:
            reference = {
                "framework": "ISO/IEC 27001:2022 NIST OLIR-Derived Technical Alignment",
                "iso_open_data_url": "https://www.iso.org/open-data.html",
                "iso_reference": "ISO/IEC 27001:2022", "olir_version": "1.0.0",
                "official_source_url": OLIR_URL, "olir_sha3_256": OLIR_DIGEST,
                "nist_control_id": "AC-17", "olir_focal_element_id": "AC-17",
                "iso_annex_a_control_id": "A.5.14",
                "relationship_disclaimer": "NIST OLIR is an informative crosswalk; mappings do not establish control equivalence or ISO conformity.",
                "implementation_rationale": "Bounded device-configuration evidence only; no ISO conformity claim is made.",
            }
            framework_version, source_url, source_digest, control = "ISO/IEC 27001:2022 / OLIR 1.0.0", OLIR_URL, OLIR_DIGEST, "A.5.14"
        else:
            reference = {
                "framework": "NIST SP 800-53", "revision": "Rev. 5", "catalog_version": "5.2.0",
                "official_source_url": NIST_URL, "source_sha256": NIST_DIGEST,
                "control_id": "AC-17", "control_title": "Remote Access",
                "implementation_rationale": "Bounded device-configuration evidence only; organizational remote-access authorization remains manual.",
            }
            framework_version, source_url, source_digest, control = "Rev. 5", NIST_URL, NIST_DIGEST, "AC-17"
        rows.append({
            "assessment_obligation_id": item["id"], "assessment_pack_version_id": pack_id,
            "obligation_key": item["key"], "title": item["title"],
            "framework_version": framework_version, "source_url": source_url,
            "source_digest": source_digest, "control_id": control,
            "severity": item["severity"], "scope": "Scoped device configuration technical evidence only",
            "applicability": {"profile_version_ids": item["profiles"], "scope_note": "Evaluate native EffectiveState scope only; missing, conflicting, unresolved, or multiple scopes are UNKNOWN."},
            "assessment_method": "automatic", "implementation_status": "implemented",
            "evaluator_rule_id": item["rule"],
            "policy_parameters": {"required_canonical_fields": [item["field"]]},
            "source_reference": reference,
        })
    return rows


def upgrade() -> None:
    now = datetime.now(timezone.utc)
    _clone(NIST_PREVIOUS_ID, NIST_PACK_ID, _digest(NIST_PREVIOUS_ID, NIST_ADDITIONS), now)
    _clone(ISO_PREVIOUS_ID, ISO_PACK_ID, _digest(ISO_PREVIOUS_ID, ISO_ADDITIONS), now)
    rows = _new_rows(NIST_PACK_ID, NIST_ADDITIONS, iso=False) + _new_rows(ISO_PACK_ID, ISO_ADDITIONS, iso=True)
    op.bulk_insert(_obligation_table(), [{**row, "created_at": now} for row in rows])


def downgrade() -> None:
    op.execute("ALTER TABLE assessment_obligations DISABLE TRIGGER trg_assessment_obligations_immutable")
    op.execute("ALTER TABLE assessment_pack_versions DISABLE TRIGGER trg_assessment_pack_versions_immutable")
    for pack_id in (ISO_PACK_ID, NIST_PACK_ID):
        op.execute(sa.text("DELETE FROM assessment_obligations WHERE assessment_pack_version_id = CAST(:pack_id AS uuid)").bindparams(pack_id=pack_id))
        op.execute(sa.text("DELETE FROM assessment_pack_versions WHERE assessment_pack_version_id = CAST(:pack_id AS uuid)").bindparams(pack_id=pack_id))
    op.execute("ALTER TABLE assessment_obligations ENABLE TRIGGER trg_assessment_obligations_immutable")
    op.execute("ALTER TABLE assessment_pack_versions ENABLE TRIGGER trg_assessment_pack_versions_immutable")
