from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from math import isfinite
from pathlib import Path
import re
from typing import Any, Callable
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import AssessmentObligation, AssessmentPackVersion
from app.compliance.rule_registry import RULE_PACK_BY_PROFILE
from app.profile_resolution import PROFILE_REGISTRY
from app.profile_resolution.runtime import RuntimeProfileError, profile_for
from app.compliance.runtime_rules import RuntimeRuleError, runtime_rule_for


CATALOG_DIRECTORY = Path(__file__).resolve().parent
CATALOG_FILES = {
    "nist": ("nist_sp80053_rev5_subset.json", "controls"),
    "disa": ("disa_ndm_srg_v5r5_subset.json", "rules"),
    "cis": ("cis_cisco_ios_xe_17_v2_2_1_subset.json", "recommendations"),
    "iso": ("iso27001_2022_nist_olir_subset.json", "relationships"),
}
MAX_EXTERNAL_CATALOG_BYTES = 10 * 1024 * 1024
MAX_EXTERNAL_CONTROLS = 20_000
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,254}")


class CatalogImportError(ValueError):
    pass


@dataclass(frozen=True)
class SourceCatalog:
    framework: str
    metadata: dict[str, Any]
    obligations: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class ExternalCatalog:
    framework: str
    catalog_id: str
    name: str
    source_version: str
    source_url: str
    source_digest: str
    profile_version_ids: tuple[str, ...]
    controls: tuple[dict[str, str], ...]


@dataclass(frozen=True)
class RuntimeCatalog:
    pack_key: str
    family: str
    name: str
    version: int
    source_version: str
    source_url: str
    source_digest: str
    profile_version_ids: tuple[str, ...]
    obligations: tuple[dict[str, Any], ...]


def load_source_catalog(framework: str) -> SourceCatalog:
    try:
        filename, collection = CATALOG_FILES[framework]
    except KeyError as exc:
        raise ValueError("Unsupported source catalog") from exc
    payload = json.loads((CATALOG_DIRECTORY / filename).read_text(encoding="utf-8"))
    obligations = payload.get(collection)
    if not isinstance(obligations, list) or not obligations or any(not isinstance(item, dict) for item in obligations):
        raise ValueError("Source catalog has no bounded obligations")
    serialized = json.dumps(payload, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > 2 * 1024 * 1024:
        raise ValueError("Source catalog exceeds the bounded import size")
    return SourceCatalog(framework, payload, tuple(obligations))


def load_all_source_catalogs() -> tuple[SourceCatalog, ...]:
    return tuple(load_source_catalog(item) for item in CATALOG_FILES)


def parse_external_catalog(content: bytes, filename: str) -> ExternalCatalog:
    if not content or len(content) > MAX_EXTERNAL_CATALOG_BYTES:
        raise CatalogImportError("Catalog file size is invalid")
    try:
        payload = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogImportError("Catalog must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0.0":
        raise CatalogImportError("Catalog schema_version must be 1.0.0")
    framework = str(payload.get("framework", "")).strip().lower()
    if framework not in {"cis", "iso"}:
        raise CatalogImportError("Only CIS and ISO external catalogs are supported")
    catalog_id = str(payload.get("catalog_id", "")).strip()
    name = str(payload.get("name", "")).strip()
    source_version = str(payload.get("source_version", "")).strip()
    source_url = str(payload.get("source_url", "")).strip()
    profiles = payload.get("profile_version_ids")
    controls = payload.get("controls")
    if (
        not _IDENTIFIER.fullmatch(catalog_id)
        or not name or len(name) > 255
        or not source_version or len(source_version) > 128
        or not source_url.startswith("https://") or len(source_url) > 2048
        or not isinstance(profiles, list) or not profiles or len(profiles) > 32
        or any(not isinstance(item, str) or not item.strip() or len(item) > 255 for item in profiles)
        or not isinstance(controls, list) or not controls or len(controls) > MAX_EXTERNAL_CONTROLS
    ):
        raise CatalogImportError("Catalog identity or provenance is invalid")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for control in controls:
        if not isinstance(control, dict) or control.get("evaluator_rule_id") is not None:
            raise CatalogImportError("External controls cannot define automatic evaluators")
        control_id = str(control.get("control_id", "")).strip()
        title = str(control.get("title", "")).strip()
        severity = str(control.get("severity", "not_assigned")).strip()
        scope = str(control.get("scope", "organization-defined")).strip()
        implementation = str(control.get("implementation_status", "manual")).strip().lower()
        if (
            not _IDENTIFIER.fullmatch(control_id) or control_id in seen
            or not title or len(title) > 255
            or not severity or len(severity) > 32
            or not scope or len(scope) > 512
            or implementation not in {"manual", "unimplemented"}
        ):
            raise CatalogImportError("Catalog control is invalid or duplicated")
        seen.add(control_id)
        normalized.append({
            "control_id": control_id, "title": title, "severity": severity,
            "scope": scope, "implementation_status": implementation,
        })
    return ExternalCatalog(
        framework=framework, catalog_id=catalog_id, name=name,
        source_version=source_version, source_url=source_url,
        source_digest=sha256(content).hexdigest(),
        profile_version_ids=tuple(dict.fromkeys(item.strip() for item in profiles)),
        controls=tuple(normalized),
    )


def import_external_catalog(
    db: Session, organization_id: UUID, content: bytes, filename: str,
) -> tuple[AssessmentPackVersion, dict[str, int]]:
    catalog = parse_external_catalog(content, filename)
    family = "CIS Benchmark" if catalog.framework == "cis" else "ISO/IEC 27001 Alignment"
    pack_key = f"external.{catalog.framework}.{catalog.catalog_id}"
    version = (db.scalar(select(func.max(AssessmentPackVersion.version)).where(
        AssessmentPackVersion.organization_id == organization_id,
        AssessmentPackVersion.pack_key == pack_key,
    )) or 0) + 1
    now = datetime.now(timezone.utc)
    pack = AssessmentPackVersion(
        organization_id=organization_id, pack_key=pack_key, family=family,
        name=catalog.name, version=version,
        profile_version_ids=list(catalog.profile_version_ids),
        source_metadata={
            "official_source_url": catalog.source_url,
            "source_sha256": catalog.source_digest,
            "source_version": catalog.source_version,
            "import_filename": Path(filename).name,
            "import_mode": "external_manual_only",
        },
        source_version_label=catalog.source_version,
        content_digest=catalog.source_digest,
        applicability={"profile_version_ids": list(catalog.profile_version_ids)},
        status="published", published_at=now,
    )
    db.add(pack)
    db.flush()
    counts = {"manual": 0, "unimplemented": 0}
    for control in catalog.controls:
        implementation = control["implementation_status"]
        counts[implementation] += 1
        db.add(AssessmentObligation(
            assessment_pack_version_id=pack.assessment_pack_version_id,
            obligation_key=control["control_id"], title=control["title"],
            framework_version=catalog.source_version,
            source_url=catalog.source_url, source_digest=catalog.source_digest,
            control_id=control["control_id"], severity=control["severity"],
            scope=control["scope"],
            applicability={"profile_version_ids": list(catalog.profile_version_ids)},
            assessment_method="manual", implementation_status=implementation,
            evaluator_rule_id=None, policy_parameters={},
            source_reference={
                "control_id": control["control_id"],
                "official_source_url": catalog.source_url,
                "catalog_version": catalog.source_version,
                "source_sha256": catalog.source_digest,
                "import_filename": Path(filename).name,
            },
        ))
    db.flush()
    return pack, counts


def _runtime_text(value: Any, label: str, *, limit: int) -> str:
    normalized = value.strip() if isinstance(value, str) else ""
    if not normalized or len(normalized) > limit:
        raise CatalogImportError(f"Runtime catalog {label} is invalid")
    return normalized


def _runtime_profiles(value: Any, *, profile_lookup: Callable[[str], object | None], allowed: set[str] | None = None) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 32:
        raise CatalogImportError("Runtime catalog profile applicability is invalid")
    profiles = tuple(dict.fromkeys(_runtime_text(item, "profile", limit=255) for item in value))
    if any(profile_lookup(item) is None for item in profiles):
        raise CatalogImportError("Runtime catalog references an unsupported profile")
    if allowed is not None and not set(profiles).issubset(allowed):
        raise CatalogImportError("Runtime obligation applicability exceeds the pack profiles")
    return profiles


def _runtime_rule(rule_id: str, profiles: tuple[str, ...], rule_lookup=None):
    rules = []
    for profile_version_id in profiles:
        if rule_lookup is None:
            pack = RULE_PACK_BY_PROFILE.get(profile_version_id)
            rule = next((item for item in (pack.rules if pack else ()) if item.rule_id == rule_id), None)
            if rule is None:
                raise CatalogImportError("Runtime obligation evaluator is unavailable for an applicable profile")
        else:
            try:
                rule = rule_lookup(rule_id, profile_version_id)
            except RuntimeRuleError as exc:
                raise CatalogImportError("Runtime obligation evaluator is unavailable for an applicable profile") from exc
        rules.append(rule)
    first = rules[0]
    if any(
        item.required_effective_states != first.required_effective_states
        or item.condition != first.condition
        or item.required_policy_parameters != first.required_policy_parameters
        for item in rules[1:]
    ):
        raise CatalogImportError("Runtime obligation evaluator differs between applicable profiles")
    return first


def _runtime_policy(value: Any, rule: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict) or any(not isinstance(key, str) or not key for key in value):
        raise CatalogImportError("Runtime obligation policy parameters are invalid")
    policy = dict(value)
    required_fields = list(rule.required_effective_states)
    supplied_fields = policy.pop("required_canonical_fields", required_fields)
    if not isinstance(supplied_fields, list) or supplied_fields != required_fields:
        raise CatalogImportError("Runtime obligation canonical evidence requirements are invalid")
    policy["required_canonical_fields"] = required_fields
    permitted = set(rule.required_policy_parameters) | {"expected", "required_canonical_fields"}
    if not set(policy).issubset(permitted) or any(key not in policy for key in rule.required_policy_parameters):
        raise CatalogImportError("Runtime obligation policy parameters do not match its evaluator")
    for key in rule.required_policy_parameters:
        parameter = policy[key]
        if isinstance(parameter, bool) or not isinstance(parameter, (int, float, list)):
            raise CatalogImportError("Runtime obligation evaluator parameter is invalid")
        if isinstance(parameter, (int, float)) and not isfinite(parameter):
            raise CatalogImportError("Runtime obligation evaluator parameter is invalid")
        if key in {"maximum_admin_idle_timeout_seconds"} and (not isinstance(parameter, (int, float)) or parameter <= 0):
            raise CatalogImportError("Runtime obligation timeout parameter is invalid")
        if isinstance(parameter, list) and not all(isinstance(item, str) and item for item in parameter):
            raise CatalogImportError("Runtime obligation allow-list parameter is invalid")
    if "expected" in policy:
        expected = rule.condition.get("expected")
        if expected is None or type(policy["expected"]) is not type(expected) or (
            isinstance(policy["expected"], float) and not isfinite(policy["expected"])
        ):
            raise CatalogImportError("Runtime obligation expected value is invalid")
    return policy


def parse_runtime_catalog(
    content: bytes, filename: str, *,
    profile_lookup: Callable[[str], object | None] = PROFILE_REGISTRY.get,
    rule_lookup=None,
) -> RuntimeCatalog:
    """Validate the bounded JSON schema used for tenant-published assessment packs."""
    if not content or len(content) > MAX_EXTERNAL_CATALOG_BYTES:
        raise CatalogImportError("Runtime catalog file size is invalid")
    try:
        payload = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogImportError("Runtime catalog must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0.0":
        raise CatalogImportError("Runtime catalog schema_version must be 1.0.0")
    pack_key = _runtime_text(payload.get("pack_key"), "pack key", limit=255)
    if not _IDENTIFIER.fullmatch(pack_key):
        raise CatalogImportError("Runtime catalog pack key is invalid")
    family = _runtime_text(payload.get("family"), "family", limit=128)
    name = _runtime_text(payload.get("name"), "name", limit=255)
    source_version = _runtime_text(payload.get("source_version"), "source version", limit=128)
    source_url = _runtime_text(payload.get("source_url"), "source URL", limit=2048)
    version = payload.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1 or not source_url.startswith("https://"):
        raise CatalogImportError("Runtime catalog identity or provenance is invalid")
    try:
        profiles = _runtime_profiles(payload.get("profile_version_ids"), profile_lookup=profile_lookup)
    except RuntimeProfileError as exc:
        raise CatalogImportError("Runtime catalog references an unsupported profile") from exc
    raw_obligations = payload.get("obligations")
    if not isinstance(raw_obligations, list) or not raw_obligations or len(raw_obligations) > MAX_EXTERNAL_CONTROLS:
        raise CatalogImportError("Runtime catalog must contain bounded obligations")
    normalized: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    seen_controls: set[str] = set()
    for item in raw_obligations:
        if not isinstance(item, dict):
            raise CatalogImportError("Runtime obligation is invalid")
        obligation_key = _runtime_text(item.get("obligation_key"), "obligation key", limit=255)
        control_id = _runtime_text(item.get("control_id"), "control ID", limit=255)
        if not _IDENTIFIER.fullmatch(obligation_key) or not _IDENTIFIER.fullmatch(control_id) or obligation_key in seen_keys or control_id in seen_controls:
            raise CatalogImportError("Runtime obligation or control ID is invalid or duplicated")
        method = _runtime_text(item.get("assessment_method"), "assessment method", limit=16).lower()
        implementation = _runtime_text(item.get("implementation_status"), "implementation status", limit=16).lower()
        if method not in {"automatic", "manual"} or implementation not in {"implemented", "manual", "unimplemented"}:
            raise CatalogImportError("Runtime obligation assessment status is invalid")
        try:
            applicable_profiles = _runtime_profiles(
                item.get("profile_version_ids", list(profiles)),
                profile_lookup=profile_lookup, allowed=set(profiles),
            )
        except RuntimeProfileError as exc:
            raise CatalogImportError("Runtime catalog references an unsupported profile") from exc
        evaluator = item.get("evaluator_rule_id")
        if method == "automatic" and implementation == "implemented":
            evaluator = _runtime_text(evaluator, "evaluator rule ID", limit=255)
            rule = _runtime_rule(evaluator, applicable_profiles, rule_lookup)
            policy = _runtime_policy(item.get("policy_parameters"), rule)
        elif evaluator is not None or method != "manual" or implementation == "implemented":
            raise CatalogImportError("Manual or unimplemented obligations cannot define automatic evaluators")
        else:
            if item.get("policy_parameters") not in (None, {}):
                raise CatalogImportError("Manual or unimplemented obligations cannot define evaluator policy")
            evaluator, policy = None, {}
        seen_keys.add(obligation_key)
        seen_controls.add(control_id)
        normalized.append({
            "obligation_key": obligation_key, "control_id": control_id,
            "title": _runtime_text(item.get("title"), "title", limit=255),
            "severity": _runtime_text(item.get("severity", "not_assigned"), "severity", limit=32),
            "scope": _runtime_text(item.get("scope", "organization-defined"), "scope", limit=512),
            "assessment_method": method, "implementation_status": implementation,
            "evaluator_rule_id": evaluator, "policy_parameters": policy,
            "profile_version_ids": applicable_profiles,
        })
    return RuntimeCatalog(
        pack_key=pack_key, family=family, name=name, version=version,
        source_version=source_version, source_url=source_url,
        source_digest=sha256(content).hexdigest(), profile_version_ids=profiles,
        obligations=tuple(normalized),
    )


def runtime_catalog_preview(catalog: RuntimeCatalog) -> dict[str, Any]:
    counts = {"automatic": 0, "manual": 0, "unimplemented": 0}
    for obligation in catalog.obligations:
        if obligation["assessment_method"] == "automatic":
            counts["automatic"] += 1
        else:
            counts[obligation["implementation_status"]] += 1
    return {
        "pack_key": catalog.pack_key, "family": catalog.family, "name": catalog.name,
        "version": catalog.version, "source_version": catalog.source_version,
        "source_url": catalog.source_url, "source_digest": catalog.source_digest,
        "profile_version_ids": list(catalog.profile_version_ids),
        "obligation_count": len(catalog.obligations), **counts,
    }


def publish_runtime_catalog(db: Session, organization_id: UUID, catalog: RuntimeCatalog, filename: str) -> AssessmentPackVersion:
    try:
        if any(profile_for(db, organization_id, profile_id) is None for profile_id in catalog.profile_version_ids):
            raise CatalogImportError("Runtime catalog references an unsupported profile")
    except RuntimeProfileError as exc:
        raise CatalogImportError("Runtime catalog references an unsupported profile") from exc
    for obligation in catalog.obligations:
        if obligation["assessment_method"] == "automatic":
            _runtime_rule(obligation["evaluator_rule_id"], tuple(obligation["profile_version_ids"]), lambda rule_id, profile_id: runtime_rule_for(db, organization_id, rule_id, profile_id))
    existing = db.scalar(select(AssessmentPackVersion.assessment_pack_version_id).where(
        AssessmentPackVersion.organization_id == organization_id,
        AssessmentPackVersion.pack_key == catalog.pack_key,
        AssessmentPackVersion.version == catalog.version,
    ))
    if existing is not None:
        raise CatalogImportError("Runtime catalog pack version is already published")
    now = datetime.now(timezone.utc)
    pack = AssessmentPackVersion(
        organization_id=organization_id, pack_key=catalog.pack_key, family=catalog.family,
        name=catalog.name, version=catalog.version, profile_version_ids=list(catalog.profile_version_ids),
        source_metadata={
            "official_source_url": catalog.source_url, "source_sha256": catalog.source_digest,
            "source_version": catalog.source_version, "import_filename": Path(filename).name,
            "import_mode": "runtime_validated_json",
        }, source_version_label=catalog.source_version, content_digest=catalog.source_digest,
        applicability={"profile_version_ids": list(catalog.profile_version_ids)},
        status="published", published_at=now,
    )
    db.add(pack)
    db.flush()
    for obligation in catalog.obligations:
        db.add(AssessmentObligation(
            assessment_pack_version_id=pack.assessment_pack_version_id,
            obligation_key=obligation["obligation_key"], title=obligation["title"],
            framework_version=catalog.source_version, source_url=catalog.source_url,
            source_digest=catalog.source_digest, control_id=obligation["control_id"],
            severity=obligation["severity"], scope=obligation["scope"],
            applicability={"profile_version_ids": list(obligation["profile_version_ids"])},
            assessment_method=obligation["assessment_method"],
            implementation_status=obligation["implementation_status"],
            evaluator_rule_id=obligation["evaluator_rule_id"],
            policy_parameters=obligation["policy_parameters"],
            source_reference={
                "control_id": obligation["control_id"], "official_source_url": catalog.source_url,
                "catalog_version": catalog.source_version, "source_sha256": catalog.source_digest,
                "import_filename": Path(filename).name,
            },
        ))
    db.flush()
    return pack


def validate_persisted_obligation(obligation: Any) -> None:
    values = (
        obligation.framework_version, obligation.source_url, obligation.source_digest,
        obligation.control_id, obligation.title, obligation.severity, obligation.scope,
    )
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError("Catalog obligation provenance is incomplete")
    if not obligation.source_url.startswith("https://") or len(obligation.source_digest) < 32:
        raise ValueError("Catalog obligation provenance is invalid")
