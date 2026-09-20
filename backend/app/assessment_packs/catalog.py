from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import re
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import AssessmentObligation, AssessmentPackVersion


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


def validate_persisted_obligation(obligation: Any) -> None:
    values = (
        obligation.framework_version, obligation.source_url, obligation.source_digest,
        obligation.control_id, obligation.title, obligation.severity, obligation.scope,
    )
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError("Catalog obligation provenance is incomplete")
    if not obligation.source_url.startswith("https://") or len(obligation.source_digest) < 32:
        raise ValueError("Catalog obligation provenance is invalid")
