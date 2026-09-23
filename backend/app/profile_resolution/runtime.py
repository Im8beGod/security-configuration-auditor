"""Tenant-scoped, declarative runtime profile manifests."""

import json
import re
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
from types import MappingProxyType
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import ArtifactEvidenceType, DeviceClass, ProfileManifestVersion
from app.profile_resolution.registry import ProfileManifest, VersionConstraint, XmlIdentitySelector, PROFILE_REGISTRY


_IDENTIFIER = re.compile(r"[a-z][a-z0-9._-]{0,127}")
_SEMVER = re.compile(r"\d+\.\d+\.\d+")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,63}")
_READERS = {
    "indentation_cli.v1": frozenset({ArtifactEvidenceType.CONFIGURATION, ArtifactEvidenceType.UNKNOWN_EVIDENCE}),
    "xml_tree.v1": frozenset({ArtifactEvidenceType.STRUCTURED_EXPORT}),
    "json_tree.v1": frozenset({ArtifactEvidenceType.STRUCTURED_EXPORT}),
}
_CAPABILITIES = frozenset({"structural_parsing", "semantic_interpretation", "effective_state_resolution", "administrator_training"})


class RuntimeProfileError(ValueError):
    pass


def _text(value: Any, label: str, limit: int = 255) -> str:
    result = value.strip() if isinstance(value, str) else ""
    if not result or len(result) > limit:
        raise RuntimeProfileError(f"Profile {label} is invalid")
    return result


def _version(value: Any) -> tuple[int, ...] | None:
    if value is None:
        return None
    text = _text(value, "version constraint", 64)
    parsed = VersionConstraint.parse(text)
    if parsed is None:
        raise RuntimeProfileError("Profile version constraint is invalid")
    return parsed


def _selectors(value: Any, reader: str) -> tuple[XmlIdentitySelector, ...]:
    if value is None:
        return ()
    if reader != "xml_tree.v1" or not isinstance(value, list) or len(value) > 4:
        raise RuntimeProfileError("Profile identity selectors are invalid")
    selectors = []
    for item in value:
        if not isinstance(item, dict):
            raise RuntimeProfileError("Profile identity selector is invalid")
        field = item.get("field")
        path = item.get("path")
        source = item.get("source", "text")
        attribute = item.get("attribute")
        if field not in {"os_version", "hostname", "model", "serial_number"} or not isinstance(path, list) or not path or len(path) > 8 or any(not isinstance(part, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", part) for part in path):
            raise RuntimeProfileError("Profile identity selector is invalid")
        if source not in {"text", "attribute"} or (source == "attribute" and not isinstance(attribute, str)):
            raise RuntimeProfileError("Profile identity selector is invalid")
        selectors.append(XmlIdentitySelector(field, tuple(path), source=source, attribute=attribute))
    if len({item.field for item in selectors}) != len(selectors):
        raise RuntimeProfileError("Profile identity selectors are duplicated")
    return tuple(selectors)


def parse_runtime_profile(content: bytes) -> ProfileManifest:
    if not content or len(content) > 128 * 1024:
        raise RuntimeProfileError("Profile manifest size is invalid")
    try:
        raw = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeProfileError("Profile manifest must be valid UTF-8 JSON") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != "1.0.0":
        raise RuntimeProfileError("Profile manifest schema_version must be 1.0.0")
    profile_id = _text(raw.get("profile_id"), "ID")
    profile_version = _text(raw.get("profile_version"), "version", 32)
    if not _IDENTIFIER.fullmatch(profile_id) or not _SEMVER.fullmatch(profile_version):
        raise RuntimeProfileError("Profile identity is invalid")
    if raw.get("profile_version_id") != f"{profile_id}@{profile_version}":
        raise RuntimeProfileError("Profile version identity is invalid")
    reader = raw.get("structural_reader")
    if reader not in _READERS:
        raise RuntimeProfileError("Profile structural reader is unsupported")
    evidence = raw.get("evidence_types")
    if not isinstance(evidence, list) or not evidence:
        raise RuntimeProfileError("Profile evidence types are invalid")
    try:
        evidence_types = frozenset(ArtifactEvidenceType(item) for item in evidence)
    except (TypeError, ValueError) as exc:
        raise RuntimeProfileError("Profile evidence types are invalid") from exc
    if not evidence_types.issubset(_READERS[reader]):
        raise RuntimeProfileError("Profile evidence types are incompatible with its reader")
    detection = raw.get("detection")
    if not isinstance(detection, dict):
        raise RuntimeProfileError("Profile detection is required")
    tokens = detection.get("tokens")
    version_prefix = detection.get("version_prefix", "version")
    if not isinstance(tokens, list) or not (1 <= len(tokens) <= 4) or any(not isinstance(item, str) or not _TOKEN.fullmatch(item) for item in tokens) or not isinstance(version_prefix, str) or not _TOKEN.fullmatch(version_prefix):
        raise RuntimeProfileError("Profile detection is invalid")
    constraints = raw.get("version_constraints", {})
    if not isinstance(constraints, dict):
        raise RuntimeProfileError("Profile version constraints are invalid")
    majors = constraints.get("supported_major_versions", [])
    if not isinstance(majors, list) or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in majors):
        raise RuntimeProfileError("Profile version constraints are invalid")
    excluded = constraints.get("excluded_versions", [])
    if not isinstance(excluded, list) or any(VersionConstraint.parse(item) is None for item in excluded if isinstance(item, str)) or any(not isinstance(item, str) for item in excluded):
        raise RuntimeProfileError("Profile version constraints are invalid")
    classes = raw.get("device_classes", ["unknown"])
    try:
        device_classes = frozenset(DeviceClass(item) for item in classes)
    except (TypeError, ValueError) as exc:
        raise RuntimeProfileError("Profile device classes are invalid") from exc
    capabilities = raw.get("capabilities", ["structural_parsing", "semantic_interpretation", "effective_state_resolution", "administrator_training"])
    if not isinstance(capabilities, list) or not capabilities or not set(capabilities).issubset(_CAPABILITIES):
        raise RuntimeProfileError("Profile capabilities are invalid")
    selectors = _selectors(raw.get("identity_selectors"), reader)
    return ProfileManifest(
        profile_id=profile_id, profile_version_id=f"{profile_id}@{profile_version}", profile_version=profile_version,
        vendor=_text(raw.get("vendor"), "vendor"), product_family=_text(raw.get("product_family"), "product"), os=_text(raw.get("os"), "OS"),
        version_constraint=VersionConstraint(frozenset(majors), _version(constraints.get("minimum_version")), _version(constraints.get("maximum_version")), frozenset(excluded)),
        device_classes=device_classes, accepted_evidence_types=evidence_types, structural_reader_name=reader,
        knowledge_pack_name=f"runtime.{profile_id}@{profile_version}", capabilities=frozenset(capabilities),
        coverage_manifest=MappingProxyType({"structural_reader": reader, "canonical_fields": (), "limitations": ("Runtime profiles have only administrator-published mappings; unmapped evidence remains UNKNOWN",)}),
        detection_tokens=tuple(tokens), xml_identity_selectors=selectors, structural_evidence_types=evidence_types,
    )


def runtime_profiles(db: Session, organization_id: UUID) -> tuple[ProfileManifest, ...]:
    rows = db.scalars(select(ProfileManifestVersion).where(ProfileManifestVersion.organization_id == organization_id, ProfileManifestVersion.status == "published").order_by(ProfileManifestVersion.created_at))
    profiles = []
    for row in rows:
        try:
            profiles.append(parse_runtime_profile(json.dumps(row.manifest, sort_keys=True).encode()))
        except RuntimeProfileError:
            continue
    return tuple(profiles)


def profile_for(db: Session, organization_id: UUID, profile_version_id: str) -> ProfileManifest | None:
    row = db.scalar(select(ProfileManifestVersion).where(
        ProfileManifestVersion.organization_id == organization_id,
        ProfileManifestVersion.profile_version_id == profile_version_id,
    ))
    if row is not None:
        if row.status != "published":
            raise RuntimeProfileError("Profile version is not published")
        if PROFILE_REGISTRY.get(profile_version_id) is not None:
            raise RuntimeProfileError("Profile version conflicts with a built-in profile")
        try:
            return parse_runtime_profile(json.dumps(row.manifest, sort_keys=True).encode())
        except RuntimeProfileError as exc:
            raise RuntimeProfileError("Published profile manifest is invalid") from exc
    return PROFILE_REGISTRY.get(profile_version_id)


def publish_runtime_profile(db: Session, organization_id: UUID, profile: ProfileManifest, manifest: dict[str, Any]) -> ProfileManifestVersion:
    if PROFILE_REGISTRY.get(profile.profile_version_id) is not None or db.scalar(select(ProfileManifestVersion.profile_manifest_version_id).where(ProfileManifestVersion.organization_id == organization_id, ProfileManifestVersion.profile_version_id == profile.profile_version_id)) is not None:
        raise RuntimeProfileError("Profile version is already published")
    row = ProfileManifestVersion(organization_id=organization_id, profile_id=profile.profile_id, profile_version_id=profile.profile_version_id, manifest_schema_version="1.0.0", manifest=manifest, status="published", published_at=datetime.now(timezone.utc))
    db.add(row)
    db.flush()
    return row
