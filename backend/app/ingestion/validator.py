import json
from dataclasses import dataclass
from pathlib import PurePath
from xml.etree import ElementTree

from app.db.models import ArtifactContentFamily, ArtifactEvidenceType
from app.ingestion.errors import IngestionError


@dataclass(frozen=True)
class ValidatedEvidence:
    content_family: ArtifactContentFamily
    evidence_type: ArtifactEvidenceType
    encoding: str
    validation_issues: list[dict[str, str]]


def validate_and_classify(data: bytes, filename: str, mime_type: str | None) -> ValidatedEvidence:
    if not data:
        raise IngestionError("empty_file", "Uploaded evidence must not be empty")
    if b"\x00" in data:
        raise IngestionError("unsupported_binary", "Uploaded evidence is not supported text")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise IngestionError("invalid_encoding", "Uploaded evidence must use UTF-8 encoding") from None
    if _looks_binary(text):
        raise IngestionError("unsupported_binary", "Uploaded evidence is not supported text")

    stripped = text.lstrip()
    extension = PurePath(filename).suffix.lower()
    json_hint = stripped.startswith(("{", "[")) or mime_type in {
        "application/json", "text/json"
    } or extension == ".json"
    xml_hint = stripped.startswith("<") or mime_type in {
        "application/xml", "text/xml"
    } or extension == ".xml"
    if json_hint:
        try:
            json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            raise IngestionError("malformed_json", "Uploaded JSON is malformed") from None
        family = ArtifactContentFamily.JSON
    elif xml_hint:
        upper_text = stripped.upper()
        if "<!DOCTYPE" in upper_text or "<!ENTITY" in upper_text:
            raise IngestionError("unsafe_xml", "XML DTD and entity declarations are not allowed")
        try:
            ElementTree.fromstring(text)
        except ElementTree.ParseError:
            raise IngestionError("malformed_xml", "Uploaded XML is malformed") from None
        family = ArtifactContentFamily.XML
    else:
        family = ArtifactContentFamily.TEXT

    return ValidatedEvidence(
        content_family=family,
        evidence_type=_classify_evidence(text, family, extension),
        encoding="utf-8-sig" if data.startswith(b"\xef\xbb\xbf") else "utf-8",
        validation_issues=[],
    )


def _looks_binary(text: str) -> bool:
    if not text:
        return False
    disallowed = sum(ord(character) < 32 and character not in "\n\r\t\f" for character in text)
    return disallowed / len(text) > 0.01


def _classify_evidence(
    text: str, family: ArtifactContentFamily, extension: str
) -> ArtifactEvidenceType:
    if family in {ArtifactContentFamily.JSON, ArtifactContentFamily.XML}:
        return ArtifactEvidenceType.STRUCTURED_EXPORT
    lowered = text.lower()
    if extension in {".cfg", ".conf", ".config"}:
        return ArtifactEvidenceType.CONFIGURATION
    if any(marker in lowered for marker in ("show version", "software version", "firmware version")):
        return ArtifactEvidenceType.VERSION_OUTPUT
    if any(marker in lowered for marker in ("show inventory", "serial number", "hardware inventory")):
        return ArtifactEvidenceType.INVENTORY_OUTPUT
    if any(marker in lowered for marker in ("show interface", "show route", "operational status")):
        return ArtifactEvidenceType.OPERATIONAL_OUTPUT
    return ArtifactEvidenceType.UNKNOWN_EVIDENCE
