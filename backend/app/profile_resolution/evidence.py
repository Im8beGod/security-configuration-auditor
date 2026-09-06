from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from uuid import UUID

from app.db.models import Artifact, ArtifactEvidenceType
from app.ingestion.storage import ArtifactStorage, ArtifactStorageError


MAX_ARTIFACT_INSPECTION_BYTES = 256 * 1024
MAX_SNAPSHOT_INSPECTION_BYTES = 1024 * 1024
MAX_SNAPSHOT_ARTIFACTS = 100

EVIDENCE_PRIORITY = {
    ArtifactEvidenceType.VERSION_OUTPUT: 0,
    ArtifactEvidenceType.INVENTORY_OUTPUT: 1,
    ArtifactEvidenceType.OPERATIONAL_OUTPUT: 2,
    ArtifactEvidenceType.STRUCTURED_EXPORT: 3,
    ArtifactEvidenceType.CONFIGURATION: 4,
    ArtifactEvidenceType.UNKNOWN_EVIDENCE: 5,
}


@dataclass(frozen=True)
class EvidenceDocument:
    artifact_id: UUID
    organization_id: UUID
    snapshot_id: UUID
    device_id: UUID
    evidence_type: ArtifactEvidenceType
    original_filename: str
    sha256: str
    source_metadata: Mapping[str, Any]
    text: str
    inspected_bytes: int
    truncated: bool


@dataclass(frozen=True)
class EvidenceIssue:
    artifact_id: UUID
    code: str


@dataclass(frozen=True)
class SnapshotEvidence:
    snapshot_id: UUID
    organization_id: UUID
    device_id: UUID
    documents: tuple[EvidenceDocument, ...]
    issues: tuple[EvidenceIssue, ...]
    inspected_bytes: int


def aggregate_snapshot_evidence(
    storage: ArtifactStorage,
    *,
    snapshot_id: UUID,
    organization_id: UUID,
    device_id: UUID,
    artifacts: list[Artifact],
) -> SnapshotEvidence:
    """Load deterministic bounded prefixes while retaining evidence provenance."""
    all_ordered = sorted(
        artifacts,
        key=lambda item: (EVIDENCE_PRIORITY[item.evidence_type], str(item.artifact_id)),
    )
    ordered = all_ordered[:MAX_SNAPSHOT_ARTIFACTS]
    documents: list[EvidenceDocument] = []
    issues: list[EvidenceIssue] = []
    inspected_total = 0

    if len(all_ordered) > MAX_SNAPSHOT_ARTIFACTS:
        issues.append(EvidenceIssue(
            all_ordered[MAX_SNAPSHOT_ARTIFACTS].artifact_id,
            "artifact_count_limit",
        ))

    for artifact in ordered:
        remaining = MAX_SNAPSHOT_INSPECTION_BYTES - inspected_total
        if remaining <= 0:
            issues.append(EvidenceIssue(artifact.artifact_id, "snapshot_inspection_limit"))
            break
        inspection_limit = min(MAX_ARTIFACT_INSPECTION_BYTES, remaining)
        try:
            content = storage.read_prefix(artifact.storage_reference, inspection_limit)
        except ArtifactStorageError:
            issues.append(EvidenceIssue(artifact.artifact_id, "artifact_unavailable"))
            continue

        encoding = artifact.encoding if artifact.encoding in {"utf-8", "utf-8-sig"} else "utf-8"
        text = content.decode(encoding, errors="replace")
        inspected_total += len(content)
        documents.append(EvidenceDocument(
            artifact_id=artifact.artifact_id,
            organization_id=artifact.organization_id,
            snapshot_id=snapshot_id,
            device_id=device_id,
            evidence_type=artifact.evidence_type,
            original_filename=artifact.original_filename,
            sha256=artifact.sha256,
            source_metadata=dict(artifact.source_metadata or {}),
            text=text,
            inspected_bytes=len(content),
            truncated=artifact.byte_size > len(content),
        ))

    return SnapshotEvidence(
        snapshot_id=snapshot_id,
        organization_id=organization_id,
        device_id=device_id,
        documents=tuple(documents),
        issues=tuple(issues),
        inspected_bytes=inspected_total,
    )
