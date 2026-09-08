from uuid import UUID

from app.db.models import Artifact, ArtifactEvidenceType
from app.ingestion.storage import ArtifactStorage, ArtifactStorageError
from app.parsing.exceptions import (
    ArtifactNotParseableError,
    ParsingInfrastructureError,
    StructuralReaderNotFoundError,
)
from app.parsing.models import ArtifactProvenance, StructuralIR, StructuralParseRequest
from app.parsing.reader_registry import READER_REGISTRY
from app.parsing.readers.indentation_cli import MAX_INPUT_CHARACTERS
from app.profile_resolution.registry import PROFILE_REGISTRY
from app.snapshots.service import ELIGIBLE_ARTIFACT_STATUSES


MAX_CONFIGURATION_BYTES = MAX_INPUT_CHARACTERS


def parse_artifact(
    storage: ArtifactStorage,
    artifact: Artifact,
    *,
    profile_version_id: str,
    organization_id: UUID,
) -> StructuralIR:
    if artifact.organization_id != organization_id:
        raise ArtifactNotParseableError("artifact_not_found", "Artifact not found")
    profile = PROFILE_REGISTRY.get(profile_version_id)
    if profile is None or profile.structural_reader_name is None:
        raise StructuralReaderNotFoundError(
            "structural_reader_unavailable", "No structural reader is available"
        )
    if artifact.evidence_type not in profile.structural_evidence_types:
        raise ArtifactNotParseableError(
            "artifact_evidence_incompatible",
            "Artifact evidence is incompatible with the selected profile",
        )
    if artifact.status not in ELIGIBLE_ARTIFACT_STATUSES:
        raise ArtifactNotParseableError(
            "artifact_not_eligible", "Artifact is not eligible for structural parsing"
        )
    try:
        content = storage.read_prefix(artifact.storage_reference, MAX_CONFIGURATION_BYTES)
    except ArtifactStorageError:
        raise ParsingInfrastructureError(
            "artifact_storage_unavailable", "Configuration evidence could not be read"
        ) from None

    encoding = artifact.encoding if artifact.encoding in {"utf-8", "utf-8-sig"} else "utf-8"
    text = content.decode(encoding, errors="replace")
    source = ArtifactProvenance(
        artifact_id=artifact.artifact_id,
        organization_id=artifact.organization_id,
        snapshot_id=artifact.snapshot_id,
        source_label=artifact.original_filename,
        sha256=artifact.sha256,
        source_metadata=dict(artifact.source_metadata or {}),
    )
    return parse_configuration_text(
        text,
        source=source,
        reader_id=profile.structural_reader_name,
        input_truncated=artifact.byte_size > len(content),
    )


def parse_configuration_text(
    content: str,
    *,
    source: ArtifactProvenance,
    reader_id: str,
    input_truncated: bool = False,
) -> StructuralIR:
    reader = READER_REGISTRY.get(reader_id)
    if reader is None:
        raise StructuralReaderNotFoundError(
            "structural_reader_unavailable", "No structural reader is available"
        )
    return reader.parse(StructuralParseRequest(
        content=content,
        source=source,
        input_truncated=input_truncated,
    ))


def parse_xml_text(content: str, *, source: ArtifactProvenance, input_truncated: bool = False):
    return parse_configuration_text(
        content, source=source, reader_id="xml_tree.v1", input_truncated=input_truncated
    )
