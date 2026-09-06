from hashlib import sha256
from uuid import uuid4

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.models import Artifact, ArtifactStatus, User
from app.db.models.common import utc_now
from app.ingestion.errors import IngestionInfrastructureError
from app.ingestion.metadata import normalize_filename, normalize_mime_type
from app.ingestion.storage import ArtifactStorage, ArtifactStorageError
from app.ingestion.validator import validate_and_classify


def ingest_artifact(
    db: Session,
    storage: ArtifactStorage,
    user: User,
    data: bytes,
    filename: str | None,
    mime_type: str | None,
) -> Artifact:
    safe_filename = normalize_filename(filename)
    safe_mime_type = normalize_mime_type(mime_type)
    validated = validate_and_classify(data, safe_filename, safe_mime_type)
    artifact_id = uuid4()
    try:
        reference = storage.write(
            data, organization_id=user.organization_id, artifact_id=artifact_id
        )
    except ArtifactStorageError:
        raise IngestionInfrastructureError(
            "storage_unavailable", "Uploaded evidence could not be stored"
        ) from None

    artifact = Artifact(
        artifact_id=artifact_id,
        organization_id=user.organization_id,
        original_filename=safe_filename,
        storage_reference=reference,
        byte_size=len(data),
        sha256=sha256(data).hexdigest(),
        mime_type=safe_mime_type,
        encoding=validated.encoding,
        content_family=validated.content_family,
        evidence_type=validated.evidence_type,
        status=ArtifactStatus.READY,
        validation_issues=validated.validation_issues,
        source_metadata={"ingestion": "authenticated_upload"},
        uploaded_by=user.user_id,
        validated_at=utc_now(),
        schema_version="1.0.0",
    )
    try:
        db.add(artifact)
        db.commit()
        db.refresh(artifact)
    except SQLAlchemyError:
        db.rollback()
        try:
            storage.delete(reference)
        except ArtifactStorageError:
            pass
        raise IngestionInfrastructureError(
            "persistence_failed", "Uploaded evidence could not be persisted"
        ) from None
    return artifact
