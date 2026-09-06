from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.db.models import ArtifactContentFamily, ArtifactEvidenceType, ArtifactStatus


class ArtifactResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    artifact_id: UUID
    organization_id: UUID
    snapshot_id: UUID | None
    original_filename: str
    storage_reference: str
    byte_size: int
    sha256: str
    mime_type: str | None
    encoding: str | None
    content_family: ArtifactContentFamily
    evidence_type: ArtifactEvidenceType
    status: ArtifactStatus
    validation_issues: list[dict[str, object]]
    source_metadata: dict[str, object]
    uploaded_by: UUID | None
    created_at: datetime
    validated_at: datetime | None
    schema_version: str


class UploadError(BaseModel):
    code: str
    message: str


class BulkUploadItem(BaseModel):
    filename: str
    status: Literal["success", "failed"]
    artifact: ArtifactResponse | None = None
    error: UploadError | None = None


class BulkUploadResponse(BaseModel):
    total: int
    succeeded: int
    failed: int
    results: list[BulkUploadItem]
