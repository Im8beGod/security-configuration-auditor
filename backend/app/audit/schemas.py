from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.models import AuditProcessingStage, AuditReevaluationReason, AuditStatus
from app.jobs.enums import JobStatus, JobType


class AuditCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_id: UUID
    selected_frameworks: list[str] = Field(default_factory=list, max_length=50)
    assessment_pack_version_id: UUID | None = None

    @field_validator("selected_frameworks")
    @classmethod
    def validate_framework_intent(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values]
        if any(not value or len(value) > 100 for value in normalized):
            raise ValueError("Framework identifiers must contain 1 to 100 characters")
        if len(set(normalized)) != len(normalized):
            raise ValueError("Framework identifiers must be unique")
        return normalized


class BatchAuditItem(AuditCreate):
    device_id: UUID


class BatchAuditCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[BatchAuditItem] = Field(min_length=2, max_length=50)


class BatchAuditItemResponse(BaseModel):
    status: str
    device_id: UUID
    snapshot_id: UUID
    audit_id: UUID | None = None
    job_id: UUID | None = None
    error_code: str | None = None
    error_message: str | None = None


class BatchAuditResponse(BaseModel):
    accepted: int
    rejected: int
    results: list[BatchAuditItemResponse]


class AssessmentPackResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    assessment_pack_version_id: UUID
    pack_key: str
    family: str
    name: str
    version: int
    profile_version_ids: list[str]
    source_metadata: dict[str, object]
    source_version_label: str
    content_digest: str
    status: str


class JobSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    job_id: UUID
    job_type: JobType
    status: JobStatus
    stage: str | None
    progress: int
    attempt_count: int
    audit_id: UUID | None
    device_id: UUID | None
    error_code: str | None
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class AuditResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    audit_id: UUID
    organization_id: UUID
    device_id: UUID
    snapshot_id: UUID
    audit_batch_id: UUID | None
    revision_number: int
    previous_audit_id: UUID | None
    reevaluation_reason: AuditReevaluationReason
    status: AuditStatus
    processing_stage: AuditProcessingStage | None
    selected_frameworks: list[str]
    version_refs: dict[str, object]
    profile_resolution: dict[str, object]
    verdict_counts: dict[str, object]
    severity_counts: dict[str, object]
    coverage: dict[str, object]
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    created_by: UUID | None
    schema_version: str
    job: JobSummary | None = None
    assessment: dict[str, object] | None = None


class ReevaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    knowledge_pack_version_id: UUID


class ReevaluationEligibilityResponse(BaseModel):
    eligible: bool
    reason: str | None
    source_audit_id: UUID
    source_revision_number: int
    candidates: list[dict[str, object]]
