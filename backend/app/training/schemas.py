from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import MappingOrigin, MappingStatus, UnresolvedReviewStatus, ValidationRunStatus
from app.training.dsl import MappingDefinition


class OrmModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UnresolvedResponse(OrmModel):
    unresolved_block_id: UUID
    audit_id: UUID
    device_id: UUID
    snapshot_id: UUID
    profile_id: str | None
    profile_version_id: str | None
    source_ir_node_ids: list[str]
    evidence_refs: list[dict[str, Any]]
    raw_text: str
    surrounding_context: str
    unknown_reason: str
    candidate_field_ids: list[str]
    affected_rule_ids: list[str]
    fingerprint: str
    occurrence: dict[str, Any]
    review_status: UnresolvedReviewStatus
    assigned_mapping_version_id: UUID | None
    created_at: datetime
    updated_at: datetime
    schema_version: str


class MappingCreateRequest(BaseModel):
    mapping_key: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=2048)
    definition: MappingDefinition
    previous_mapping_version_id: UUID | None = None
    unresolved_block_id: UUID | None = None


class MappingUpdateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=2048)
    definition: MappingDefinition


class ReviewUpdateRequest(BaseModel):
    review_status: UnresolvedReviewStatus


class MappingResponse(OrmModel):
    mapping_version_id: UUID
    mapping_id: UUID
    mapping_key: str
    version: int
    previous_mapping_version_id: UUID | None
    title: str
    description: str
    status: MappingStatus
    profile_applicability: dict[str, Any]
    structural_match: dict[str, Any]
    target_field_id: str
    value_extraction: dict[str, Any]
    unit_conversion: dict[str, Any]
    scope_resolution: dict[str, Any]
    negation_behavior: dict[str, Any]
    removal_behavior: dict[str, Any]
    default_behavior: dict[str, Any]
    examples: list[dict[str, Any]]
    validation_results: dict[str, Any]
    origin: MappingOrigin
    ai_suggestion_metadata: dict[str, Any] | None
    created_by: UUID | None
    approved_by: UUID | None
    knowledge_pack_version_id: UUID | None
    created_at: datetime
    approved_at: datetime | None
    published_at: datetime | None
    schema_version: str


class ValidationRequestResponse(BaseModel):
    validation_run_id: UUID
    job_id: UUID
    status: ValidationRunStatus


class PublicationResponse(BaseModel):
    mapping: MappingResponse
    knowledge_pack_version_id: UUID
    knowledge_pack_version: int


class ImpactResponse(BaseModel):
    mapping_version_id: UUID
    matching_unresolved_block_ids: list[UUID]
    affected_device_ids: list[UUID]
    affected_historical_audit_ids: list[UUID]
    potentially_affected_unknown_findings: int
    historical_profile_audit_count: int
    creates_audit_revision: bool


class KnowledgePackResponse(OrmModel):
    knowledge_pack_id: UUID
    pack_key: str
    name: str
    created_at: datetime


class KnowledgePackVersionResponse(OrmModel):
    knowledge_pack_version_id: UUID
    knowledge_pack_id: UUID
    version: int
    previous_knowledge_pack_version_id: UUID | None
    mapping_version_ids: list[str]
    published_by: UUID
    published_at: datetime


class CanonicalFieldResponse(BaseModel):
    field_id: str
    expected_types: list[str]
    allowed_scope_types: list[str]
    domain: str
    description: str
    repeatable: bool
