from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.compliance.verdicts import FindingSeverity, FindingVerdict
from app.effective_state.contracts import ResolutionStatus, UnresolvedReason


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    finding_id: UUID; audit_id: UUID; device_id: UUID; comparison_key: str; rule_id: str
    rule_pack_version_id: UUID; title: str; security_domain: str; verdict: FindingVerdict
    severity: FindingSeverity; expected_state: dict[str, Any] | None; observed_state: dict[str, Any] | None
    explanation: str; affected_scope: dict[str, Any] | None; effective_state_refs: list[str]
    evidence_refs: list[dict[str, Any]]; unknown_reason: UnresolvedReason | None
    framework_references: list[dict[str, Any]]; remediation_procedure_id: UUID | None
    created_at: datetime; schema_version: str


class FindingPage(BaseModel):
    items: list[FindingResponse]
    total: int
    offset: int
    limit: int


class EvidenceArtifact(BaseModel):
    artifact_id: UUID; original_filename: str; evidence_type: str; content_family: str; sha256: str
    excerpt: str | None = None; truncated: bool = False; available: bool = True


class EvidenceFact(BaseModel):
    fact_id: UUID; field_id: str; value: dict[str, Any]; scope: dict[str, Any]; state: str
    extraction_method: str; mapping_id: UUID | None; mapping_version_id: UUID | None
    knowledge_pack_version_id: UUID; validation_status: str; interpretation_confidence: str
    evidence_refs: list[dict[str, Any]]; artifacts: list[EvidenceArtifact]


class EvidenceState(BaseModel):
    effective_state_id: UUID; field_id: str; scope: dict[str, Any]; effective_value: dict[str, Any] | None
    resolution_status: ResolutionStatus; resolution_trace: list[dict[str, Any]]
    inherited_from: dict[str, Any] | None; default_reference: str | None
    referenced_objects: list[dict[str, Any]]; precedence_applied: list[dict[str, Any]]
    unresolved_reason: UnresolvedReason | None; facts: list[EvidenceFact]


class FindingEvidenceResponse(BaseModel):
    finding_id: UUID
    states: list[EvidenceState]
    status: str
