from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping
from uuid import UUID

from app.db.models.artifact import ArtifactEvidenceType
from app.db.models.security_fact import (
    FactState,
    FactValidationStatus,
    InterpretationConfidence,
    InterpretationMethod,
)


class TypedValueType(str, Enum):
    BOOLEAN = "boolean"
    INTEGER = "integer"
    NUMBER = "number"
    STRING = "string"
    ENUM = "enum"
    IP_ADDRESS = "ip_address"
    IP_NETWORK = "ip_network"
    DURATION = "duration"
    LIST = "list"
    OBJECT = "object"
    NULL = "null"


@dataclass(frozen=True)
class TypedValue:
    type: TypedValueType
    value: Any
    unit: str | None = None
    original_value: Any = None
    original_unit: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "value": self.value,
            "unit": self.unit,
            "original_value": self.original_value,
            "original_unit": self.original_unit,
        }


@dataclass(frozen=True)
class ScopeRef:
    type: str
    key: str
    attributes: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "key": self.key,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class EvidenceRef:
    artifact_id: UUID
    start_line: int
    end_line: int
    source_path: str
    ir_node_id: str
    evidence_type: ArtifactEvidenceType

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": str(self.artifact_id),
            "start_line": self.start_line,
            "end_line": self.end_line,
            "source_path": self.source_path,
            "ir_node_id": self.ir_node_id,
            "evidence_type": self.evidence_type.value,
        }


@dataclass(frozen=True)
class SecurityFactDraft:
    fact_id: UUID
    audit_id: UUID
    device_id: UUID
    snapshot_id: UUID
    field_id: str
    value: TypedValue
    entity: str | None
    scope: ScopeRef
    state: FactState
    evidence_refs: tuple[EvidenceRef, ...]
    source_ir_node_ids: tuple[str, ...]
    extraction_method: InterpretationMethod
    mapping_id: UUID | None
    mapping_version_id: UUID | None
    knowledge_pack_version_id: UUID
    validation_status: FactValidationStatus
    dependencies: tuple[UUID, ...]
    interpretation_confidence: InterpretationConfidence
    schema_version: str = "1.0.0"
