from dataclasses import dataclass
from uuid import UUID

from app.db.models import SecurityFact
from app.security_model import SecurityFactDraft


@dataclass(frozen=True)
class InterpretationContext:
    audit_id: UUID
    device_id: UUID
    snapshot_id: UUID


@dataclass(frozen=True)
class InterpretationDiagnostic:
    code: str
    node_id: str | None = None
    mapping_id: UUID | None = None


@dataclass(frozen=True)
class InterpretationMetrics:
    nodes_considered: int
    nodes_matched: int
    mappings_applied: int
    facts_produced: int
    unmatched_nodes: int
    unsupported_cases: int


@dataclass(frozen=True)
class InterpretationResult:
    facts: tuple[SecurityFactDraft, ...]
    diagnostics: tuple[InterpretationDiagnostic, ...]
    metrics: InterpretationMetrics


@dataclass(frozen=True)
class ArtifactInterpretationDiagnostic:
    artifact_id: UUID
    code: str


@dataclass(frozen=True)
class AuditInterpretationResult:
    facts: tuple[SecurityFact, ...]
    artifact_results: tuple[InterpretationResult, ...]
    artifact_diagnostics: tuple[ArtifactInterpretationDiagnostic, ...] = ()
