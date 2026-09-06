from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping
from uuid import UUID


class ConfigNodeKind(str, Enum):
    STATEMENT = "statement"
    COMMENT = "comment"
    OPAQUE = "opaque"


class ParseStatus(str, Enum):
    PARSED = "parsed"
    OPAQUE = "opaque"
    PARTIAL = "partial"
    UNRESOLVED = "unresolved"


class DiagnosticSeverity(str, Enum):
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class ArtifactProvenance:
    artifact_id: UUID
    organization_id: UUID
    snapshot_id: UUID | None
    source_label: str
    sha256: str
    source_metadata: Mapping[str, Any]


@dataclass(frozen=True)
class ParseDiagnostic:
    code: str
    message: str
    severity: DiagnosticSeverity
    source_start: int | None = None
    source_end: int | None = None


@dataclass(frozen=True)
class ConfigNode:
    node_id: str
    artifact_id: UUID
    source_label: str
    raw_text: str
    command: str | None
    arguments: tuple[str, ...]
    parent_id: str | None
    children: tuple[str, ...]
    depth: int
    order: int
    context_path: tuple[str, ...]
    source_start: int
    source_end: int
    negated: bool
    inactive: bool
    comments: tuple[str, ...]
    kind: ConfigNodeKind
    parse_status: ParseStatus


@dataclass(frozen=True)
class StructuralIR:
    reader_id: str
    source: ArtifactProvenance
    nodes: tuple[ConfigNode, ...]
    root_node_ids: tuple[str, ...]
    diagnostics: tuple[ParseDiagnostic, ...]
    truncated: bool

    def node(self, node_id: str) -> ConfigNode:
        for item in self.nodes:
            if item.node_id == node_id:
                return item
        raise KeyError(node_id)


@dataclass(frozen=True)
class StructuralParseRequest:
    content: str
    source: ArtifactProvenance
    input_truncated: bool = False
