from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256

from app.parsing.models import (
    ArtifactProvenance,
    ConfigNode,
    ConfigNodeKind,
    DiagnosticSeverity,
    ParseDiagnostic,
    ParseStatus,
    StructuralIR,
)


@dataclass
class _NodeDraft:
    node_id: str
    raw_text: str
    command: str | None
    arguments: tuple[str, ...]
    parent_id: str | None
    children: list[str]
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
    indent: int = field(repr=False)


class IRBuilder:
    def __init__(
        self,
        *,
        reader_id: str,
        source: ArtifactProvenance,
        max_depth: int,
        max_nodes: int,
    ) -> None:
        self.reader_id = reader_id
        self.source = source
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.diagnostics: list[ParseDiagnostic] = []
        self._nodes: list[_NodeDraft] = []
        self._nodes_by_id: dict[str, _NodeDraft] = {}
        self._roots: list[str] = []
        self._stack: list[_NodeDraft] = []

    @property
    def node_limit_reached(self) -> bool:
        return len(self._nodes) >= self.max_nodes

    def add_diagnostic(
        self,
        code: str,
        message: str,
        *,
        source_start: int | None = None,
        source_end: int | None = None,
        severity: DiagnosticSeverity = DiagnosticSeverity.WARNING,
    ) -> None:
        self.diagnostics.append(ParseDiagnostic(
            code=code,
            message=message,
            severity=severity,
            source_start=source_start,
            source_end=source_end,
        ))

    def add_node(
        self,
        *,
        raw_text: str,
        command: str | None,
        arguments: tuple[str, ...],
        indent: int,
        source_start: int,
        source_end: int,
        negated: bool,
        kind: ConfigNodeKind,
        parse_status: ParseStatus,
        comments: tuple[str, ...] = (),
        force_root: bool = False,
        can_parent: bool = True,
    ) -> str | None:
        if self.node_limit_reached:
            return None

        node_status = parse_status
        if force_root or indent == 0:
            self._stack.clear()
            parent = None
        else:
            unmatched_dedent = (
                bool(self._stack)
                and indent < self._stack[-1].indent
                and all(item.indent != indent for item in self._stack)
            )
            while self._stack and self._stack[-1].indent >= indent:
                self._stack.pop()
            parent = self._stack[-1] if self._stack else None
            if unmatched_dedent:
                node_status = ParseStatus.PARTIAL
                self.add_diagnostic(
                    "inconsistent_dedent",
                    "Dedent did not match an observed structural indentation level",
                    source_start=source_start,
                    source_end=source_end,
                )
            if parent is None:
                node_status = ParseStatus.PARTIAL
                self.add_diagnostic(
                    "orphan_indentation",
                    "Indented statement has no observable parent context",
                    source_start=source_start,
                    source_end=source_end,
                )

        if parent is not None and parent.depth >= self.max_depth:
            while self._stack and self._stack[-1].depth >= self.max_depth:
                self._stack.pop()
            parent = self._stack[-1] if self._stack else None
            node_status = ParseStatus.PARTIAL
            self.add_diagnostic(
                "maximum_depth_reached",
                "Structural depth was bounded",
                source_start=source_start,
                source_end=source_end,
            )

        parent_id = parent.node_id if parent is not None else None
        depth = parent.depth + 1 if parent is not None else 0
        context_path = (
            parent.context_path + (parent.node_id,) if parent is not None else ()
        )
        order = len(self._nodes) + 1
        node_id = self._node_id(
            raw_text=raw_text,
            source_start=source_start,
            source_end=source_end,
            order=order,
            parent_id=parent_id,
        )
        draft = _NodeDraft(
            node_id=node_id,
            raw_text=raw_text,
            command=command,
            arguments=arguments,
            parent_id=parent_id,
            children=[],
            depth=depth,
            order=order,
            context_path=context_path,
            source_start=source_start,
            source_end=source_end,
            negated=negated,
            inactive=False,
            comments=comments,
            kind=kind,
            parse_status=node_status,
            indent=indent,
        )
        self._nodes.append(draft)
        self._nodes_by_id[node_id] = draft
        if parent is None:
            self._roots.append(node_id)
        else:
            parent.children.append(node_id)
        if can_parent:
            self._stack.append(draft)
        return node_id

    def reset_context(self) -> None:
        self._stack.clear()

    def build(self, *, truncated: bool) -> StructuralIR:
        nodes = tuple(ConfigNode(
            node_id=item.node_id,
            artifact_id=self.source.artifact_id,
            source_label=self.source.source_label,
            raw_text=item.raw_text,
            command=item.command,
            arguments=item.arguments,
            parent_id=item.parent_id,
            children=tuple(item.children),
            depth=item.depth,
            order=item.order,
            context_path=item.context_path,
            source_start=item.source_start,
            source_end=item.source_end,
            negated=item.negated,
            inactive=item.inactive,
            comments=item.comments,
            kind=item.kind,
            parse_status=item.parse_status,
        ) for item in self._nodes)
        return StructuralIR(
            reader_id=self.reader_id,
            source=self.source,
            nodes=nodes,
            root_node_ids=tuple(self._roots),
            diagnostics=tuple(self.diagnostics),
            truncated=truncated,
        )

    def _node_id(
        self,
        *,
        raw_text: str,
        source_start: int,
        source_end: int,
        order: int,
        parent_id: str | None,
    ) -> str:
        identity = "\x1f".join((
            str(self.source.artifact_id),
            self.reader_id,
            str(source_start),
            str(source_end),
            str(order),
            parent_id or "root",
            raw_text,
        ))
        return f"irn_{sha256(identity.encode('utf-8')).hexdigest()[:32]}"
