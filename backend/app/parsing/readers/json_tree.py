from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any

from app.parsing.models import ArtifactProvenance, StructuralParseRequest


JSON_TREE_READER_ID = "json_tree.v1"
MAX_JSON_INPUT_CHARACTERS = 2 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 20_000
MAX_JSON_STRING = 16 * 1024


@dataclass(frozen=True)
class JsonNode:
    node_id: str
    path: tuple[str | int, ...]
    value: Any
    parent_id: str | None
    order: int
    source: ArtifactProvenance


@dataclass(frozen=True)
class JsonStructuralIR:
    reader_id: str
    source: ArtifactProvenance
    nodes: tuple[JsonNode, ...]
    diagnostics: tuple[str, ...]
    truncated: bool = False


class JsonTreeReader:
    reader_id = JSON_TREE_READER_ID

    def parse(self, request: StructuralParseRequest) -> JsonStructuralIR:
        if len(request.content) > MAX_JSON_INPUT_CHARACTERS:
            raise ValueError("JSON input exceeds the bounded size limit")

        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate JSON property")
                result[key] = value
            return result

        def invalid_constant(_value: str) -> None:
            raise ValueError("Non-finite JSON value")

        try:
            payload = json.loads(
                request.content,
                object_pairs_hook=unique_object,
                parse_constant=invalid_constant,
            )
        except (json.JSONDecodeError, RecursionError, ValueError) as error:
            raise ValueError("Malformed JSON evidence") from error

        nodes: list[JsonNode] = []
        truncated = False

        def visit(value: Any, parent_id: str | None, path: tuple[str | int, ...], depth: int) -> None:
            nonlocal truncated
            if len(nodes) >= MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
                truncated = True
                return
            if isinstance(value, str) and len(value) > MAX_JSON_STRING:
                value = value[:MAX_JSON_STRING]
                truncated = True
            order = len(nodes) + 1
            node_id = "jsonn_" + sha256(
                f"{request.source.artifact_id}|{path}|{order}".encode()
            ).hexdigest()[:32]
            nodes.append(JsonNode(node_id, path, value, parent_id, order, request.source))
            if isinstance(value, dict):
                for key, child in value.items():
                    visit(child, node_id, path + (key,), depth + 1)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, node_id, path + (index,), depth + 1)

        visit(payload, None, (), 0)
        return JsonStructuralIR(
            self.reader_id, request.source, tuple(nodes), (),
            truncated or request.input_truncated,
        )
