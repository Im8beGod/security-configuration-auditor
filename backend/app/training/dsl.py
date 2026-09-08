from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.security_model import get_field


SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:/@-]{1,255}$")
IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
MAX_MAPPING_BYTES = 64 * 1024
MAX_DSL_DEPTH = 12


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ArgumentPattern(StrictModel):
    operation: Literal["literal", "capture", "optional", "one_of"]
    value: str | None = None
    name: str | None = None
    value_type: Literal["string", "integer", "number", "boolean"] | None = None
    options: list[str] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def bounded_shape(self) -> "ArgumentPattern":
        if self.operation == "literal" and not _safe(self.value):
            raise ValueError("literal requires a safe bounded value")
        if self.operation == "capture" and (
            not self.name or not IDENTIFIER.fullmatch(self.name) or not self.value_type
        ):
            raise ValueError("capture requires a typed identifier")
        if self.operation == "optional" and not _safe(self.value):
            raise ValueError("optional requires a safe bounded value")
        if self.operation == "one_of" and (
            not self.options or any(not _safe(item) for item in self.options)
        ):
            raise ValueError("one_of requires safe bounded alternatives")
        return self


class XmlPathSegment(StrictModel):
    local_name: str = Field(min_length=1, max_length=128)
    namespace_uri: str | None = Field(default=None, max_length=512)
    occurrence: Literal["exact", "any"] = "exact"
    index: int = Field(default=1, ge=1, le=1024)

    @model_validator(mode="after")
    def safe_name(self) -> "XmlPathSegment":
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", self.local_name):
            raise ValueError("XML path segment is invalid")
        if self.namespace_uri is not None and not self.namespace_uri.startswith(("http://", "https://", "urn:")):
            raise ValueError("XML namespace URI is invalid")
        return self


class XmlPathMatch(StrictModel):
    path: list[XmlPathSegment] = Field(min_length=1, max_length=16)
    source: Literal["presence", "text", "attribute"] = "presence"
    attribute: str | None = Field(default=None, max_length=128)
    capture: str | None = None
    value_type: Literal["string", "integer", "number", "boolean", "ip_address"] | None = None
    start_mode: Literal["document_root"] = "document_root"

    @model_validator(mode="after")
    def valid_source(self) -> "XmlPathMatch":
        if self.source == "attribute" and not self.attribute:
            raise ValueError("XML attribute source requires an attribute")
        if self.capture and not IDENTIFIER.fullmatch(self.capture):
            raise ValueError("XML capture is invalid")
        if self.source != "presence" and not self.capture:
            raise ValueError("XML value source requires a capture")
        if self.attribute and not IDENTIFIER.fullmatch(self.attribute):
            raise ValueError("XML attribute is invalid")
        return self


class StructuralMatch(StrictModel):
    operation: Literal["command_equality", "command_prefix", "xml_path"] = "command_equality"
    command: str = Field(min_length=1, max_length=100)
    arguments: list[ArgumentPattern] = Field(default_factory=list, max_length=32)
    minimum_arguments: int | None = Field(default=None, ge=0, le=64)
    maximum_arguments: int | None = Field(default=None, ge=0, le=64)
    parent_command: str | None = Field(default=None, max_length=100)
    ancestor_commands: list[str] = Field(default_factory=list, max_length=8)
    scope_type: Literal["device", "current_scope", "parent_scope", "management_plane", "vty_range", "interface", "interface_range", "vrf", "security_zone", "global"] | None = None
    negated: bool | None = None
    xml_path: XmlPathMatch | None = None

    @model_validator(mode="after")
    def safe_matcher(self) -> "StructuralMatch":
        if self.operation == "xml_path":
            if self.xml_path is None:
                raise ValueError("xml_path operation requires an XML path")
            return self
        if self.xml_path is not None:
            raise ValueError("XML path is only valid for xml_path operation")
        tokens = [self.command, *self.ancestor_commands]
        if self.parent_command:
            tokens.append(self.parent_command)
        if any(not _safe(item) for item in tokens):
            raise ValueError("matcher contains an unsafe token")
        if self.minimum_arguments is not None and self.maximum_arguments is not None and self.minimum_arguments > self.maximum_arguments:
            raise ValueError("argument range is invalid")
        return self


class ValueExtraction(StrictModel):
    operation: Literal["capture", "constant", "boolean_from_presence", "enum_mapping", "integer", "number", "list", "duration_from_parts"]
    capture: str | None = None
    value: Any | None = None
    values: list[str] = Field(default_factory=list, max_length=32)
    enum_map: dict[str, str] = Field(default_factory=dict)
    parts: list[str] = Field(default_factory=list, max_length=8)
    output_type: Literal["boolean", "integer", "number", "string", "enum", "ip_address", "ip_network", "duration", "list", "object", "null"]

    @model_validator(mode="after")
    def valid_operation(self) -> "ValueExtraction":
        names = ([self.capture] if self.capture else []) + self.parts
        if any(not IDENTIFIER.fullmatch(name) for name in names):
            raise ValueError("extraction references an invalid capture")
        if self.operation in {"capture", "integer", "number"} and not self.capture:
            raise ValueError("extraction operation requires a capture")
        if self.operation == "enum_mapping" and (not self.capture or not self.enum_map):
            raise ValueError("enum mapping requires a capture and values")
        if self.operation == "duration_from_parts" and not self.parts:
            raise ValueError("duration extraction requires captured parts")
        return self


class UnitConversion(StrictModel):
    operation: Literal["none", "minutes_to_seconds", "hours_to_seconds", "milliseconds_to_seconds"] = "none"


class ScopeResolution(StrictModel):
    strategy: Literal["device", "current_scope", "parent_scope", "management_plane", "vty_range", "interface", "interface_range", "vrf", "security_zone", "global"]
    xml_unsupported_qualifier_paths: list[list[str]] = Field(default_factory=list, max_length=8)

    @field_validator("xml_unsupported_qualifier_paths")
    @classmethod
    def bounded_xml_qualifiers(cls, paths: list[list[str]]) -> list[list[str]]:
        if any(not path or len(path) > 8 or any(not _safe(segment) for segment in path) for path in paths):
            raise ValueError("XML qualifier paths are malformed")
        return paths


class ExplicitBehavior(StrictModel):
    operation: Literal["unsupported", "emit_value", "reset_to_default", "remove_value", "unknown"]


class ValidationNode(StrictModel):
    command: str = Field(min_length=1, max_length=100)
    arguments: list[str] = Field(default_factory=list, max_length=64)
    parent_command: str | None = Field(default=None, max_length=100)
    ancestor_commands: list[str] = Field(default_factory=list, max_length=8)
    scope_type: str | None = Field(default=None, max_length=64)
    negated: bool = False


class MappingExample(StrictModel):
    family: Literal["positive", "alternate_values", "negative", "wrong_scope", "negation", "conflict", "regression"]
    node: ValidationNode
    expected_match: bool
    expected_value: Any | None = None


class ProfileApplicability(StrictModel):
    profile_ids: list[str] = Field(default_factory=list, max_length=32)
    profile_version_ids: list[str] = Field(min_length=1, max_length=32)

    @field_validator("profile_ids", "profile_version_ids")
    @classmethod
    def safe_profiles(cls, values: list[str]) -> list[str]:
        if any(not _safe(item) for item in values):
            raise ValueError("profile applicability contains an unsafe identifier")
        return values


class MappingDefinition(StrictModel):
    profile_applicability: ProfileApplicability
    structural_match: StructuralMatch
    target_field_id: str = Field(min_length=1, max_length=255)
    value_extraction: ValueExtraction
    unit_conversion: UnitConversion = Field(default_factory=UnitConversion)
    scope_resolution: ScopeResolution
    negation_behavior: ExplicitBehavior
    removal_behavior: ExplicitBehavior
    default_behavior: ExplicitBehavior
    examples: list[MappingExample] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def trusted_registry_and_bounds(self) -> "MappingDefinition":
        field = get_field(self.target_field_id)
        if self.value_extraction.output_type not in {item.value for item in field.expected_types}:
            raise ValueError("extraction output type is incompatible with canonical field")
        if self.scope_resolution.strategy not in field.allowed_scope_types:
            raise ValueError("scope strategy is incompatible with canonical field")
        payload = self.model_dump(mode="json")
        if len(json.dumps(payload, separators=(",", ":")).encode()) > MAX_MAPPING_BYTES:
            raise ValueError("mapping definition is too large")
        if _depth(payload) > MAX_DSL_DEPTH:
            raise ValueError("mapping definition is too deeply nested")
        return self


def matches(definition: MappingDefinition, node: ValidationNode) -> tuple[bool, dict[str, Any]]:
    match = definition.structural_match
    if match.operation == "xml_path":
        return False, {}
    command_matches = node.command == match.command if match.operation == "command_equality" else node.command.startswith(match.command)
    if not command_matches or match.negated is not None and node.negated != match.negated:
        return False, {}
    if match.parent_command is not None and node.parent_command != match.parent_command:
        return False, {}
    if match.ancestor_commands and not all(item in node.ancestor_commands for item in match.ancestor_commands):
        return False, {}
    if match.scope_type is not None and node.scope_type != match.scope_type:
        return False, {}
    count = len(node.arguments)
    if match.minimum_arguments is not None and count < match.minimum_arguments or match.maximum_arguments is not None and count > match.maximum_arguments:
        return False, {}
    captures: dict[str, Any] = {}
    index = 0
    for pattern in match.arguments:
        if pattern.operation == "optional":
            if index < count and node.arguments[index] == pattern.value:
                index += 1
            continue
        if index >= count:
            return False, {}
        value = node.arguments[index]
        if pattern.operation == "literal" and value != pattern.value:
            return False, {}
        if pattern.operation == "one_of" and value not in pattern.options:
            return False, {}
        if pattern.operation == "capture":
            try:
                captures[pattern.name or ""] = _typed(value, pattern.value_type or "string")
            except ValueError:
                return False, {}
        index += 1
    return True, captures


def matches_xml(definition: MappingDefinition, ir: Any) -> tuple[tuple[Any, dict[str, Any]], ...]:
    """Return bounded XML node matches without XPath, regex, or descendant wildcards."""
    match = definition.structural_match
    if match.operation != "xml_path" or match.xml_path is None:
        return ()
    result: list[tuple[Any, dict[str, Any]]] = []
    expected = match.xml_path.path
    for node in ir.nodes:
        if len(node.path) != len(expected):
            continue
        captures: dict[str, Any] = {}
        valid = True
        for actual, segment in zip(node.path, expected):
            tag = actual.rsplit("[", 1)[0]
            occurrence = int(actual.rsplit("[", 1)[1][:-1])
            namespace, local = _xml_name(tag)
            if local != segment.local_name or (segment.namespace_uri is not None and namespace != segment.namespace_uri) or (segment.occurrence == "exact" and occurrence != segment.index):
                valid = False
                break
        if not valid:
            continue
        source = match.xml_path
        if source.source == "text":
            raw = node.text
        elif source.source == "attribute":
            raw = dict(node.attributes).get(source.attribute or "")
        else:
            raw = True
        if raw is None:
            continue
        if source.capture:
            try:
                captures[source.capture] = _typed(str(raw), source.value_type or "string")
            except ValueError:
                continue
        result.append((node, captures))
    return tuple(result)


def xml_match_has_unsupported_qualifier(definition: MappingDefinition, ir: Any, node: Any) -> bool:
    """Fail closed when a matched XML value carries a declared unsupported scope qualifier."""
    paths = definition.scope_resolution.xml_unsupported_qualifier_paths
    if not paths or node.parent_id is None:
        return False
    nodes = {item.node_id: item for item in ir.nodes}
    children: dict[str, list[Any]] = {}
    for item in ir.nodes:
        if item.parent_id is not None:
            children.setdefault(item.parent_id, []).append(item)
    frontier = [nodes.get(node.parent_id)]
    for path in paths:
        current = [item for item in frontier if item is not None]
        for segment in path:
            current = [child for item in current for child in children.get(item.node_id, ()) if _xml_name(child.tag)[1] == segment]
        if current:
            return True
    return False


def _xml_name(tag: str) -> tuple[str | None, str]:
    if tag.startswith("{") and "}" in tag:
        namespace, local = tag[1:].split("}", 1)
        return namespace, local
    return None, tag


def extract(definition: MappingDefinition, captures: dict[str, Any]) -> Any:
    rule = definition.value_extraction
    if rule.operation == "constant":
        value = rule.value
    elif rule.operation == "boolean_from_presence":
        value = True
    elif rule.operation == "capture":
        value = captures[rule.capture or ""]
    elif rule.operation == "integer":
        value = int(captures[rule.capture or ""])
    elif rule.operation == "number":
        value = float(captures[rule.capture or ""])
    elif rule.operation == "enum_mapping":
        value = rule.enum_map[str(captures[rule.capture or ""])]
    elif rule.operation == "list":
        value = [captures[item] for item in rule.values]
    else:
        multipliers = [60, 1] if len(rule.parts) == 2 else [1] * len(rule.parts)
        value = sum(float(captures[name]) * multipliers[index] for index, name in enumerate(rule.parts))
    conversion = definition.unit_conversion.operation
    if conversion == "minutes_to_seconds":
        value *= 60
    elif conversion == "hours_to_seconds":
        value *= 3600
    elif conversion == "milliseconds_to_seconds":
        value /= 1000
    return value


def _typed(value: str, kind: str) -> Any:
    if kind == "integer":
        return int(value)
    if kind == "number":
        return float(value)
    if kind == "boolean":
        if value not in {"true", "false"}:
            raise ValueError
        return value == "true"
    return value


def _safe(value: str | None) -> bool:
    return bool(value and SAFE_TOKEN.fullmatch(value))


def _depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max((_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(item) for item in value), default=0)
    return 0
