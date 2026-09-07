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


class StructuralMatch(StrictModel):
    operation: Literal["command_equality", "command_prefix"] = "command_equality"
    command: str = Field(min_length=1, max_length=100)
    arguments: list[ArgumentPattern] = Field(default_factory=list, max_length=32)
    minimum_arguments: int | None = Field(default=None, ge=0, le=64)
    maximum_arguments: int | None = Field(default=None, ge=0, le=64)
    parent_command: str | None = Field(default=None, max_length=100)
    ancestor_commands: list[str] = Field(default_factory=list, max_length=8)
    scope_type: Literal["device", "current_scope", "parent_scope", "management_plane", "vty_range", "interface", "interface_range", "vrf", "security_zone", "global"] | None = None
    negated: bool | None = None

    @model_validator(mode="after")
    def safe_matcher(self) -> "StructuralMatch":
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
