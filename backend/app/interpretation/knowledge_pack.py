from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any
from uuid import UUID

from app.security_model import FIELD_REGISTRY, TypedValueType


SUPPORTED_KNOWLEDGE_PACK_SCHEMA_VERSIONS = frozenset({"1.0.0"})
MAPPING_TOKEN_PATTERN = re.compile(r"^[^\s]{1,255}$")
COMMAND_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,99}$")


class KnowledgePackValidationError(ValueError):
    pass


class NegationBehavior(str, Enum):
    """Bounded semantic operation declared by a versioned mapping."""

    UNSUPPORTED = "unsupported"
    RESET_TO_DEFAULT = "reset_to_default"
    REMOVE_VALUE = "remove_value"


@dataclass(frozen=True)
class NodeMatcher:
    command: str
    arguments_prefix: tuple[str, ...] = ()
    parent_command: str | None = None
    parent_arguments_prefix: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeclarativeMapping:
    mapping_id: UUID
    mapping_version_id: UUID
    field_id: str
    matcher: NodeMatcher
    extractor: str
    scope_resolver: str
    declared_value_types: frozenset[TypedValueType]
    negation_behavior: NegationBehavior = NegationBehavior.UNSUPPORTED
    reset_mapping_version_id: UUID | None = None
    removal_mapping_version_id: UUID | None = None
    training_definition: dict[str, Any] | None = None


@dataclass(frozen=True)
class KnowledgePack:
    knowledge_pack_id: UUID
    knowledge_pack_version_id: UUID
    name: str
    version: str
    schema_version: str
    profile_id: str
    profile_version_id: str
    mappings: tuple[DeclarativeMapping, ...]


def validate_knowledge_pack(
    pack: KnowledgePack,
    *,
    expected_profile_id: str,
    expected_profile_version_id: str,
    allowed_extractors: frozenset[str],
    scope_resolver_types: dict[str, str],
) -> KnowledgePack:
    if pack.schema_version not in SUPPORTED_KNOWLEDGE_PACK_SCHEMA_VERSIONS:
        raise KnowledgePackValidationError("Unsupported knowledge-pack schema version")
    if (
        pack.profile_id != expected_profile_id
        or pack.profile_version_id != expected_profile_version_id
    ):
        raise KnowledgePackValidationError("Knowledge pack is incompatible with profile")
    if (
        not isinstance(pack.knowledge_pack_id, UUID)
        or not isinstance(pack.knowledge_pack_version_id, UUID)
        or pack.knowledge_pack_id.int == 0
        or pack.knowledge_pack_version_id.int == 0
        or not pack.name
        or not pack.version
    ):
        raise KnowledgePackValidationError("Knowledge pack requires stable identity")

    mapping_ids: set[UUID] = set()
    mapping_version_ids: set[UUID] = set()
    for mapping in pack.mappings:
        if (
            not isinstance(mapping.mapping_id, UUID)
            or not isinstance(mapping.mapping_version_id, UUID)
            or mapping.mapping_id.int == 0
            or mapping.mapping_version_id.int == 0
        ):
            raise KnowledgePackValidationError("Mapping requires stable identity")
        if mapping.mapping_id in mapping_ids:
            raise KnowledgePackValidationError("Duplicate mapping ID")
        if mapping.mapping_version_id in mapping_version_ids:
            raise KnowledgePackValidationError("Duplicate mapping-version ID")
        mapping_ids.add(mapping.mapping_id)
        mapping_version_ids.add(mapping.mapping_version_id)

        field = FIELD_REGISTRY.get(mapping.field_id)
        if field is None:
            raise KnowledgePackValidationError("Mapping references unknown canonical field")
        if mapping.extractor not in allowed_extractors and mapping.extractor != "training_dsl":
            raise KnowledgePackValidationError("Mapping references unknown extractor")
        scope_type = scope_resolver_types.get(mapping.scope_resolver)
        if scope_type is None:
            raise KnowledgePackValidationError("Mapping references unknown scope resolver")
        if (
            not mapping.declared_value_types
            or not mapping.declared_value_types <= field.expected_types
        ):
            raise KnowledgePackValidationError("Mapping value type is incompatible with field")
        if not isinstance(mapping.negation_behavior, NegationBehavior):
            raise KnowledgePackValidationError("Mapping negation behavior is invalid")
        if mapping.reset_mapping_version_id is not None and not isinstance(
            mapping.reset_mapping_version_id, UUID
        ):
            raise KnowledgePackValidationError("Mapping reset version is invalid")
        if mapping.removal_mapping_version_id is not None and not isinstance(
            mapping.removal_mapping_version_id, UUID
        ):
            raise KnowledgePackValidationError("Mapping removal version is invalid")
        if scope_type not in field.allowed_scope_types:
            raise KnowledgePackValidationError("Mapping scope is incompatible with field")
        _validate_matcher(mapping.matcher)
    return pack


def _validate_matcher(matcher: NodeMatcher) -> None:
    if not COMMAND_PATTERN.fullmatch(matcher.command):
        raise KnowledgePackValidationError("Mapping command matcher is malformed")
    if matcher.parent_command is not None and not COMMAND_PATTERN.fullmatch(
        matcher.parent_command
    ):
        raise KnowledgePackValidationError("Mapping parent matcher is malformed")
    if matcher.parent_command is None and matcher.parent_arguments_prefix:
        raise KnowledgePackValidationError("Mapping parent matcher is malformed")
    tokens = matcher.arguments_prefix + matcher.parent_arguments_prefix
    if any(not MAPPING_TOKEN_PATTERN.fullmatch(token) for token in tokens):
        raise KnowledgePackValidationError("Mapping token matcher is malformed")
