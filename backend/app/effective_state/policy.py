from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping
from uuid import UUID

from app.interpretation.knowledge_pack import NegationBehavior
from app.knowledge_packs.cisco_iosxe_17 import CISCO_IOS_XE_17_KNOWLEDGE_PACK
from app.security_model import FIELD_REGISTRY

from app.effective_state.exceptions import EffectiveStateValidationError


LEGACY_KNOWLEDGE_PACK_VERSION_ID = UUID("17e3e913-17df-53bf-b8c1-5cae4bfa133e")
LEGACY_MAPPING_VERSION_IDS = {
    "management.remote.telnet.enabled": UUID("4e5634f2-c0f2-529e-912f-e42139aed61e"),
    "management.remote.ssh.enabled": UUID("82f62960-c06e-5ee1-a1ce-ccd574ead730"),
    "management.session.idle_timeout": UUID("a153b5c4-786d-5940-9fc7-2906ea7d42c7"),
    "management.remote.ssh.version": UUID("4b13928b-98eb-5dc2-a739-d978d5c8bd95"),
    "logging.remote.destination": UUID("f112df12-f860-5fad-b013-7b89701d2fcf"),
    "time.ntp.server": UUID("31eadc31-751e-5451-bdd7-2532a26c9710"),
}


class FieldCardinality(str, Enum):
    SCALAR = "scalar"
    REPEATABLE = "repeatable"


class FactOperation(str, Enum):
    ASSIGN = "assign"
    RESET = "reset"
    REMOVE = "remove"


@dataclass(frozen=True)
class FieldResolutionPolicy:
    field_id: str
    cardinality: FieldCardinality
    legal_scope_types: frozenset[str]
    precedence_categories: tuple[str, ...]
    inheritance_scope_types: tuple[str, ...]


@dataclass(frozen=True)
class MappingOperationPolicy:
    knowledge_pack_version_id: UUID
    mapping_version_id: UUID
    field_id: str
    operation: FactOperation


FIELD_POLICIES: Mapping[str, FieldResolutionPolicy] = MappingProxyType({
    field_id: FieldResolutionPolicy(
        field_id=field_id,
        cardinality=(FieldCardinality.REPEATABLE if field.repeatable else FieldCardinality.SCALAR),
        legal_scope_types=field.allowed_scope_types,
        # Scope partitions define applicability, not precedence. Only a persisted
        # source position within one artifact can order otherwise-equal operations.
        precedence_categories=("same_artifact_source_order",),
        inheritance_scope_types=(),
    )
    for field_id, field in FIELD_REGISTRY.items()
})

_ACTIVE_MAPPING_POLICIES = tuple(
    MappingOperationPolicy(
        knowledge_pack_version_id=CISCO_IOS_XE_17_KNOWLEDGE_PACK.knowledge_pack_version_id,
        mapping_version_id=mapping.mapping_version_id,
        field_id=mapping.field_id,
        operation=FactOperation.ASSIGN,
    )
    for mapping in CISCO_IOS_XE_17_KNOWLEDGE_PACK.mappings
)
_ACTIVE_OPERATION_POLICIES = tuple(
    MappingOperationPolicy(
        knowledge_pack_version_id=CISCO_IOS_XE_17_KNOWLEDGE_PACK.knowledge_pack_version_id,
        mapping_version_id=mapping.reset_mapping_version_id,
        field_id=mapping.field_id,
        operation=FactOperation.RESET,
    )
    for mapping in CISCO_IOS_XE_17_KNOWLEDGE_PACK.mappings
    if mapping.reset_mapping_version_id is not None
) + tuple(
    MappingOperationPolicy(
        knowledge_pack_version_id=CISCO_IOS_XE_17_KNOWLEDGE_PACK.knowledge_pack_version_id,
        mapping_version_id=mapping.removal_mapping_version_id,
        field_id=mapping.field_id,
        operation=FactOperation.REMOVE,
    )
    for mapping in CISCO_IOS_XE_17_KNOWLEDGE_PACK.mappings
    if mapping.removal_mapping_version_id is not None
)
_FORTIOS_PACK_ID_LEGACY = UUID("a1b2c3d4-2222-5aaa-8aaa-000000000013")
_FORTIOS_PACK_ID_CURRENT = UUID("a1b2c3d4-3333-5aaa-8aaa-000000000013")
_FORTIOS_LEGACY_MAPPING_POLICIES = tuple(
    MappingOperationPolicy(
        knowledge_pack_version_id=_FORTIOS_PACK_ID_LEGACY,
        mapping_version_id=UUID(mapping_id),
        field_id=field_id,
        operation=operation,
    )
    for mapping_id, field_id, operation in (
        ("a1b2c3d4-4101-5aaa-8aaa-000000000013", "management.remote.telnet.enabled", FactOperation.ASSIGN),
        ("a1b2c3d4-4201-5aaa-8aaa-000000000013", "management.remote.telnet.enabled", FactOperation.RESET),
        ("a1b2c3d4-4102-5aaa-8aaa-000000000013", "management.remote.ssh.enabled", FactOperation.ASSIGN),
        ("a1b2c3d4-4202-5aaa-8aaa-000000000013", "management.remote.ssh.enabled", FactOperation.RESET),
        ("a1b2c3d4-4103-5aaa-8aaa-000000000013", "management.session.idle_timeout", FactOperation.ASSIGN),
        ("a1b2c3d4-4203-5aaa-8aaa-000000000013", "management.session.idle_timeout", FactOperation.RESET),
        ("a1b2c3d4-4104-5aaa-8aaa-000000000013", "logging.remote.destination", FactOperation.ASSIGN),
        ("a1b2c3d4-4105-5aaa-8aaa-000000000013", "time.ntp.server", FactOperation.ASSIGN),
    )
)
_FORTIOS_CURRENT_MAPPING_POLICIES = tuple(
    MappingOperationPolicy(
        knowledge_pack_version_id=_FORTIOS_PACK_ID_CURRENT,
        mapping_version_id=UUID(mapping_id),
        field_id=field_id,
        operation=operation,
    )
    for mapping_id, field_id, operation in (
        ("a1b2c3d4-6101-5aaa-8aaa-000000000013", "management.remote.telnet.enabled", FactOperation.ASSIGN),
        ("a1b2c3d4-6201-5aaa-8aaa-000000000013", "management.remote.telnet.enabled", FactOperation.RESET),
        ("a1b2c3d4-6102-5aaa-8aaa-000000000013", "management.remote.ssh.enabled", FactOperation.ASSIGN),
        ("a1b2c3d4-6202-5aaa-8aaa-000000000013", "management.remote.ssh.enabled", FactOperation.RESET),
        ("a1b2c3d4-6103-5aaa-8aaa-000000000013", "management.session.idle_timeout", FactOperation.ASSIGN),
        ("a1b2c3d4-6203-5aaa-8aaa-000000000013", "management.session.idle_timeout", FactOperation.RESET),
        ("a1b2c3d4-6104-5aaa-8aaa-000000000013", "logging.remote.destination", FactOperation.ASSIGN),
        ("a1b2c3d4-6105-5aaa-8aaa-000000000013", "time.ntp.server", FactOperation.ASSIGN),
    )
)
_LEGACY_MAPPING_POLICIES = tuple(
    MappingOperationPolicy(
        knowledge_pack_version_id=LEGACY_KNOWLEDGE_PACK_VERSION_ID,
        mapping_version_id=mapping_version_id,
        field_id=field_id,
        operation=FactOperation.ASSIGN,
    )
    for field_id, mapping_version_id in LEGACY_MAPPING_VERSION_IDS.items()
)
MAPPING_OPERATION_POLICIES: Mapping[tuple[UUID, UUID], MappingOperationPolicy] = (
    MappingProxyType({
        (item.knowledge_pack_version_id, item.mapping_version_id): item
        for item in _LEGACY_MAPPING_POLICIES + _FORTIOS_LEGACY_MAPPING_POLICIES + _FORTIOS_CURRENT_MAPPING_POLICIES + _ACTIVE_MAPPING_POLICIES + _ACTIVE_OPERATION_POLICIES
    })
)

# No IOS XE defaults are registered until a source is reviewed and pinned.
DOCUMENTED_DEFAULTS: Mapping[tuple[str, UUID, str, str], object] = MappingProxyType({})


def get_field_policy(field_id: str) -> FieldResolutionPolicy:
    try:
        return FIELD_POLICIES[field_id]
    except KeyError as exc:
        raise EffectiveStateValidationError("EffectiveState field policy is unavailable") from exc


def get_mapping_operation_policy(
    knowledge_pack_version_id: UUID, mapping_version_id: UUID | None, field_id: str
) -> MappingOperationPolicy:
    if mapping_version_id is None:
        raise EffectiveStateValidationError("SecurityFact mapping provenance is missing")
    policy = MAPPING_OPERATION_POLICIES.get(
        (knowledge_pack_version_id, mapping_version_id)
    )
    if policy is None or policy.field_id != field_id:
        raise EffectiveStateValidationError("SecurityFact mapping provenance is incompatible")
    return policy


def lookup_documented_default(
    profile_version_id: str,
    knowledge_pack_version_id: UUID,
    field_id: str,
    scope_type: str,
    *,
    registry: Mapping[tuple[str, UUID, str, str], object] = DOCUMENTED_DEFAULTS,
) -> object | None:
    validate_policy_metadata(registry=registry)
    return registry.get((profile_version_id, knowledge_pack_version_id, field_id, scope_type))


def validate_policy_metadata(
    *,
    field_policies: Mapping[str, FieldResolutionPolicy] = FIELD_POLICIES,
    mapping_policies: Mapping[tuple[UUID, UUID], MappingOperationPolicy] = MAPPING_OPERATION_POLICIES,
    registry: Mapping[tuple[str, UUID, str, str], object] = DOCUMENTED_DEFAULTS,
) -> None:
    for field_id, policy in field_policies.items():
        field = FIELD_REGISTRY.get(field_id)
        if (
            field is None or policy.field_id != field_id
            or not isinstance(policy.cardinality, FieldCardinality)
            or policy.legal_scope_types != field.allowed_scope_types
            or not policy.precedence_categories
            or any(item != "same_artifact_source_order" for item in policy.precedence_categories)
            or policy.inheritance_scope_types
        ):
            raise EffectiveStateValidationError("EffectiveState field policy is malformed")
    for (pack_id, mapping_id), policy in mapping_policies.items():
        if (
            not isinstance(pack_id, UUID) or not isinstance(mapping_id, UUID)
            or policy.knowledge_pack_version_id != pack_id
            or policy.mapping_version_id != mapping_id
            or policy.field_id not in FIELD_POLICIES
            or not isinstance(policy.operation, FactOperation)
        ):
            raise EffectiveStateValidationError("EffectiveState mapping policy is malformed")
    for key, value in registry.items():
        if (
            not isinstance(key, tuple) or len(key) != 4 or not isinstance(key[0], str)
            or not isinstance(key[1], UUID) or key[2] not in FIELD_POLICIES
            or key[3] not in FIELD_POLICIES[key[2]].legal_scope_types
            or not isinstance(value, Mapping) or set(value) != {"reference", "value"}
        ):
            raise EffectiveStateValidationError("Documented default metadata is malformed")
