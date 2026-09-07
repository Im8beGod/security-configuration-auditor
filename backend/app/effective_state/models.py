from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import UUID, uuid5

from app.security_model import ScopeRef, TypedValue, TypedValueType, validate_field_value_scope

from app.effective_state.contracts import ResolutionStatus, UnresolvedReason
from app.effective_state.exceptions import EffectiveStateValidationError


EFFECTIVE_STATE_NAMESPACE = UUID("0c197da4-5d9a-5c9b-8595-31c2115e4189")


@dataclass(frozen=True)
class EffectiveStateDraft:
    effective_state_id: UUID
    audit_id: UUID
    device_id: UUID
    field_id: str
    scope: ScopeRef
    effective_value: TypedValue | None
    resolution_status: ResolutionStatus
    source_fact_ids: tuple[UUID, ...]
    resolution_trace: tuple[dict[str, Any], ...] = ()
    inherited_from: ScopeRef | None = None
    default_reference: str | None = None
    referenced_objects: tuple[dict[str, Any], ...] = ()
    precedence_applied: tuple[dict[str, Any], ...] = ()
    unresolved_reason: UnresolvedReason | None = None
    created_at: datetime | None = None
    schema_version: str = "1.0.0"


def canonical_scope_key(scope: ScopeRef) -> str:
    """Stable database identity for the frozen ScopeRef shape."""
    _validate_scope(scope)
    return f"{scope.type}::{scope.key}"


def deterministic_effective_state_id(
    audit_id: UUID, field_id: str, scope: ScopeRef
) -> UUID:
    if not isinstance(audit_id, UUID) or audit_id.int == 0 or not field_id.strip():
        raise EffectiveStateValidationError("EffectiveState identity is malformed")
    return uuid5(
        EFFECTIVE_STATE_NAMESPACE,
        f"{audit_id}:{field_id}:{canonical_scope_key(scope)}",
    )


def make_effective_state_draft(
    *,
    audit_id: UUID,
    device_id: UUID,
    field_id: str,
    scope: ScopeRef,
    effective_value: TypedValue | None,
    resolution_status: ResolutionStatus,
    source_fact_ids: tuple[UUID, ...],
    resolution_trace: tuple[dict[str, Any], ...] = (),
    inherited_from: ScopeRef | None = None,
    default_reference: str | None = None,
    referenced_objects: tuple[dict[str, Any], ...] = (),
    precedence_applied: tuple[dict[str, Any], ...] = (),
    unresolved_reason: UnresolvedReason | None = None,
    schema_version: str = "1.0.0",
) -> EffectiveStateDraft:
    draft = EffectiveStateDraft(
        effective_state_id=deterministic_effective_state_id(audit_id, field_id, scope),
        audit_id=audit_id,
        device_id=device_id,
        field_id=field_id,
        scope=scope,
        effective_value=effective_value,
        resolution_status=resolution_status,
        source_fact_ids=source_fact_ids,
        resolution_trace=resolution_trace,
        inherited_from=inherited_from,
        default_reference=default_reference,
        referenced_objects=referenced_objects,
        precedence_applied=precedence_applied,
        unresolved_reason=unresolved_reason,
        created_at=datetime.now(timezone.utc),
        schema_version=schema_version,
    )
    validate_effective_state_draft(draft)
    return draft


def validate_effective_state_draft(draft: EffectiveStateDraft) -> None:
    if (
        not isinstance(draft.audit_id, UUID)
        or not isinstance(draft.device_id, UUID)
        or draft.audit_id.int == 0
        or draft.device_id.int == 0
        or not isinstance(draft.field_id, str)
        or not draft.field_id.strip()
    ):
        raise EffectiveStateValidationError("EffectiveState identity is malformed")
    expected_id = deterministic_effective_state_id(
        draft.audit_id, draft.field_id, draft.scope
    )
    if draft.effective_state_id != expected_id:
        raise EffectiveStateValidationError("EffectiveState ID is not deterministic")
    _validate_scope(draft.scope)
    if draft.inherited_from is not None:
        _validate_scope(draft.inherited_from)
    if draft.effective_value is not None:
        try:
            if draft.effective_value.type is TypedValueType.LIST:
                for item in draft.effective_value.value:
                    validate_field_value_scope(
                        draft.field_id, typed_value_from_dict(item), draft.scope
                    )
            else:
                validate_field_value_scope(draft.field_id, draft.effective_value, draft.scope)
        except ValueError as exc:
            raise EffectiveStateValidationError("EffectiveState value is malformed") from exc
    if len(set(draft.source_fact_ids)) != len(draft.source_fact_ids) or any(
        not isinstance(item, UUID) or item.int == 0 for item in draft.source_fact_ids
    ):
        raise EffectiveStateValidationError("EffectiveState source facts are malformed")
    if draft.resolution_status is ResolutionStatus.RESOLVED:
        if draft.effective_value is None or draft.unresolved_reason is not None:
            raise EffectiveStateValidationError("Resolved EffectiveState requires a value")
    elif draft.resolution_status is ResolutionStatus.UNKNOWN:
        if draft.effective_value is not None or draft.unresolved_reason in {
            None, UnresolvedReason.CONFLICTING_EVIDENCE
        }:
            raise EffectiveStateValidationError("Unknown EffectiveState requires an unknown reason")
    elif draft.resolution_status is ResolutionStatus.CONFLICTING:
        if (
            draft.effective_value is not None
            or draft.unresolved_reason is not UnresolvedReason.CONFLICTING_EVIDENCE
        ):
            raise EffectiveStateValidationError("Conflicting EffectiveState requires conflict reason")
    else:
        raise EffectiveStateValidationError("EffectiveState status is invalid")
    if not isinstance(draft.schema_version, str) or not draft.schema_version.strip():
        raise EffectiveStateValidationError("EffectiveState schema version is malformed")
    for value in (
        draft.resolution_trace,
        draft.referenced_objects,
        draft.precedence_applied,
    ):
        _validate_json_collection(value)


def typed_value_from_dict(value: Mapping[str, Any]) -> TypedValue:
    if not isinstance(value, Mapping) or set(value) != {
        "type", "value", "unit", "original_value", "original_unit"
    }:
        raise EffectiveStateValidationError("SecurityFact TypedValue is malformed")
    try:
        typed_value = TypedValue(
            type=TypedValueType(value["type"]),
            value=value["value"],
            unit=value["unit"],
            original_value=value["original_value"],
            original_unit=value["original_unit"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise EffectiveStateValidationError("SecurityFact TypedValue is malformed") from exc
    return typed_value


def scope_from_dict(value: Mapping[str, Any]) -> ScopeRef:
    if not isinstance(value, Mapping) or set(value) != {"type", "key", "attributes"}:
        raise EffectiveStateValidationError("SecurityFact ScopeRef is malformed")
    scope = ScopeRef(value["type"], value["key"], value["attributes"])
    _validate_scope(scope)
    return scope


def _validate_scope(scope: ScopeRef) -> None:
    if not isinstance(scope.type, str) or not isinstance(scope.key, str) or not isinstance(
        scope.attributes, Mapping
    ):
        raise EffectiveStateValidationError("ScopeRef is malformed")
    if scope.type == "device":
        valid = scope.key == "device" and dict(scope.attributes) == {}
    elif scope.type == "vty_range":
        attributes = dict(scope.attributes)
        start, end = attributes.get("start"), attributes.get("end")
        match = re.fullmatch(r"vty:(\d+)-(\d+)", scope.key)
        key_start, key_end = (
            (int(match.group(1)), int(match.group(2))) if match else (None, None)
        )
        valid = (
            match is not None and 0 <= key_start <= key_end <= 999
            and (
                attributes == {}
                or (
                    set(attributes) == {"start", "end"}
                    and isinstance(start, int) and not isinstance(start, bool)
                    and isinstance(end, int) and not isinstance(end, bool)
                    and (start, end) == (key_start, key_end)
                )
            )
        )
    else:
        valid = False
    if not valid:
        raise EffectiveStateValidationError("ScopeRef is malformed")


def _validate_json_collection(value: tuple[dict[str, Any], ...]) -> None:
    if not isinstance(value, tuple):
        raise EffectiveStateValidationError("EffectiveState metadata must be immutable")
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise EffectiveStateValidationError("EffectiveState metadata is malformed") from exc
    if not encoded.startswith("["):
        raise EffectiveStateValidationError("EffectiveState metadata is malformed")
