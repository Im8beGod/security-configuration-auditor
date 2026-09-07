"""Deterministic, persisted-fact-only EffectiveState resolution."""

from __future__ import annotations

import json
from dataclasses import dataclass
from itertools import groupby
from typing import Iterable, Mapping
from uuid import UUID

from app.db.models import SecurityFact
from app.effective_state.contracts import ResolutionStatus, UnresolvedReason
from app.effective_state.exceptions import EffectiveStateValidationError
from app.effective_state.models import (
    EffectiveStateDraft,
    make_effective_state_draft,
    scope_from_dict,
    typed_value_from_dict,
)
from app.effective_state.policy import FactOperation, FieldCardinality, get_field_policy, get_mapping_operation_policy
from app.security_model import ScopeRef, TypedValue, TypedValueType


MAX_TRACE_ENTRIES = 128


@dataclass(frozen=True)
class ClassifiedFact:
    fact: SecurityFact
    scope: ScopeRef
    value: TypedValue
    operation: FactOperation
    artifact_id: str
    source_line: int


def resolve_security_facts(
    *, audit_id: UUID, device_id: UUID, facts: Iterable[SecurityFact], operations: Mapping[UUID, FactOperation] | None = None
) -> tuple[EffectiveStateDraft, ...]:
    """Resolve valid persisted facts without configuration parsing or storage access."""
    source_facts = tuple(facts)
    blocked_dependencies = _blocked_dependency_ids(source_facts)
    classified = tuple(_classify(fact, operations.get(fact.fact_id) if operations else None) for fact in source_facts)
    drafts: list[EffectiveStateDraft] = []
    for field_id, field_facts in groupby(
        sorted(classified, key=lambda item: (item.fact.field_id, item.scope.type, item.scope.key, str(item.fact.fact_id))),
        key=lambda item: item.fact.field_id,
    ):
        policy = get_field_policy(field_id)
        grouped_facts = tuple(field_facts)
        blocked = tuple(item for item in grouped_facts if item.fact.fact_id in blocked_dependencies)
        if blocked:
            scopes = {item.scope.key: item.scope for item in blocked}
            drafts.extend(_unknown(
                audit_id, device_id, field_id, scope,
                tuple(sorted({item.fact.fact_id for item in blocked}, key=str)),
                [_trace("dependency_missing", fact_id=str(item.fact.fact_id)) for item in blocked],
                reason=UnresolvedReason.MISSING_EVIDENCE,
            ) for scope in scopes.values())
        elif policy.cardinality is FieldCardinality.SCALAR:
            drafts.extend(_resolve_scalar_field(audit_id, device_id, field_id, grouped_facts))
        else:
            drafts.extend(_resolve_repeatable_field(audit_id, device_id, field_id, grouped_facts))
    return tuple(sorted(drafts, key=lambda item: (item.field_id, item.scope.type, item.scope.key)))


def _blocked_dependency_ids(facts: tuple[SecurityFact, ...]) -> set[UUID]:
    """Bound dependency traversal and fail closed on missing or cyclic references."""
    ids = {item.fact_id for item in facts}
    graph: dict[UUID, set[UUID]] = {}
    blocked: set[UUID] = set()
    for fact in facts:
        dependencies: set[UUID] = set()
        for value in fact.dependencies:
            try:
                dependency_id = UUID(str(value))
            except (TypeError, ValueError):
                blocked.add(fact.fact_id)
                continue
            dependencies.add(dependency_id)
            if dependency_id not in ids:
                blocked.add(fact.fact_id)
        graph[fact.fact_id] = dependencies
    for root in graph:
        seen: set[UUID] = set()
        stack = [root]
        while stack:
            current = stack.pop()
            if current in seen or len(seen) >= 128:
                blocked.add(root)
                break
            seen.add(current)
            for dependency in graph.get(current, ()):
                if dependency == root:
                    blocked.add(root)
                elif dependency in graph:
                    stack.append(dependency)
    return blocked


def _classify(fact: SecurityFact, persisted_operation: FactOperation | None = None) -> ClassifiedFact:
    scope = scope_from_dict(fact.scope)
    value = typed_value_from_dict(fact.value)
    operation = persisted_operation or get_mapping_operation_policy(fact.knowledge_pack_version_id, fact.mapping_version_id, fact.field_id).operation
    refs = fact.evidence_refs
    if not isinstance(refs, list) or not refs:
        raise EffectiveStateValidationError("SecurityFact ordering provenance is missing")
    artifact_ids = {item.get("artifact_id") for item in refs if isinstance(item, dict)}
    lines = [item.get("start_line") for item in refs if isinstance(item, dict)]
    if len(artifact_ids) != 1 or None in artifact_ids or not lines or any(
        not isinstance(item, int) or item < 1 for item in lines
    ):
        raise EffectiveStateValidationError("SecurityFact ordering provenance is malformed")
    if operation is FactOperation.RESET and value.type is not TypedValueType.NULL:
        raise EffectiveStateValidationError("SecurityFact reset value is malformed")
    if operation is FactOperation.REMOVE and value.type is TypedValueType.NULL:
        raise EffectiveStateValidationError("SecurityFact removal value is malformed")
    return ClassifiedFact(fact, scope, value, operation, next(iter(artifact_ids)), min(lines))


def _resolve_scalar_field(audit_id: UUID, device_id: UUID, field_id: str, facts: tuple[ClassifiedFact, ...]) -> list[EffectiveStateDraft]:
    if not facts:
        return []
    if facts[0].scope.type != "vty_range":
        return [_resolve_scalar_scope(audit_id, device_id, field_id, facts[0].scope, facts)]
    result = []
    for scope, applicable in _vty_partitions(facts):
        result.append(_resolve_scalar_scope(audit_id, device_id, field_id, scope, applicable))
    return result


def _resolve_scalar_scope(audit_id: UUID, device_id: UUID, field_id: str, scope: ScopeRef, facts: tuple[ClassifiedFact, ...]) -> EffectiveStateDraft:
    # Partitioning determines which operations apply. Scope size never determines
    # precedence; the policy only permits later source positions in one artifact.
    trace = [_trace("input_fact", fact_id=str(item.fact.fact_id), scope_key=item.scope.key) for item in facts]
    winner, conflict = _ordered_winner(facts)
    source_ids = tuple(sorted({item.fact.fact_id for item in facts}, key=str))
    if conflict:
        return _unknown(audit_id, device_id, field_id, scope, source_ids, trace + [_trace("conflict_detected")], conflict=True)
    if winner.operation is FactOperation.RESET:
        return _unknown(audit_id, device_id, field_id, scope, source_ids, trace + [_trace("default_missing", fact_id=str(winner.fact.fact_id))], reason=UnresolvedReason.UNRESOLVED_DEFAULT)
    if winner.operation is not FactOperation.ASSIGN:
        return _unknown(audit_id, device_id, field_id, scope, source_ids, trace + [_trace("unresolved")], reason=UnresolvedReason.UNKNOWN_SEMANTICS)
    equivalent = tuple(item for item in facts if _value_key(item.value) == _value_key(winner.value))
    if len(equivalent) > 1:
        trace.append(_trace("duplicate_collapsed", fact_ids=[str(item.fact.fact_id) for item in equivalent]))
    trace.append(_trace("explicit_selected", fact_id=str(winner.fact.fact_id)))
    return make_effective_state_draft(
        audit_id=audit_id, device_id=device_id, field_id=field_id, scope=scope,
        effective_value=winner.value, resolution_status=ResolutionStatus.RESOLVED,
        source_fact_ids=source_ids, resolution_trace=tuple(_bounded(trace)),
        precedence_applied=tuple([
            {"rule": "same_artifact_source_order", "winner_fact_id": str(winner.fact.fact_id)}
        ] if len(facts) > 1 else []),
    )


def _resolve_repeatable_field(audit_id: UUID, device_id: UUID, field_id: str, facts: tuple[ClassifiedFact, ...]) -> list[EffectiveStateDraft]:
    grouped = groupby(sorted(facts, key=lambda item: (item.scope.type, item.scope.key, _value_key(item.value))), key=lambda item: (item.scope.type, item.scope.key))
    results = []
    for (_, _), scoped in grouped:
        items = tuple(scoped)
        scope = items[0].scope
        members: dict[str, list[ClassifiedFact]] = {}
        for item in items:
            members.setdefault(_value_key(item.value), []).append(item)
        trace = [_trace("input_fact", fact_id=str(item.fact.fact_id), scope_key=scope.key) for item in items]
        values: list[TypedValue] = []
        conflict = False
        for key in sorted(members):
            winner, member_conflict = _ordered_winner(tuple(members[key]))
            conflict = conflict or member_conflict
            if member_conflict:
                continue
            if winner.operation is FactOperation.ASSIGN:
                values.append(winner.value)
                trace.append(_trace("collection_member_added", fact_id=str(winner.fact.fact_id)))
            elif winner.operation is FactOperation.REMOVE:
                trace.append(_trace("collection_member_removed", fact_id=str(winner.fact.fact_id)))
            else:
                conflict = True
        source_ids = tuple(sorted({item.fact.fact_id for item in items}, key=str))
        if conflict:
            results.append(_unknown(audit_id, device_id, field_id, scope, source_ids, trace + [_trace("conflict_detected")], conflict=True))
            continue
        collection = TypedValue(TypedValueType.LIST, [item.to_dict() for item in values])
        results.append(make_effective_state_draft(
            audit_id=audit_id, device_id=device_id, field_id=field_id, scope=scope,
            effective_value=collection, resolution_status=ResolutionStatus.RESOLVED,
            source_fact_ids=source_ids, resolution_trace=tuple(_bounded(trace)),
        ))
    return results


def _vty_partitions(facts: tuple[ClassifiedFact, ...]) -> Iterable[tuple[ScopeRef, tuple[ClassifiedFact, ...]]]:
    boundaries = sorted({point for item in facts for point in (_vty_bounds(item.scope)[0], _vty_bounds(item.scope)[1] + 1)})
    for start, after_end in zip(boundaries, boundaries[1:]):
        end = after_end - 1
        applicable = tuple(item for item in facts if _vty_bounds(item.scope)[0] <= start and _vty_bounds(item.scope)[1] >= end)
        if applicable:
            yield ScopeRef("vty_range", f"vty:{start}-{end}", {"start": start, "end": end}), applicable


def _ordered_winner(facts: tuple[ClassifiedFact, ...]) -> tuple[ClassifiedFact, bool]:
    artifacts = {item.artifact_id for item in facts}
    if len(artifacts) > 1:
        operations = {(item.operation, _value_key(item.value)) for item in facts}
        if len(operations) == 1:
            return sorted(facts, key=lambda item: str(item.fact.fact_id))[0], False
        return sorted(facts, key=lambda item: str(item.fact.fact_id))[0], True
    ordered = sorted(facts, key=lambda item: (item.source_line, str(item.fact.fact_id)))
    final_line = ordered[-1].source_line
    final_operations = {
        (item.operation, _value_key(item.value))
        for item in ordered if item.source_line == final_line
    }
    if len(final_operations) > 1:
        return ordered[-1], True
    return ordered[-1], False


def _unknown(audit_id, device_id, field_id, scope, source_ids, trace, *, reason=UnresolvedReason.CONFLICTING_EVIDENCE, conflict=False):
    return make_effective_state_draft(
        audit_id=audit_id, device_id=device_id, field_id=field_id, scope=scope,
        effective_value=None,
        resolution_status=ResolutionStatus.CONFLICTING if conflict else ResolutionStatus.UNKNOWN,
        source_fact_ids=source_ids, resolution_trace=tuple(_bounded(trace)),
        unresolved_reason=UnresolvedReason.CONFLICTING_EVIDENCE if conflict else reason,
    )


def _vty_bounds(scope: ScopeRef) -> tuple[int, int]:
    if scope.type != "vty_range":
        raise EffectiveStateValidationError("VTY scope is required")
    start, end = scope.key.removeprefix("vty:").split("-", 1)
    return int(start), int(end)


def _value_key(value: TypedValue) -> str:
    return json.dumps(value.to_dict(), sort_keys=True, separators=(",", ":"))


def _trace(event: str, **values):
    return {"event": event, **values}


def _bounded(trace: list[dict]) -> list[dict]:
    return trace[:MAX_TRACE_ENTRIES]
