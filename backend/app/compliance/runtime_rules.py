"""Strictly declarative, tenant-scoped runtime compliance rules."""

import json
import re
from hashlib import sha256
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.compliance.models import RuleDefinition
from app.compliance.rule_registry import RULE_PACK_BY_PROFILE, RuleRegistry
from app.compliance.verdicts import FindingSeverity
from app.db.models import MappingStatus, MappingVersion, RuntimeRuleVersion
from app.profile_resolution.runtime import RuntimeProfileError, profile_for
from app.security_model import FIELD_REGISTRY
from app.security_model import TypedValueType


_ID = re.compile(r"[A-Za-z][A-Za-z0-9._:-]{0,254}")
_OPS = frozenset({"equals", "less_than_or_equal", "non_empty", "all_members_in_parameter_set", "enum_at_least"})


class RuntimeRuleError(ValueError):
    pass


def _text(value: Any, label: str, limit: int = 255) -> str:
    value = value.strip() if isinstance(value, str) else ""
    if not value or len(value) > limit:
        raise RuntimeRuleError(f"Runtime rule {label} is invalid")
    return value


def _definition(payload: dict[str, Any]) -> RuleDefinition:
    rule_id = _text(payload.get("rule_id"), "ID")
    profiles = payload.get("profile_version_ids")
    field = _text(payload.get("canonical_field"), "canonical field")
    operator = payload.get("operator")
    if not _ID.fullmatch(rule_id) or not isinstance(profiles, list) or not profiles or len(profiles) > 32 or len(set(profiles)) != len(profiles) or any(not isinstance(item, str) or not item for item in profiles) or field not in FIELD_REGISTRY or operator not in _OPS:
        raise RuntimeRuleError("Runtime rule definition is invalid")
    field_types = FIELD_REGISTRY[field].expected_types
    required_type = {
        "equals": {TypedValueType.BOOLEAN, TypedValueType.INTEGER},
        "less_than_or_equal": {TypedValueType.DURATION},
        "non_empty": {TypedValueType.LIST},
        "all_members_in_parameter_set": {TypedValueType.LIST},
        "enum_at_least": {TypedValueType.ENUM},
    }[operator]
    if not field_types.issubset(required_type):
        raise RuntimeRuleError("Runtime rule operator is incompatible with its canonical field")
    condition: dict[str, Any] = {"operator": operator}
    parameter = payload.get("required_policy_parameter")
    if operator in {"equals", "enum_at_least"}:
        expected = payload.get("expected")
        if (operator == "equals" and (type(expected) not in {bool, int})) or (operator == "enum_at_least" and not isinstance(expected, str)):
            raise RuntimeRuleError("Runtime rule expected value is invalid")
        condition["expected"] = expected
    if operator in {"less_than_or_equal", "all_members_in_parameter_set"}:
        if not _ID.fullmatch(_text(parameter, "policy parameter")):
            raise RuntimeRuleError("Runtime rule policy parameter is invalid")
        condition["parameter"] = parameter
    elif parameter is not None:
        raise RuntimeRuleError("Runtime rule policy parameter is invalid")
    minimum = payload.get("minimum_exclusive")
    if minimum is not None:
        if operator != "less_than_or_equal" or isinstance(minimum, bool) or not isinstance(minimum, (int, float)):
            raise RuntimeRuleError("Runtime rule lower bound is invalid")
        condition["minimum_exclusive"] = minimum
    order = payload.get("order")
    if operator == "enum_at_least":
        if not isinstance(order, list) or len(order) < 2 or len(set(order)) != len(order) or any(not isinstance(item, str) or not item for item in order) or condition["expected"] not in order:
            raise RuntimeRuleError("Runtime rule enum order is invalid")
        condition["order"] = order
    elif order is not None:
        raise RuntimeRuleError("Runtime rule enum order is invalid")
    references = payload.get("framework_references", [])
    if not isinstance(references, list):
        raise RuntimeRuleError("Runtime rule framework provenance is invalid")
    try:
        severity = FindingSeverity(_text(payload.get("severity"), "severity", 32))
    except ValueError as exc:
        raise RuntimeRuleError("Runtime rule severity is invalid") from exc
    rule = RuleDefinition(rule_id, _text(payload.get("title"), "title"), _text(payload.get("description", payload.get("title")), "description", 2048), _text(payload.get("security_domain"), "security domain", 128), severity, "Administrator-published runtime rule.", {"profile_version_ids": tuple(profiles)}, (field,), condition, ((parameter,) if parameter else ()), tuple(references))
    try:
        RuleRegistry._validate(type("Pack", (), {"name": "runtime", "version": "1", "rules": (rule,), "schema_version": "1.0.0", "profile_version_id": profiles[0]})())
    except (ValueError, TypeError) as exc:
        raise RuntimeRuleError("Runtime rule definition is invalid") from exc
    return rule


def _mapped(db: Session, organization_id: UUID, profile_version_id: str, field_id: str) -> bool:
    return db.scalar(select(MappingVersion.mapping_version_id).where(MappingVersion.organization_id == organization_id, MappingVersion.status == MappingStatus.PUBLISHED, MappingVersion.target_field_id == field_id).where(MappingVersion.profile_applicability["profile_version_ids"].contains([profile_version_id])).limit(1)) is not None


def validate_runtime_rule(db: Session, organization_id: UUID, payload: dict[str, Any]) -> RuleDefinition:
    rule = _definition(payload)
    for profile_id in rule.applicability["profile_version_ids"]:
        try:
            profile = profile_for(db, organization_id, profile_id)
        except RuntimeProfileError as exc:
            raise RuntimeRuleError("Runtime rule references an unavailable profile") from exc
        if profile is None:
            raise RuntimeRuleError("Runtime rule references an unavailable profile")
        if profile_id in RULE_PACK_BY_PROFILE:
            if rule.required_effective_states[0] not in profile.coverage_manifest.get("canonical_fields", ()):
                raise RuntimeRuleError("Runtime rule canonical field is unsupported")
        elif not _mapped(db, organization_id, profile_id, rule.required_effective_states[0]):
            raise RuntimeRuleError("Runtime rule canonical field is unsupported")
    return rule


def publish_runtime_rule(db: Session, organization_id: UUID, payload: dict[str, Any]) -> RuntimeRuleVersion:
    rule = validate_runtime_rule(db, organization_id, payload)
    version = (db.scalar(select(func.max(RuntimeRuleVersion.version)).where(RuntimeRuleVersion.organization_id == organization_id, RuntimeRuleVersion.rule_id == rule.rule_id)) or 0) + 1
    content = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    row = RuntimeRuleVersion(organization_id=organization_id, rule_id=rule.rule_id, version=version, profile_version_ids=list(rule.applicability["profile_version_ids"]), canonical_field=rule.required_effective_states[0], operator=rule.condition["operator"], condition=dict(rule.condition), required_policy_parameters=list(rule.required_policy_parameters), title=rule.title, security_domain=rule.security_domain, severity=rule.severity.value, framework_references=list(rule.framework_references), content_digest=sha256(content.encode()).hexdigest())
    db.add(row); db.flush()
    return row


def runtime_rule_for(db: Session, organization_id: UUID, rule_id: str, profile_version_id: str) -> RuleDefinition:
    rows = list(db.scalars(select(RuntimeRuleVersion).where(RuntimeRuleVersion.organization_id == organization_id, RuntimeRuleVersion.rule_id == rule_id, RuntimeRuleVersion.status == "published").order_by(RuntimeRuleVersion.version.desc())))
    rows = [row for row in rows if profile_version_id in row.profile_version_ids]
    if rows:
        row = rows[0]
        return RuleDefinition(row.rule_id, row.title, row.title, row.security_domain, FindingSeverity(row.severity), "Administrator-published runtime rule.", {"profile_version_ids": tuple(row.profile_version_ids)}, (row.canonical_field,), row.condition, tuple(row.required_policy_parameters), tuple(row.framework_references))
    pack = RULE_PACK_BY_PROFILE.get(profile_version_id)
    rule = next((item for item in (pack.rules if pack else ()) if item.rule_id == rule_id), None)
    if rule is None:
        raise RuntimeRuleError("Runtime rule evaluator is unavailable")
    return rule
