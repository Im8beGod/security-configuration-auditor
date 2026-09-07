from __future__ import annotations

from typing import Any

from app.compliance.models import RuleDefinition
from app.compliance.verdicts import FindingVerdict
from app.security_model import TypedValueType


class EvaluationError(ValueError):
    pass


def evaluate_condition(rule: RuleDefinition, value: dict[str, Any], parameter: Any = None) -> FindingVerdict:
    """Evaluate only the small, audited declarative operator vocabulary."""
    operator = rule.condition["operator"]
    candidate = value.get("value")
    value_type = value.get("type")
    if operator == "equals":
        if value_type not in {TypedValueType.BOOLEAN.value, TypedValueType.INTEGER.value}:
            raise EvaluationError("TypedValue is incompatible with equality rule")
        return FindingVerdict.PASS if candidate == rule.condition["expected"] else FindingVerdict.FAIL
    if operator == "less_than_or_equal":
        if value_type != TypedValueType.DURATION.value or isinstance(candidate, bool) or not isinstance(candidate, (int, float)):
            raise EvaluationError("TypedValue is incompatible with duration rule")
        if isinstance(parameter, bool) or not isinstance(parameter, (int, float)):
            raise EvaluationError("Policy maximum is malformed")
        return FindingVerdict.PASS if candidate <= parameter else FindingVerdict.FAIL
    if operator in {"non_empty", "all_members_in_parameter_set"}:
        if value_type != TypedValueType.LIST.value or not isinstance(candidate, list):
            raise EvaluationError("TypedValue is incompatible with collection rule")
        members = []
        for item in candidate:
            if not isinstance(item, dict) or not isinstance(item.get("value"), str):
                raise EvaluationError("Collection member is malformed")
            members.append(item["value"])
        if operator == "non_empty":
            return FindingVerdict.PASS if members else FindingVerdict.FAIL
        if not isinstance(parameter, list) or not all(isinstance(item, str) for item in parameter):
            raise EvaluationError("Policy allow-list is malformed")
        return FindingVerdict.PASS if all(item in set(parameter) for item in members) else FindingVerdict.FAIL
    raise EvaluationError("Rule operator is unsupported")
