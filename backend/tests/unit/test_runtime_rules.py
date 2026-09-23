import pytest

from app.compliance.evaluator import evaluate_condition
from app.compliance.runtime_rules import RuntimeRuleError, _definition
from app.compliance.verdicts import FindingVerdict


def _payload(**changes):
    value = {
        "rule_id": "tenant.ssh.enabled", "profile_version_ids": ["runtime.acme@1.0.0"],
        "canonical_field": "management.remote.ssh.enabled", "operator": "equals",
        "expected": True, "title": "SSH enabled", "security_domain": "management",
        "severity": "high", "framework_references": [],
    }
    value.update(changes)
    return value


def test_runtime_rule_compiles_to_the_existing_safe_evaluator_contract():
    rule = _definition(_payload())
    assert evaluate_condition(rule, {"type": "boolean", "value": True}) is FindingVerdict.PASS
    assert evaluate_condition(rule, {"type": "boolean", "value": False}) is FindingVerdict.FAIL


@pytest.mark.parametrize("changes", (
    {"operator": "python"}, {"operator": "equals", "expected": "true"},
    {"canonical_field": "not.a.field"}, {"operator": "enum_at_least", "expected": "x", "order": ["x"]},
))
def test_runtime_rules_reject_unsupported_or_unsafe_definition_values(changes):
    with pytest.raises(RuntimeRuleError):
        _definition(_payload(**changes))
