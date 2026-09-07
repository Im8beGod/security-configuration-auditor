from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from app.compliance.applicability import determine_applicability
from app.compliance.evaluator import EvaluationError, evaluate_condition
from app.compliance.models import (
    ApplicabilityStatus, FindingDraft, OrganizationPolicyVersion, comparison_key,
    deterministic_finding_id, deterministic_policy_version_id,
)
from app.compliance.policy import OrganizationPolicyRegistry, PolicyRegistryError
from app.compliance.rule_registry import RULE_PACK, RuleRegistry, RuleRegistryError
from app.compliance.verdicts import FindingVerdict
from app.effective_state import UnresolvedReason
from app.profile_resolution import CISCO_IOS_XE_17
from app.security_model import ScopeRef


def _value(type_, value):
    return {"type": type_, "value": value, "unit": None, "original_value": None, "original_unit": None}


def rule(rule_id):
    return next(item for item in RULE_PACK.rules if item.rule_id == rule_id)


@pytest.mark.parametrize(("rule_id", "value", "expected"), [
    ("management.telnet.disabled", _value("boolean", False), FindingVerdict.PASS),
    ("management.telnet.disabled", _value("boolean", True), FindingVerdict.FAIL),
    ("management.ssh.enabled", _value("boolean", True), FindingVerdict.PASS),
    ("management.ssh.enabled", _value("boolean", False), FindingVerdict.FAIL),
    ("management.ssh.version_2", _value("integer", 2), FindingVerdict.PASS),
    ("management.ssh.version_2", _value("integer", 1), FindingVerdict.FAIL),
    ("management.idle_timeout.maximum", _value("duration", 300), FindingVerdict.PASS),
    ("management.idle_timeout.maximum", _value("duration", 301), FindingVerdict.FAIL),
    ("logging.remote.destination.configured", _value("list", []), FindingVerdict.FAIL),
    ("logging.remote.destination.configured", _value("list", [{"value": "192.0.2.1"}]), FindingVerdict.PASS),
    ("time.ntp.server.configured", _value("list", []), FindingVerdict.FAIL),
    ("time.ntp.server.configured", _value("list", [{"value": "192.0.2.1"}]), FindingVerdict.PASS),
    ("logging.remote.destination.approved", _value("list", [{"value": "192.0.2.1"}]), FindingVerdict.PASS),
    ("time.ntp.server.approved", _value("list", [{"value": "192.0.2.2"}]), FindingVerdict.FAIL),
])
def test_bounded_rules_produce_expected_verdicts(rule_id, value, expected):
    parameter = 300 if rule_id == "management.idle_timeout.maximum" else ["192.0.2.1"]
    assert evaluate_condition(rule(rule_id), value, parameter) is expected


def test_registry_is_versioned_immutable_and_fails_closed():
    assert len(RULE_PACK.rules) == 8
    assert RuleRegistry().get(RULE_PACK.rule_pack_version_id) is RULE_PACK
    with pytest.raises(RuleRegistryError, match="unavailable"):
        RuleRegistry().get(uuid4())
    bad = SimpleNamespace(rule_pack_version_id=uuid4(), name="bad", version="1", rules=(
        SimpleNamespace(rule_id="duplicate", required_effective_states=("a",), condition={"operator": "equals"}),
        SimpleNamespace(rule_id="duplicate", required_effective_states=("a",), condition={"operator": "equals"}),
    ))
    with pytest.raises(RuleRegistryError, match="duplicate"):
        RuleRegistry((bad,))
    changed = replace(RULE_PACK, rules=(replace(RULE_PACK.rules[0], title="Changed"), *RULE_PACK.rules[1:]))
    with pytest.raises(RuleRegistryError, match="content conflicts"):
        RuleRegistry((RULE_PACK, changed))


def test_unsupported_operator_and_typed_value_fail_closed():
    bad_rule = SimpleNamespace(condition={"operator": "eval"})
    with pytest.raises(EvaluationError, match="unsupported"):
        evaluate_condition(bad_rule, _value("boolean", True))
    with pytest.raises(EvaluationError, match="incompatible"):
        evaluate_condition(rule("management.ssh.enabled"), _value("string", "true"))


def test_policy_identity_is_stable_and_unknown_versions_fail_closed():
    organization_id = UUID(int=1)
    registry = OrganizationPolicyRegistry()
    first = registry.register(organization_id=organization_id, name="org", version="1.0.0", parameters={"approved_ntp_servers": ["192.0.2.1"]})
    second = registry.register(organization_id=organization_id, name="org", version="1.0.0", parameters={"approved_ntp_servers": ["192.0.2.1"]})
    assert first.organization_policy_version_id == second.organization_policy_version_id
    assert first.organization_policy_version_id == deterministic_policy_version_id(organization_id, "org", "1.0.0", first.parameters)
    with pytest.raises(PolicyRegistryError, match="content conflicts"):
        registry.register(organization_id=organization_id, name="org", version="1.0.0", parameters={"approved_ntp_servers": ["192.0.2.2"]})
    with pytest.raises(PolicyRegistryError, match="unavailable"):
        registry.get(uuid4())


def test_applicability_distinguishes_supported_nonapplicable_and_unresolved():
    supported = SimpleNamespace(profile_resolution={"resolution_status": "resolved", "profile_version_id": CISCO_IOS_XE_17.profile_version_id})
    assert determine_applicability(supported, RULE_PACK).status is ApplicabilityStatus.APPLICABLE
    other = SimpleNamespace(profile_resolution={"resolution_status": "resolved", "profile_version_id": "junos@1"})
    assert determine_applicability(other, RULE_PACK).status is ApplicabilityStatus.NOT_APPLICABLE
    unresolved = SimpleNamespace(profile_resolution={"resolution_status": "unresolved"})
    result = determine_applicability(unresolved, RULE_PACK)
    assert result.status is ApplicabilityStatus.UNRESOLVED
    assert result.reason is UnresolvedReason.UNSUPPORTED_PROFILE


def test_finding_identity_and_comparison_key_are_scope_stable():
    audit_id = UUID(int=99)
    first = ScopeRef("vty_range", "vty:0-4", {"start": 0, "end": 4})
    second = ScopeRef("vty_range", "vty:5-15", {"start": 5, "end": 15})
    assert deterministic_finding_id(audit_id, "management.ssh.enabled", first) == deterministic_finding_id(audit_id, "management.ssh.enabled", first)
    assert deterministic_finding_id(audit_id, "management.ssh.enabled", first) != deterministic_finding_id(audit_id, "management.ssh.enabled", second)
    assert comparison_key("management.ssh.enabled", first) == "management.ssh.enabled::vty_range::vty:0-4"
    assert comparison_key("management.ssh.enabled", None).endswith("unscoped::rule")
