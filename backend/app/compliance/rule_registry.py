from __future__ import annotations

from dataclasses import replace
from types import MappingProxyType
from typing import Mapping
from uuid import uuid5

from app.compliance.models import RULE_PACK_NAMESPACE, RuleDefinition, RulePack
from app.compliance.verdicts import FindingSeverity
from app.profile_resolution import CISCO_IOS_XE_17, FORTIOS_7, JUNIPER_JUNOS_18


class RuleRegistryError(ValueError):
    pass


SUPPORTED_OPERATORS = frozenset({
    "equals", "less_than_or_equal", "non_empty", "all_members_in_parameter_set",
})

NIST_FRAMEWORK = "NIST SP 800-53"
NIST_REVISION = "Rev. 5"
VERIFIED_NIST_TITLES = {
    "AC-11": "Device Lock",
    "AC-17": "Remote Access",
    "AU-8": "Time Stamps",
    "AU-12": "Audit Record Generation",
}


def _nist(control_id: str) -> dict[str, str]:
    return {
        "framework": NIST_FRAMEWORK,
        "revision": NIST_REVISION,
        "control_id": control_id,
        "control_title": VERIFIED_NIST_TITLES[control_id],
    }


def _rule(rule_id: str, title: str, domain: str, severity: FindingSeverity, field: str,
          operator: str, expected: object | None = None, parameter: str | None = None,
          framework_references: tuple[dict[str, str], ...] = ()) -> RuleDefinition:
    condition: dict[str, object] = {"operator": operator}
    if expected is not None:
        condition["expected"] = expected
    if parameter is not None:
        condition["parameter"] = parameter
    return RuleDefinition(
        rule_id=rule_id, title=title, description=title, security_domain=domain,
        severity=severity, severity_reason="Internal technical baseline severity.",
        applicability=MappingProxyType({"profile_version_id": CISCO_IOS_XE_17.profile_version_id}),
        required_effective_states=(field,), condition=MappingProxyType(condition),
        required_policy_parameters=((parameter,) if parameter else ()),
        framework_references=framework_references,
    )


RULES = (
    _rule("management.telnet.disabled", "Telnet management access disabled", "management", FindingSeverity.HIGH, "management.remote.telnet.enabled", "equals", False, framework_references=(_nist("AC-17"),)),
    _rule("management.ssh.enabled", "SSH management access enabled", "management", FindingSeverity.HIGH, "management.remote.ssh.enabled", "equals", True, framework_references=(_nist("AC-17"),)),
    _rule("management.ssh.version_2", "SSH protocol version 2 required", "management", FindingSeverity.MEDIUM, "management.remote.ssh.version", "equals", 2, framework_references=(_nist("AC-17"),)),
    _rule("management.idle_timeout.maximum", "Administrative idle timeout within organization maximum", "management", FindingSeverity.MEDIUM, "management.session.idle_timeout", "less_than_or_equal", parameter="maximum_admin_idle_timeout_seconds", framework_references=(_nist("AC-11"),)),
    _rule("logging.enabled", "Configuration logging enabled", "logging", FindingSeverity.MEDIUM, "logging.enabled", "equals", True, framework_references=(_nist("AU-12"),)),
    _rule("logging.remote.destination.configured", "Remote logging destination configured", "logging", FindingSeverity.MEDIUM, "logging.remote.destination", "non_empty", framework_references=(_nist("AU-12"),)),
    _rule("logging.remote.destination.approved", "Remote logging destinations approved by organization policy", "logging", FindingSeverity.MEDIUM, "logging.remote.destination", "all_members_in_parameter_set", parameter="approved_logging_destinations"),
    _rule("time.ntp.server.configured", "NTP server configured", "time", FindingSeverity.MEDIUM, "time.ntp.server", "non_empty", framework_references=(_nist("AU-8"),)),
    _rule("time.ntp.configured", "NTP configuration present", "time", FindingSeverity.MEDIUM, "time.ntp.configured", "equals", True, framework_references=(_nist("AU-8"),)),
    _rule("time.ntp.server.approved", "NTP servers approved by organization policy", "time", FindingSeverity.MEDIUM, "time.ntp.server", "all_members_in_parameter_set", parameter="approved_ntp_servers"),
)

RULE_PACK = RulePack(
    rule_pack_version_id=uuid5(RULE_PACK_NAMESPACE, "cisco_iosxe_17_technical_baseline@1.0.0"),
    name="cisco_iosxe_17_technical_baseline", version="1.0.0",
    profile_version_id=CISCO_IOS_XE_17.profile_version_id, rules=RULES,
)

FORTIOS_RULE_PACK = RulePack(
    rule_pack_version_id=uuid5(RULE_PACK_NAMESPACE, "fortios_7_technical_baseline@1.0.0"),
    name="fortios_7_technical_baseline", version="1.0.0",
    profile_version_id=FORTIOS_7.profile_version_id,
    rules=tuple(replace(rule, applicability=MappingProxyType({"profile_version_id": FORTIOS_7.profile_version_id})) for rule in RULES),
)

JUNOS_RULE_PACK = RulePack(
    rule_pack_version_id=uuid5(RULE_PACK_NAMESPACE, "juniper_junos_18_technical_baseline@1.0.0"),
    name="juniper_junos_18_technical_baseline", version="1.0.0",
    profile_version_id=JUNIPER_JUNOS_18.profile_version_id,
    rules=tuple(replace(rule, applicability=MappingProxyType({"profile_version_id": JUNIPER_JUNOS_18.profile_version_id})) for rule in RULES),
)


class RuleRegistry:
    def __init__(self, packs: tuple[RulePack, ...] = (RULE_PACK,)) -> None:
        self._packs = {}
        self._logical_versions: dict[tuple[str, str], RulePack] = {}
        for pack in packs:
            self._validate(pack)
            existing = self._packs.get(pack.rule_pack_version_id)
            logical = self._logical_versions.get((pack.name, pack.version))
            if (existing is not None and existing != pack) or (logical is not None and logical != pack):
                raise RuleRegistryError("Rule pack version content conflicts")
            self._packs[pack.rule_pack_version_id] = pack
            self._logical_versions[(pack.name, pack.version)] = pack

    def get(self, version_id):
        try:
            return self._packs[version_id]
        except KeyError as exc:
            raise RuleRegistryError("Rule pack version is unavailable") from exc

    @staticmethod
    def _validate(pack: RulePack) -> None:
        if not pack.name.strip() or not pack.version.strip() or not pack.rules:
            raise RuleRegistryError("Rule pack is malformed")
        ids = [rule.rule_id for rule in pack.rules]
        if len(ids) != len(set(ids)) or any(not item.strip() for item in ids):
            raise RuleRegistryError("Rule pack has duplicate or malformed rule IDs")
        for rule in pack.rules:
            if len(rule.required_effective_states) != 1:
                raise RuleRegistryError("Only single-field rules are supported in Step 7.1")
            if rule.condition.get("operator") not in SUPPORTED_OPERATORS:
                raise RuleRegistryError("Rule pack uses an unsupported operator")
            _validate_framework_references(rule.framework_references)


def _validate_framework_references(references: tuple[dict[str, object], ...]) -> None:
    seen: set[tuple[str, str, str]] = set()
    for reference in references:
        if not isinstance(reference, Mapping):
            raise RuleRegistryError("Framework reference is malformed")
        required = {"framework", "revision", "control_id", "control_title"}
        if any(not isinstance(reference.get(key), str) or not reference[key].strip() for key in required):
            raise RuleRegistryError("Framework reference is malformed")
        identity = (reference["framework"], reference["revision"], reference["control_id"])
        if identity in seen:
            raise RuleRegistryError("Framework reference is duplicated")
        seen.add(identity)
        if reference["framework"] == NIST_FRAMEWORK and reference["revision"] == NIST_REVISION:
            if VERIFIED_NIST_TITLES.get(reference["control_id"]) != reference["control_title"]:
                raise RuleRegistryError("NIST control title is not verified")


RULE_REGISTRY = RuleRegistry((RULE_PACK, FORTIOS_RULE_PACK, JUNOS_RULE_PACK))


RULE_PACK_BY_PROFILE = {
    CISCO_IOS_XE_17.profile_version_id: RULE_PACK,
    FORTIOS_7.profile_version_id: FORTIOS_RULE_PACK,
    JUNIPER_JUNOS_18.profile_version_id: JUNOS_RULE_PACK,
}
