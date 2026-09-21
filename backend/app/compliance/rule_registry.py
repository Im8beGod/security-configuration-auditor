from __future__ import annotations

from dataclasses import replace
from types import MappingProxyType
from typing import Mapping
from uuid import uuid5

from app.compliance.models import RULE_PACK_NAMESPACE, RuleDefinition, RulePack
from app.compliance.verdicts import FindingSeverity
from app.profile_resolution import ARISTA_EOS_4, CISCO_IOS_XE_17, FORTIOS_7, GENERIC_CLI, GENERIC_JSON, GENERIC_XML, JUNIPER_JUNOS_18


class RuleRegistryError(ValueError):
    pass


SUPPORTED_OPERATORS = frozenset({
    "equals", "less_than_or_equal", "non_empty", "all_members_in_parameter_set", "enum_at_least",
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
          framework_references: tuple[dict[str, str], ...] = (),
          minimum_exclusive: int | float | None = None,
          order: tuple[str, ...] = ()) -> RuleDefinition:
    condition: dict[str, object] = {"operator": operator}
    if expected is not None:
        condition["expected"] = expected
    if parameter is not None:
        condition["parameter"] = parameter
    if minimum_exclusive is not None:
        condition["minimum_exclusive"] = minimum_exclusive
    if order:
        condition["order"] = list(order)
    return RuleDefinition(
        rule_id=rule_id, title=title, description=title, security_domain=domain,
        severity=severity, severity_reason="Internal technical baseline severity.",
        applicability=MappingProxyType({"profile_version_id": CISCO_IOS_XE_17.profile_version_id}),
        required_effective_states=(field,), condition=MappingProxyType(condition),
        required_policy_parameters=((parameter,) if parameter else ()),
        framework_references=framework_references,
    )


BASE_RULES = (
    _rule("management.telnet.disabled", "Telnet management access disabled", "management", FindingSeverity.HIGH, "management.remote.telnet.enabled", "equals", False, framework_references=(_nist("AC-17"),)),
    _rule("management.ssh.enabled", "SSH management access enabled", "management", FindingSeverity.HIGH, "management.remote.ssh.enabled", "equals", True, framework_references=(_nist("AC-17"),)),
    _rule("management.ssh.version_2", "SSH protocol version 2 required", "management", FindingSeverity.MEDIUM, "management.remote.ssh.version", "equals", 2, framework_references=(_nist("AC-17"),)),
    _rule("management.source.restriction.configured", "Management source restriction configured", "management", FindingSeverity.MEDIUM, "management.remote.source.restriction.configured", "equals", True),
    _rule("management.idle_timeout.maximum", "Administrative idle timeout within organization maximum", "management", FindingSeverity.MEDIUM, "management.session.idle_timeout", "less_than_or_equal", parameter="maximum_admin_idle_timeout_seconds", framework_references=(_nist("AC-11"),), minimum_exclusive=0),
    _rule("logging.enabled", "Configuration logging enabled", "logging", FindingSeverity.MEDIUM, "logging.enabled", "equals", True, framework_references=(_nist("AU-12"),)),
    _rule("logging.remote.destination.configured", "Remote logging destination configured", "logging", FindingSeverity.MEDIUM, "logging.remote.destination", "non_empty", framework_references=(_nist("AU-12"),)),
    _rule("logging.remote.destination.approved", "Remote logging destinations approved by organization policy", "logging", FindingSeverity.MEDIUM, "logging.remote.destination", "all_members_in_parameter_set", parameter="approved_logging_destinations"),
    _rule("time.ntp.server.configured", "NTP server configured", "time", FindingSeverity.MEDIUM, "time.ntp.server", "non_empty", framework_references=(_nist("AU-8"),)),
    _rule("time.ntp.configured", "NTP configuration present", "time", FindingSeverity.MEDIUM, "time.ntp.configured", "equals", True, framework_references=(_nist("AU-8"),)),
    _rule("time.ntp.authentication.enabled", "Cryptographic NTP source authentication enabled", "time", FindingSeverity.MEDIUM, "time.ntp.authentication.enabled", "equals", True),
    _rule("time.ntp.server.approved", "NTP servers approved by organization policy", "time", FindingSeverity.MEDIUM, "time.ntp.server", "all_members_in_parameter_set", parameter="approved_ntp_servers"),
)

RULES = BASE_RULES + (
    _rule("management.http.disabled", "HTTP management access disabled", "management", FindingSeverity.HIGH, "management.remote.http.enabled", "equals", False, framework_references=(_nist("AC-17"),)),
    _rule("management.https.enabled", "HTTPS management access enabled", "management", FindingSeverity.MEDIUM, "management.remote.https.enabled", "equals", True, framework_references=(_nist("AC-17"),)),
    _rule("management.tls.minimum_1_2", "Administrative TLS minimum version is 1.2", "management", FindingSeverity.HIGH, "management.remote.tls.minimum_version", "enum_at_least", "tlsv1-2", framework_references=(_nist("AC-17"),), order=("tlsv1-0", "tlsv1-1", "tlsv1-2", "tlsv1-3")),
    _rule("management.ssh.strong_crypto", "Strong SSH cryptographic settings configured", "management", FindingSeverity.HIGH, "management.remote.ssh.strong_crypto.configured", "equals", True, framework_references=(_nist("AC-17"),)),
    _rule("logging.administrative_access.enabled", "Administrative access logging enabled", "logging", FindingSeverity.MEDIUM, "logging.administrative_access.enabled", "equals", True, framework_references=(_nist("AU-12"),)),
)


def _rules_for(profile_version_id: str, rules: tuple[RuleDefinition, ...]) -> tuple[RuleDefinition, ...]:
    return tuple(replace(rule, applicability=MappingProxyType({"profile_version_id": profile_version_id})) for rule in rules)


RULE_PACK_V1 = RulePack(
    rule_pack_version_id=uuid5(RULE_PACK_NAMESPACE, "cisco_iosxe_17_technical_baseline@1.0.0"),
    name="cisco_iosxe_17_technical_baseline", version="1.0.0",
    profile_version_id=CISCO_IOS_XE_17.profile_version_id, rules=BASE_RULES,
)

RULE_PACK = RulePack(
    rule_pack_version_id=uuid5(RULE_PACK_NAMESPACE, "cisco_iosxe_17_technical_baseline@1.1.0"),
    name="cisco_iosxe_17_technical_baseline", version="1.1.0",
    profile_version_id=CISCO_IOS_XE_17.profile_version_id, rules=RULES,
)

FORTIOS_RULE_PACK_V1 = RulePack(uuid5(RULE_PACK_NAMESPACE, "fortios_7_technical_baseline@1.0.0"), "fortios_7_technical_baseline", "1.0.0", FORTIOS_7.profile_version_id, _rules_for(FORTIOS_7.profile_version_id, BASE_RULES))

FORTIOS_RULE_PACK = RulePack(
    rule_pack_version_id=uuid5(RULE_PACK_NAMESPACE, "fortios_7_technical_baseline@1.1.0"),
    name="fortios_7_technical_baseline", version="1.1.0",
    profile_version_id=FORTIOS_7.profile_version_id,
    rules=tuple(replace(rule, applicability=MappingProxyType({"profile_version_id": FORTIOS_7.profile_version_id})) for rule in RULES),
)

JUNOS_RULE_PACK_V1 = RulePack(uuid5(RULE_PACK_NAMESPACE, "juniper_junos_18_technical_baseline@1.0.0"), "juniper_junos_18_technical_baseline", "1.0.0", JUNIPER_JUNOS_18.profile_version_id, _rules_for(JUNIPER_JUNOS_18.profile_version_id, BASE_RULES))

JUNOS_RULE_PACK = RulePack(
    rule_pack_version_id=uuid5(RULE_PACK_NAMESPACE, "juniper_junos_18_technical_baseline@1.1.0"),
    name="juniper_junos_18_technical_baseline", version="1.1.0",
    profile_version_id=JUNIPER_JUNOS_18.profile_version_id,
    rules=tuple(replace(rule, applicability=MappingProxyType({"profile_version_id": JUNIPER_JUNOS_18.profile_version_id})) for rule in RULES),
)

ARISTA_RULE_PACK_V1 = RulePack(uuid5(RULE_PACK_NAMESPACE, "arista_eos_4_technical_baseline@1.0.0"), "arista_eos_4_technical_baseline", "1.0.0", ARISTA_EOS_4.profile_version_id, _rules_for(ARISTA_EOS_4.profile_version_id, BASE_RULES))

ARISTA_RULE_PACK = RulePack(
    rule_pack_version_id=uuid5(RULE_PACK_NAMESPACE, "arista_eos_4_technical_baseline@1.1.0"),
    name="arista_eos_4_technical_baseline", version="1.1.0",
    profile_version_id=ARISTA_EOS_4.profile_version_id,
    rules=tuple(replace(rule, applicability=MappingProxyType({"profile_version_id": ARISTA_EOS_4.profile_version_id})) for rule in RULES),
)

GENERIC_RULE_PACK_V1 = RulePack(uuid5(RULE_PACK_NAMESPACE, "generic_cli_technical_baseline@1.0.0"), "generic_cli_technical_baseline", "1.0.0", GENERIC_CLI.profile_version_id, _rules_for(GENERIC_CLI.profile_version_id, BASE_RULES))

GENERIC_RULE_PACK = RulePack(
    rule_pack_version_id=uuid5(RULE_PACK_NAMESPACE, "generic_cli_technical_baseline@1.1.0"),
    name="generic_cli_technical_baseline", version="1.1.0",
    profile_version_id=GENERIC_CLI.profile_version_id,
    rules=tuple(replace(rule, applicability=MappingProxyType({"profile_version_id": GENERIC_CLI.profile_version_id})) for rule in RULES),
)

GENERIC_XML_RULE_PACK = RulePack(
    uuid5(RULE_PACK_NAMESPACE, "generic_xml_technical_baseline@1.0.0"),
    "generic_xml_technical_baseline", "1.0.0", GENERIC_XML.profile_version_id,
    _rules_for(GENERIC_XML.profile_version_id, RULES),
)

GENERIC_JSON_RULE_PACK = RulePack(
    uuid5(RULE_PACK_NAMESPACE, "generic_json_technical_baseline@1.0.0"),
    "generic_json_technical_baseline", "1.0.0", GENERIC_JSON.profile_version_id,
    _rules_for(GENERIC_JSON.profile_version_id, RULES),
)


class RuleRegistry:
    def __init__(
        self,
        packs: tuple[RulePack, ...] = (RULE_PACK,),
        *,
        active_by_profile: Mapping[str, object] | None = None,
    ) -> None:
        self._packs = {}
        self._logical_versions: dict[tuple[str, str], RulePack] = {}
        profile_versions: dict[str, list[RulePack]] = {}
        for pack in packs:
            self._validate(pack)
            existing = self._packs.get(pack.rule_pack_version_id)
            logical = self._logical_versions.get((pack.name, pack.version))
            if (existing is not None and existing != pack) or (logical is not None and logical != pack):
                raise RuleRegistryError("Rule pack version content conflicts")
            self._packs[pack.rule_pack_version_id] = pack
            self._logical_versions[(pack.name, pack.version)] = pack
            profile_versions.setdefault(pack.profile_version_id, []).append(pack)
        active: dict[str, RulePack] = {}
        for profile_version_id, candidates in profile_versions.items():
            configured = (
                active_by_profile.get(profile_version_id)
                if active_by_profile is not None else None
            )
            if configured is None and len(candidates) == 1:
                active[profile_version_id] = candidates[0]
                continue
            selected = self._packs.get(configured)
            if selected is None or selected.profile_version_id != profile_version_id:
                raise RuleRegistryError("Active rule pack binding is invalid")
            active[profile_version_id] = selected
        self._by_profile = MappingProxyType(active)

    def get(self, version_id):
        try:
            return self._packs[version_id]
        except KeyError as exc:
            raise RuleRegistryError("Rule pack version is unavailable") from exc

    def for_profile(self, profile_version_id: str) -> RulePack | None:
        return self._by_profile.get(profile_version_id)

    @staticmethod
    def _validate(pack: RulePack) -> None:
        if not pack.name.strip() or not pack.version.strip() or not pack.rules:
            raise RuleRegistryError("Rule pack is malformed")
        ids = [rule.rule_id for rule in pack.rules]
        if len(ids) != len(set(ids)) or any(not item.strip() for item in ids):
            raise RuleRegistryError("Rule pack has duplicate or malformed rule IDs")
        if (
            getattr(pack, "schema_version", None) != "1.0.0"
            or not getattr(pack, "profile_version_id", "").strip()
        ):
            raise RuleRegistryError("Rule pack is malformed")
        for rule in pack.rules:
            if len(rule.required_effective_states) != 1:
                raise RuleRegistryError("Only single-field rules are supported in Step 7.1")
            if rule.condition.get("operator") not in SUPPORTED_OPERATORS:
                raise RuleRegistryError("Rule pack uses an unsupported operator")
            minimum = rule.condition.get("minimum_exclusive")
            if minimum is not None and (
                rule.condition.get("operator") != "less_than_or_equal"
                or isinstance(minimum, bool)
                or not isinstance(minimum, (int, float))
            ):
                raise RuleRegistryError("Rule pack uses an invalid lower bound")
            if rule.condition.get("operator") == "enum_at_least" and (
                not isinstance(rule.condition.get("expected"), str)
                or not isinstance(rule.condition.get("order"), list)
                or rule.condition.get("expected") not in rule.condition.get("order", [])
                or any(not isinstance(item, str) for item in rule.condition.get("order", []))
            ):
                raise RuleRegistryError("Rule pack uses an invalid ordered enum")
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


RULE_REGISTRY = RuleRegistry(
    (RULE_PACK_V1, RULE_PACK, FORTIOS_RULE_PACK_V1, FORTIOS_RULE_PACK, JUNOS_RULE_PACK_V1, JUNOS_RULE_PACK, ARISTA_RULE_PACK_V1, ARISTA_RULE_PACK, GENERIC_RULE_PACK_V1, GENERIC_RULE_PACK, GENERIC_XML_RULE_PACK, GENERIC_JSON_RULE_PACK),
    active_by_profile={
        CISCO_IOS_XE_17.profile_version_id: RULE_PACK.rule_pack_version_id,
        FORTIOS_7.profile_version_id: FORTIOS_RULE_PACK.rule_pack_version_id,
        JUNIPER_JUNOS_18.profile_version_id: JUNOS_RULE_PACK.rule_pack_version_id,
        ARISTA_EOS_4.profile_version_id: ARISTA_RULE_PACK.rule_pack_version_id,
        GENERIC_CLI.profile_version_id: GENERIC_RULE_PACK.rule_pack_version_id,
        GENERIC_XML.profile_version_id: GENERIC_XML_RULE_PACK.rule_pack_version_id,
        GENERIC_JSON.profile_version_id: GENERIC_JSON_RULE_PACK.rule_pack_version_id,
    },
)


RULE_PACK_BY_PROFILE = MappingProxyType({
    profile_version_id: RULE_REGISTRY.for_profile(profile_version_id)
    for profile_version_id in (
        CISCO_IOS_XE_17.profile_version_id,
        FORTIOS_7.profile_version_id,
        JUNIPER_JUNOS_18.profile_version_id,
        ARISTA_EOS_4.profile_version_id,
        GENERIC_CLI.profile_version_id,
        GENERIC_XML.profile_version_id,
        GENERIC_JSON.profile_version_id,
    )
})
