from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from app.compliance.evaluator import evaluate_condition
from app.compliance.rule_registry import FORTIOS_RULE_PACK, RULE_PACK
from app.compliance.verdicts import FindingVerdict
from app.effective_state.resolver import resolve_security_facts
from app.interpretation.models import InterpretationContext
from app.interpretation.service import (
    interpret_structural_ir,
    load_validated_knowledge_pack,
    load_validated_knowledge_pack_by_version,
)
from app.knowledge_packs.cisco_iosxe_17 import CISCO_IOS_XE_17_KNOWLEDGE_PACK
from app.knowledge_packs.fortios_7 import (
    FORTIOS_7_KNOWLEDGE_PACK,
    FORTIOS_7_KNOWLEDGE_PACK_V1,
)
from app.parsing import ArtifactProvenance, parse_configuration_text
from app.parsing.readers import FORTIOS_CLI_READER_ID, INDENTATION_CLI_READER_ID
from app.profile_resolution import FORTIOS_7


ROOT = Path(__file__).parents[1] / "fixtures" / "fortios"
SOURCE = ArtifactProvenance(
    artifact_id=UUID(int=1), organization_id=UUID(int=2), snapshot_id=UUID(int=3),
    source_label="fortios.conf", sha256="a" * 64, source_metadata={},
)
CONTEXT = InterpretationContext(UUID(int=10), UUID(int=11), UUID(int=3))


def _ir(text, reader_id=FORTIOS_CLI_READER_ID):
    return parse_configuration_text(text, source=SOURCE, reader_id=reader_id)


def _facts(text, pack=FORTIOS_7_KNOWLEDGE_PACK):
    return interpret_structural_ir(_ir(text), CONTEXT, profile_version_id=FORTIOS_7.profile_version_id, knowledge_pack=pack).facts


def test_fortios_reader_preserves_config_edit_scope_and_unset():
    ir = _ir("config ntpserver\n edit 1\n  set server \"192.0.2.20\"\n next\nend\n")
    nodes = {node.command: node for node in ir.nodes if node.command in {"config", "edit", "set", "next", "end"}}
    assert nodes["set"].parent_id == nodes["edit"].node_id
    assert nodes["edit"].parent_id == nodes["config"].node_id
    assert nodes["set"].source_start == 3
    unset = _ir("config system global\n unset admin-telnet-port\nend\n")
    unset_node = next(node for node in unset.nodes if node.command == "unset")
    assert unset_node.negated is True
    assert unset_node.parent_id is not None


def test_fortios_pack_is_immutable_and_profile_compatible():
    assert load_validated_knowledge_pack(FORTIOS_7.profile_version_id) is FORTIOS_7_KNOWLEDGE_PACK
    assert load_validated_knowledge_pack_by_version(
        FORTIOS_7_KNOWLEDGE_PACK.knowledge_pack_version_id
    ) is FORTIOS_7_KNOWLEDGE_PACK
    assert load_validated_knowledge_pack_by_version(
        FORTIOS_7_KNOWLEDGE_PACK_V1.knowledge_pack_version_id
    ) is FORTIOS_7_KNOWLEDGE_PACK_V1


def test_fortios_fixture_maps_canonical_fields_and_preserves_evidence():
    facts = _facts((ROOT / "secure.conf").read_text())
    values = {(fact.field_id, fact.value.value) for fact in facts}
    assert ("management.remote.ssh.enabled", True) in values
    assert ("management.remote.telnet.enabled", False) in values
    assert ("management.remote.https.enabled", True) in values
    assert ("management.remote.tls.minimum_version", "tlsv1-2") in values
    assert ("management.remote.source.restriction.configured", True) in values
    assert ("management.remote.source.permitted_network", "192.0.2.0/24") in values
    assert ("logging.enabled", True) in values
    assert ("management.session.idle_timeout", 600) in values
    assert ("logging.remote.destination", "192.0.2.10") in values
    assert ("time.ntp.server", "192.0.2.20") in values
    assert all(fact.knowledge_pack_version_id == FORTIOS_7_KNOWLEDGE_PACK.knowledge_pack_version_id for fact in facts)
    assert all(fact.evidence_refs and fact.evidence_refs[0].source_path == "fortios.conf" for fact in facts)


def test_fortios_disabled_fixture_explicitly_disables_both_protocols():
    facts = _facts((ROOT / "insecure.conf").read_text())
    values = {(fact.field_id, fact.value.value) for fact in facts}
    assert ("management.remote.ssh.enabled", False) in values
    assert ("management.remote.telnet.enabled", False) in values
    assert ("management.session.idle_timeout", 3600) in values


def test_fortios_telnet_enabled_fixture_preserves_ssh_disabled_evidence():
    facts = _facts((ROOT / "telnet_enabled.conf").read_text())
    values = {(fact.field_id, fact.value.value) for fact in facts}
    assert ("management.remote.telnet.enabled", True) in values
    assert ("management.remote.ssh.enabled", False) in values


def test_fortios_port_only_configuration_remains_unknown():
    result = interpret_structural_ir(
        _ir((ROOT / "unknown.conf").read_text()), CONTEXT,
        profile_version_id=FORTIOS_7.profile_version_id,
        knowledge_pack=FORTIOS_7_KNOWLEDGE_PACK,
    )
    assert not result.facts
    assert result.unresolved_node_ids
    assert result.metrics.unsupported_cases == 0


def test_fortios_incomplete_allowaccess_evidence_remains_unresolved():
    result = interpret_structural_ir(
        _ir((ROOT / "ambiguous.conf").read_text()), CONTEXT,
        profile_version_id=FORTIOS_7.profile_version_id,
        knowledge_pack=FORTIOS_7_KNOWLEDGE_PACK,
    )
    assert not result.facts
    assert "invalid_fortios_allowaccess" in {item.code for item in result.diagnostics}
    assert result.unresolved_node_ids


def test_fortios_unset_uses_existing_effective_state_reset_semantics():
    facts = _facts("config system interface\n edit \"port1\"\n  unset allowaccess\n next\nend\n")
    assert {fact.field_id for fact in facts} == {
        "management.remote.telnet.enabled",
        "management.remote.ssh.enabled",
        "management.remote.https.enabled",
    }
    assert all(fact.value.value is None for fact in facts)
    assert all(fact.validation_status.value == "unresolved" for fact in facts)


def test_fortios_facts_resolve_through_existing_effective_state_engine():
    facts = _facts((ROOT / "secure.conf").read_text())
    persisted = [SimpleNamespace(
        fact_id=item.fact_id, audit_id=item.audit_id, device_id=item.device_id,
        field_id=item.field_id, value=item.value.to_dict(), scope=item.scope.to_dict(),
        evidence_refs=[reference.to_dict() for reference in item.evidence_refs],
        dependencies=[], knowledge_pack_version_id=item.knowledge_pack_version_id,
        mapping_version_id=item.mapping_version_id,
    ) for item in facts]
    states = resolve_security_facts(
        audit_id=CONTEXT.audit_id, device_id=CONTEXT.device_id, facts=persisted
    )
    resolved = {state.field_id: state.effective_value.value for state in states if state.effective_value is not None}
    assert resolved["management.remote.ssh.enabled"] is True
    assert resolved["time.ntp.server"][0]["value"] == "192.0.2.20"


def test_fortios_management_facts_stay_in_their_interface_and_administrator_scopes():
    facts = _facts("""config system interface
 edit \"port1\"
  set allowaccess ssh https
 next
 edit \"port2\"
  set allowaccess telnet
 next
end
config system admin
 edit \"ops\"
  set trusthost1 198.51.100.0 255.255.255.0
 next
end
""")
    persisted = [SimpleNamespace(
        fact_id=item.fact_id, audit_id=item.audit_id, device_id=item.device_id,
        field_id=item.field_id, value=item.value.to_dict(), scope=item.scope.to_dict(),
        evidence_refs=[reference.to_dict() for reference in item.evidence_refs], dependencies=[],
        knowledge_pack_version_id=item.knowledge_pack_version_id, mapping_version_id=item.mapping_version_id,
    ) for item in facts]
    states = resolve_security_facts(audit_id=CONTEXT.audit_id, device_id=CONTEXT.device_id, facts=persisted)
    selected = {
        (item.field_id, item.scope.key, item.effective_value.value if item.effective_value else None)
        for item in states
        if item.field_id in {"management.remote.ssh.enabled", "management.remote.source.restriction.configured"}
    }
    assert selected >= {
        ("management.remote.ssh.enabled", "interface:port1", True),
        ("management.remote.ssh.enabled", "interface:port2", False),
        ("management.remote.source.restriction.configured", "administrator:ops", True),
    }


def test_cisco_and_fortios_equivalent_controls_share_canonical_compliance():
    cisco = """line vty 0 4
 transport input ssh
 exec-timeout 10 0
!
logging host 192.0.2.10
ntp server 192.0.2.20
"""
    fortios = (ROOT / "secure.conf").read_text()
    cisco_facts = interpret_structural_ir(
            parse_configuration_text(cisco, source=SOURCE, reader_id=INDENTATION_CLI_READER_ID),
        CONTEXT, profile_version_id="cisco.ios_xe.17@1.0.0", knowledge_pack=CISCO_IOS_XE_17_KNOWLEDGE_PACK,
    ).facts
    fortios_facts = _facts(fortios)
    def values(facts):
        return {field: sorted(str(item.value.value) for item in facts if item.field_id == field) for field in {
            "management.remote.ssh.enabled",
            "management.session.idle_timeout", "logging.remote.destination", "time.ntp.server",
        }}
    assert values(cisco_facts) == values(fortios_facts)
    for rule_id, field in (
        ("management.ssh.enabled", "management.remote.ssh.enabled"),
        ("management.idle_timeout.maximum", "management.session.idle_timeout"),
        ("logging.remote.destination.configured", "logging.remote.destination"),
        ("time.ntp.server.configured", "time.ntp.server"),
    ):
        def effective_value(facts):
            items = [item.value.to_dict() for item in facts if item.field_id == field]
            if field in {"logging.remote.destination", "time.ntp.server"}:
                return {"type": "list", "value": items, "unit": None, "original_value": None, "original_unit": None}
            return items[0]
        cisco_value = effective_value(cisco_facts)
        fortios_value = effective_value(fortios_facts)
        cisco_rule = next(rule for rule in RULE_PACK.rules if rule.rule_id == rule_id)
        fortios_rule = next(rule for rule in FORTIOS_RULE_PACK.rules if rule.rule_id == rule_id)
        assert cisco_rule.framework_references == fortios_rule.framework_references
        parameter = 900 if "idle_timeout" in rule_id else None
        assert evaluate_condition(cisco_rule, cisco_value, parameter) == evaluate_condition(fortios_rule, fortios_value, parameter)
