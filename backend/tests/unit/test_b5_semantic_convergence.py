from types import SimpleNamespace
from uuid import UUID

from app.effective_state.resolver import resolve_security_facts
from app.interpretation.models import InterpretationContext
from app.interpretation.service import interpret_structural_ir, interpret_xml_structural_ir
from app.knowledge_packs.cisco_iosxe_17 import CISCO_IOS_XE_17_KNOWLEDGE_PACK
from app.knowledge_packs.fortios_7 import FORTIOS_7_KNOWLEDGE_PACK
from app.knowledge_packs.juniper_junos_18 import JUNIPER_JUNOS_18_KNOWLEDGE_PACK
from app.parsing import ArtifactProvenance, parse_configuration_text
from app.parsing.readers import FORTIOS_CLI_READER_ID, INDENTATION_CLI_READER_ID
from app.parsing.models import StructuralParseRequest
from app.parsing.readers.xml_tree import XmlTreeReader


SOURCE = ArtifactProvenance(UUID(int=81), UUID(int=82), UUID(int=83), "b5-convergence", "a" * 64, {})
CONTEXT = InterpretationContext(UUID(int=84), UUID(int=85), UUID(int=83))


def _values(facts, field_id):
    return [item.value.value for item in facts if item.field_id == field_id]


def _states(facts):
    return resolve_security_facts(
        audit_id=CONTEXT.audit_id, device_id=CONTEXT.device_id,
        facts=[SimpleNamespace(
            fact_id=item.fact_id, audit_id=item.audit_id, device_id=item.device_id,
            field_id=item.field_id, value=item.value.to_dict(), scope=item.scope.to_dict(),
            evidence_refs=[reference.to_dict() for reference in item.evidence_refs], dependencies=[],
            knowledge_pack_version_id=item.knowledge_pack_version_id, mapping_version_id=item.mapping_version_id,
        ) for item in facts],
    )


def test_cisco_fortios_and_junos_converge_on_shared_canonical_semantics():
    cisco = interpret_structural_ir(
        parse_configuration_text("""line vty 0 4
 transport input ssh
 exec-timeout 10 0
!
logging host logs.example.invalid
ntp server time.example.invalid
""", source=SOURCE, reader_id=INDENTATION_CLI_READER_ID),
        CONTEXT, profile_version_id="cisco.ios_xe.17@1.0.0", knowledge_pack=CISCO_IOS_XE_17_KNOWLEDGE_PACK,
    ).facts
    fortios = interpret_structural_ir(
        parse_configuration_text("""config system interface
 edit \"port1\"
  set allowaccess ssh
 next
end
config system global
 set admintimeout 10
end
config log syslogd setting
 set server \"logs.example.invalid\"
end
config ntpserver
 edit 1
  set server \"time.example.invalid\"
 next
end
""", source=SOURCE, reader_id=FORTIOS_CLI_READER_ID),
        CONTEXT, profile_version_id="fortinet.fortios.7@1.0.0", knowledge_pack=FORTIOS_7_KNOWLEDGE_PACK,
    ).facts
    junos = interpret_xml_structural_ir(
        XmlTreeReader().parse(StructuralParseRequest(
            "<configuration><system><services><ssh/></services><syslog><host><name>logs.example.invalid</name></host></syslog><ntp><server><name>time.example.invalid</name></server></ntp></system></configuration>",
            SOURCE,
        )), CONTEXT, profile_version_id="juniper.junos.18@1.0.0", knowledge_pack=JUNIPER_JUNOS_18_KNOWLEDGE_PACK,
    ).facts

    for facts in (cisco, fortios, junos):
        assert _values(facts, "management.remote.ssh.enabled") == [True]
        assert _values(facts, "logging.remote.destination") == ["logs.example.invalid"]
        assert _values(facts, "time.ntp.server") == ["time.example.invalid"]
        assert all(
            item.mapping_id is not None and item.mapping_version_id is not None
            and item.evidence_refs and item.evidence_refs[0].source_path == "b5-convergence"
            and item.evidence_refs[0].start_line >= 1
            for item in facts
        )
    assert _values(cisco, "management.session.idle_timeout") == _values(fortios, "management.session.idle_timeout") == [600]
    assert [len(_states(facts)) for facts in (cisco, fortios, junos)] == [6, 7, 4]
