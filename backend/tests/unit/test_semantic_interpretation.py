from pathlib import Path
from uuid import UUID

from app.db.models import (
    FactState,
    FactValidationStatus,
    InterpretationConfidence,
    InterpretationMethod,
)
from app.interpretation import InterpretationContext, interpret_structural_ir
from app.parsing import (
    INDENTATION_CLI_READER_ID,
    ArtifactProvenance,
    parse_configuration_text,
)
from app.profile_resolution import CISCO_IOS_XE_17
from app.security_model import TypedValueType


FIXTURE = (
    Path(__file__).parents[1]
    / "fixtures"
    / "cisco_ios_xe"
    / "semantic.cfg"
)
AUDIT_ID = UUID(int=501)
DEVICE_ID = UUID(int=502)
SNAPSHOT_ID = UUID(int=503)
ARTIFACT_ID = UUID(int=504)


def _interpret(content: str):
    ir = parse_configuration_text(
        content,
        source=ArtifactProvenance(
            artifact_id=ARTIFACT_ID,
            organization_id=UUID(int=505),
            snapshot_id=SNAPSHOT_ID,
            source_label="semantic.cfg",
            sha256="a" * 64,
            source_metadata={"ingestion": "test"},
        ),
        reader_id=INDENTATION_CLI_READER_ID,
    )
    result = interpret_structural_ir(
        ir,
        InterpretationContext(AUDIT_ID, DEVICE_ID, SNAPSHOT_ID),
        profile_version_id=CISCO_IOS_XE_17.profile_version_id,
    )
    return ir, result


def _facts(result, field_id: str):
    return [fact for fact in result.facts if fact.field_id == field_id]


def test_semantic_fixture_produces_only_bounded_explicit_meaning():
    ir, result = _interpret(FIXTURE.read_text(encoding="utf-8"))

    telnet = _facts(result, "management.remote.telnet.enabled")
    ssh = _facts(result, "management.remote.ssh.enabled")
    timeouts = _facts(result, "management.session.idle_timeout")
    ssh_version = _facts(result, "management.remote.ssh.version")
    logging = _facts(result, "logging.remote.destination")
    ntp = _facts(result, "time.ntp.server")

    assert [(item.scope.key, item.value.value) for item in telnet] == [("vty:0-4", True)]
    assert [(item.scope.key, item.value.value) for item in ssh] == [
        ("vty:0-4", True), ("vty:5-15", True)
    ]
    assert [(item.scope.key, item.value.value) for item in timeouts] == [
        ("vty:0-4", 600), ("vty:5-15", 330)
    ]
    assert [item.value.original_value for item in timeouts] == ["10 0", "5 30"]
    assert all(item.value.unit == "seconds" for item in timeouts)
    assert all(item.value.original_unit == "minutes_seconds" for item in timeouts)
    assert len(ssh_version) == 1 and ssh_version[0].value.value == 2
    assert [item.value.value for item in logging] == [
        "192.0.2.10", "logs.example.invalid"
    ]
    assert [item.value.type for item in logging] == [
        TypedValueType.IP_ADDRESS, TypedValueType.STRING
    ]
    assert len(ntp) == 1 and ntp[0].value.value == "192.0.2.20"
    assert len(result.facts) == 9
    assert result.metrics.facts_produced == 9
    assert result.metrics.nodes_matched == 8
    assert "invalid_exec_timeout" in {item.code for item in result.diagnostics}
    assert "unsupported_negation" in {item.code for item in result.diagnostics}
    assert "unsupported_vty_scope" in {item.code for item in result.diagnostics}
    assert all("203.0.113.20" not in str(fact.value.value) for fact in result.facts)
    assert all(fact.field_id in {
        "management.remote.telnet.enabled",
        "management.remote.ssh.enabled",
        "management.remote.ssh.version",
        "management.session.idle_timeout",
        "logging.remote.destination",
        "time.ntp.server",
    } for fact in result.facts)
    assert not hasattr(result, "effective_state")
    assert not hasattr(result, "findings")
    assert all(ir.node(node_id) for fact in result.facts for node_id in fact.source_ir_node_ids)


def test_transport_variants_do_not_fabricate_absent_protocol_meaning():
    _ir, ssh_only = _interpret("line vty 0 4\n transport input ssh\n")
    assert _facts(ssh_only, "management.remote.telnet.enabled") == []
    assert [fact.value.value for fact in _facts(
        ssh_only, "management.remote.ssh.enabled"
    )] == [True]

    _ir, none = _interpret("line vty 7\n transport input none\n")
    assert [(fact.field_id, fact.value.value, fact.scope.to_dict()) for fact in none.facts] == [
        (
            "management.remote.telnet.enabled", False,
            {"type": "vty_range", "key": "vty:7-7", "attributes": {"start": 7, "end": 7}},
        ),
        (
            "management.remote.ssh.enabled", False,
            {"type": "vty_range", "key": "vty:7-7", "attributes": {"start": 7, "end": 7}},
        ),
    ]

    _ir, malformed = _interpret(
        "line vty 0 4\n transport input ssh ssh\n transport input telnet ssh telnet\n"
    )
    assert malformed.facts == ()
    assert {item.code for item in malformed.diagnostics} == {
        "unsupported_transport_input"
    }


def test_invalid_extractors_negation_and_unknown_nodes_produce_no_fabricated_facts():
    _ir, result = _interpret(
        "ip ssh version three\n"
        "logging host bad destination\n"
        "ntp server ???\n"
        "line vty 0 4\n"
        " exec-timeout ten 0\n"
        " no transport input telnet\n"
        " default exec-timeout\n"
        "unknown command value\n"
    )
    assert result.facts == ()
    assert result.metrics.facts_produced == 0
    assert result.metrics.unsupported_cases >= 4


def test_fact_identity_and_full_provenance_are_stable():
    ir, first = _interpret("line vty 0 4\n exec-timeout 10 0\n")
    _second_ir, second = _interpret("line vty 0 4\n exec-timeout 10 0\n")
    fact = first.facts[0]
    producer = next(node for node in ir.nodes if node.command == "exec-timeout")
    context = next(node for node in ir.nodes if node.command == "line")

    assert fact.fact_id == second.facts[0].fact_id
    assert fact.audit_id == AUDIT_ID
    assert fact.device_id == DEVICE_ID
    assert fact.snapshot_id == SNAPSHOT_ID
    assert fact.source_ir_node_ids == (producer.node_id, context.node_id)
    assert [item.ir_node_id for item in fact.evidence_refs] == [
        producer.node_id, context.node_id
    ]
    assert fact.evidence_refs[0].artifact_id == ARTIFACT_ID
    assert fact.evidence_refs[0].start_line == fact.evidence_refs[0].end_line == 2
    assert fact.evidence_refs[0].source_path == "semantic.cfg"
    assert fact.mapping_id is not None and fact.mapping_version_id is not None
    assert fact.knowledge_pack_version_id == UUID("dbad6d61-97d6-5e42-a1aa-feb4e28e15b0")
    assert fact.state == FactState.EXPLICIT
    assert fact.extraction_method == InterpretationMethod.DECLARATIVE_MAPPING
    assert fact.validation_status == FactValidationStatus.VALIDATED
    assert fact.interpretation_confidence == InterpretationConfidence.HIGH
    assert fact.dependencies == ()
    assert "running" not in fact.scope.type


def test_repeated_destinations_remain_independent():
    _ir, result = _interpret(
        "logging host 192.0.2.1\nlogging host 192.0.2.1\nntp server time.example.invalid\n"
    )
    logging = _facts(result, "logging.remote.destination")
    assert len(logging) == 2
    assert logging[0].fact_id != logging[1].fact_id
    assert _facts(result, "time.ntp.server")[0].value.value == "time.example.invalid"


def test_recognized_negation_is_preserved_without_inventing_a_default():
    _ir, result = _interpret(
        "no ip ssh version\n"
        "no logging host 192.0.2.10\n"
        "no ntp server time.example.invalid\n"
        "line vty 0 4\n"
        " no exec-timeout\n"
        " no transport input\n"
    )

    reset_facts = [
        item for item in result.facts if item.value.type is TypedValueType.NULL
    ]
    assert {item.field_id for item in reset_facts} == {
        "management.remote.ssh.version",
        "management.session.idle_timeout",
        "management.remote.telnet.enabled",
        "management.remote.ssh.enabled",
    }
    assert all(item.value.value is None for item in reset_facts)
    assert all(item.state is FactState.UNKNOWN for item in reset_facts)
    assert all(item.validation_status is FactValidationStatus.UNRESOLVED for item in reset_facts)
    assert all(item.interpretation_confidence is InterpretationConfidence.UNRESOLVED for item in reset_facts)
    assert [item.value.value for item in _facts(result, "logging.remote.destination")] == ["192.0.2.10"]
    assert [item.value.value for item in _facts(result, "time.ntp.server")] == ["time.example.invalid"]


def test_unsupported_negation_is_not_fabricated_as_a_known_event():
    _ir, result = _interpret("line vty 0 4\n no transport input telnet\n")
    assert result.facts == ()
    assert {item.code for item in result.diagnostics} == {"unsupported_negation"}
