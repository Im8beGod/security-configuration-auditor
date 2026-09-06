from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.db.models import (
    Artifact,
    ArtifactContentFamily,
    ArtifactEvidenceType,
    ArtifactStatus,
    JobType,
)
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.jobs.runner import PRODUCTION_HANDLERS
from app.parsing import (
    INDENTATION_CLI_READER_ID,
    ArtifactNotParseableError,
    ArtifactProvenance,
    ConfigNodeKind,
    ParseStatus,
    parse_artifact,
    parse_configuration_text,
)
from app.parsing.readers import indentation_cli
from app.profile_resolution import CISCO_IOS_XE_17


FIXTURE = (
    Path(__file__).parents[1]
    / "fixtures"
    / "cisco_ios_xe"
    / "representative.cfg"
)


def _source(*, source_label: str = "running-config.txt") -> ArtifactProvenance:
    return ArtifactProvenance(
        artifact_id=UUID(int=101),
        organization_id=UUID(int=102),
        snapshot_id=UUID(int=103),
        source_label=source_label,
        sha256="a" * 64,
        source_metadata={"ingestion": "test_fixture"},
    )


def _parse(content: str, *, source: ArtifactProvenance | None = None):
    return parse_configuration_text(
        content,
        source=source or _source(),
        reader_id=INDENTATION_CLI_READER_ID,
    )


def _statement(ir, raw_text: str):
    return next(
        node for node in ir.nodes
        if node.kind == ConfigNodeKind.STATEMENT and node.raw_text.strip() == raw_text
    )


def test_representative_fixture_preserves_top_level_commands_and_unknown_syntax():
    ir = _parse(FIXTURE.read_text(encoding="utf-8"))

    hostname = _statement(ir, "hostname router01")
    unknown = _statement(ir, "platform mystery-mode enabled")
    assert hostname.parent_id is None and hostname.depth == 0
    assert hostname.command == "hostname" and hostname.arguments == ("router01",)
    assert unknown.command == "platform"
    assert unknown.arguments == ("mystery-mode", "enabled")
    assert unknown.parse_status == ParseStatus.PARSED


def test_one_level_hierarchy_parent_ids_children_order_and_raw_text():
    ir = _parse(
        "line vty 0 4\n"
        " exec-timeout 10 0\n"
        " transport input ssh\n"
    )
    parent = _statement(ir, "line vty 0 4")
    timeout = _statement(ir, "exec-timeout 10 0")
    transport = _statement(ir, "transport input ssh")

    assert parent.children == (timeout.node_id, transport.node_id)
    assert timeout.parent_id == transport.parent_id == parent.node_id
    assert timeout.depth == transport.depth == 1
    assert [parent.order, timeout.order, transport.order] == [1, 2, 3]
    assert timeout.raw_text == " exec-timeout 10 0"
    assert timeout.command == "exec-timeout"
    assert timeout.arguments == ("10", "0")
    assert timeout.context_path == (parent.node_id,)


def test_multilevel_policy_hierarchy_is_structural_only():
    ir = _parse("policy-map WAN-QOS\n class VOICE\n  priority percent 20\n")
    policy = _statement(ir, "policy-map WAN-QOS")
    class_node = _statement(ir, "class VOICE")
    priority = _statement(ir, "priority percent 20")

    assert class_node.parent_id == policy.node_id
    assert priority.parent_id == class_node.node_id
    assert priority.context_path == (policy.node_id, class_node.node_id)
    assert priority.depth == 2
    assert not hasattr(ir, "security_facts")
    assert not hasattr(ir, "effective_state")
    assert not hasattr(ir, "findings")


def test_repeated_contexts_remain_distinct_and_in_source_order():
    ir = _parse(
        "interface GigabitEthernet1\n description First\n"
        "interface GigabitEthernet1\n description Second\n"
    )
    interfaces = [node for node in ir.nodes if node.command == "interface"]
    assert len(interfaces) == 2
    assert interfaces[0].node_id != interfaces[1].node_id
    assert interfaces[0].order < interfaces[1].order
    assert len(interfaces[0].children) == len(interfaces[1].children) == 1


def test_source_lines_are_one_based_and_ids_are_deterministic():
    content = "\nhostname router01\nline vty 0 4\n transport input ssh\n"
    first = _parse(content)
    second = _parse(content)
    hostname = _statement(first, "hostname router01")
    transport = _statement(first, "transport input ssh")

    assert hostname.source_start == hostname.source_end == 2
    assert transport.source_start == transport.source_end == 4
    assert [node.node_id for node in first.nodes] == [node.node_id for node in second.nodes]
    changed_source = _parse(content, source=_source(source_label="copy.cfg"))
    assert [node.node_id for node in first.nodes] == [
        node.node_id for node in changed_source.nodes
    ]


def test_negation_is_structural_and_inactive_defaults_false():
    ir = _parse("no ip http server\n no transport input telnet\ndefault interface Gi1\n")
    http = _statement(ir, "no ip http server")
    transport = _statement(ir, "no transport input telnet")
    default = _statement(ir, "default interface Gi1")

    assert http.command == "ip" and http.arguments == ("http", "server")
    assert transport.command == "transport"
    assert transport.arguments == ("input", "telnet")
    assert http.negated and transport.negated
    assert not default.negated
    assert all(not node.inactive for node in ir.nodes)


def test_comments_and_blank_lines_are_preserved_without_becoming_commands():
    ir = _parse("! section separator\n\n hostname indented-after-comment\n!")
    comments = [node for node in ir.nodes if node.kind == ConfigNodeKind.COMMENT]
    statement = _statement(ir, "hostname indented-after-comment")

    assert len(comments) == 2
    assert comments[0].command is None
    assert comments[0].comments == ("section separator",)
    assert statement.order == 2
    assert statement.parent_id is None
    assert statement.parse_status == ParseStatus.PARTIAL


def test_banner_body_cannot_inject_configuration_nodes():
    content = (
        "banner motd ^C\n"
        "line vty 0 4\n"
        " transport input telnet\n"
        "^C\n"
        "hostname real-router\n"
    )
    ir = _parse(content)
    banner = next(node for node in ir.nodes if node.kind == ConfigNodeKind.OPAQUE)

    assert banner.command == "banner"
    assert banner.source_start == 1 and banner.source_end == 4
    assert banner.parse_status == ParseStatus.OPAQUE
    assert "transport input telnet" in banner.raw_text
    assert [node.command for node in ir.nodes if node.kind == ConfigNodeKind.STATEMENT] == [
        "hostname"
    ]


def test_inline_and_unterminated_banners_are_controlled():
    inline = _parse("banner login #Authorized users only#\nhostname after-inline\n")
    unterminated = _parse(
        "banner motd ^C\nline vty 0 4\ntransport input telnet\n"
    )

    assert inline.nodes[0].kind == ConfigNodeKind.OPAQUE
    assert inline.nodes[0].parse_status == ParseStatus.OPAQUE
    assert _statement(inline, "hostname after-inline").source_start == 2
    assert len(unterminated.nodes) == 1
    assert unterminated.nodes[0].parse_status == ParseStatus.PARTIAL
    assert {item.code for item in unterminated.diagnostics} == {"unterminated_banner"}


def test_malformed_banner_fails_closed_over_remaining_command_like_text():
    ir = _parse("banner motd\nline vty 0 4\ntransport input telnet\n")
    assert len(ir.nodes) == 1
    assert ir.nodes[0].kind == ConfigNodeKind.OPAQUE
    assert ir.nodes[0].parse_status == ParseStatus.PARTIAL
    assert "transport input telnet" in ir.nodes[0].raw_text
    assert "unterminated_banner" in {item.code for item in ir.diagnostics}


def test_opaque_block_scan_limit_stops_parsing_fail_closed(monkeypatch):
    monkeypatch.setattr(indentation_cli, "MAX_OPAQUE_BLOCK_LINES", 2)
    ir = _parse(
        "banner motd ^C\nbody\nline vty 0 4\ntransport input telnet\n^C\nhostname hidden\n"
    )
    assert len(ir.nodes) == 1
    assert ir.nodes[0].kind == ConfigNodeKind.OPAQUE
    assert ir.nodes[0].parse_status == ParseStatus.PARTIAL
    assert ir.truncated
    assert {item.code for item in ir.diagnostics} == {
        "opaque_block_limit", "unterminated_banner"
    }


def test_certificate_material_is_opaque_and_cannot_inject_commands():
    ir = _parse(
        "crypto pki certificate chain TEST\n"
        " certificate self-signed 01\n"
        "  30820000SANITIZED\n"
        "  line vty 0 4\n"
        "  transport input telnet\n"
        "  quit\n"
        "hostname real-router\n"
    )
    opaque = ir.nodes[0]
    assert opaque.kind == ConfigNodeKind.OPAQUE
    assert opaque.source_start == 1 and opaque.source_end == 6
    assert opaque.parse_status == ParseStatus.OPAQUE
    assert [node.command for node in ir.nodes[1:]] == ["hostname"]


def test_mixed_indentation_does_not_crash_and_is_marked_partial():
    ir = _parse("policy-map TEST\n \tclass MIXED\n  priority percent 10\n")
    mixed = _statement(ir, "class MIXED")
    assert mixed.parse_status == ParseStatus.PARTIAL
    assert "mixed_indentation" in {item.code for item in ir.diagnostics}


def test_unmatched_dedent_is_preserved_with_explicit_uncertainty():
    ir = _parse("policy-map TEST\n    class VOICE\n  priority percent 10\n")
    priority = _statement(ir, "priority percent 10")
    policy = _statement(ir, "policy-map TEST")
    assert priority.parent_id == policy.node_id
    assert priority.parse_status == ParseStatus.PARTIAL
    assert "inconsistent_dedent" in {item.code for item in ir.diagnostics}


def test_pathological_depth_is_bounded_iteratively():
    content = "\n".join(
        f"{' ' * depth}command-{depth}" for depth in range(100)
    )
    ir = _parse(content)
    assert max(node.depth for node in ir.nodes) <= indentation_cli.MAX_DEPTH
    assert "maximum_depth_reached" in {item.code for item in ir.diagnostics}


def test_node_and_input_limits_are_controlled(monkeypatch):
    monkeypatch.setattr(indentation_cli, "MAX_NODE_COUNT", 5)
    node_limited = _parse("\n".join(f"command-{item}" for item in range(20)))
    assert len(node_limited.nodes) == 5
    assert node_limited.truncated
    assert "node_limit" in {item.code for item in node_limited.diagnostics}

    monkeypatch.setattr(indentation_cli, "MAX_INPUT_CHARACTERS", 20)
    input_limited = _parse("hostname router01\ninterface GigabitEthernet1\n")
    assert input_limited.truncated
    assert "input_limit" in {item.code for item in input_limited.diagnostics}


def test_long_line_and_empty_input_are_safe(monkeypatch):
    monkeypatch.setattr(indentation_cli, "MAX_LINE_CHARACTERS", 16)
    long_line = _parse("description " + "x" * 100)
    empty = _parse("")

    assert len(long_line.nodes[0].raw_text) == 16
    assert long_line.nodes[0].parse_status == ParseStatus.PARTIAL
    assert long_line.truncated
    assert empty.nodes == () and empty.root_node_ids == ()
    assert not empty.truncated and empty.diagnostics == ()


def test_artifact_service_uses_storage_and_preserves_safe_provenance(tmp_path):
    storage = LocalFilesystemArtifactStorage(tmp_path / "protected" / "artifacts")
    organization_id, snapshot_id, artifact_id = uuid4(), uuid4(), uuid4()
    content = b"hostname stored-router\n"
    reference = storage.write(
        content, organization_id=organization_id, artifact_id=artifact_id
    )
    artifact = Artifact(
        artifact_id=artifact_id,
        organization_id=organization_id,
        snapshot_id=snapshot_id,
        original_filename="running-config.cfg",
        storage_reference=reference,
        byte_size=len(content),
        sha256=sha256(content).hexdigest(),
        encoding="utf-8",
        content_family=ArtifactContentFamily.TEXT,
        evidence_type=ArtifactEvidenceType.CONFIGURATION,
        status=ArtifactStatus.READY,
        source_metadata={"ingestion": "authenticated_upload"},
    )

    ir = parse_artifact(
        storage,
        artifact,
        profile_version_id=CISCO_IOS_XE_17.profile_version_id,
        organization_id=organization_id,
    )
    assert ir.source.artifact_id == artifact_id
    assert ir.source.snapshot_id == snapshot_id
    assert ir.source.source_label == "running-config.cfg"
    assert ir.nodes[0].artifact_id == artifact_id
    assert ir.nodes[0].source_label == "running-config.cfg"
    assert str(tmp_path) not in repr(ir)
    assert reference not in repr(ir)

    with pytest.raises(ArtifactNotParseableError):
        parse_artifact(
            storage,
            artifact,
            profile_version_id=CISCO_IOS_XE_17.profile_version_id,
            organization_id=uuid4(),
        )

    artifact.status = ArtifactStatus.REJECTED
    with pytest.raises(ArtifactNotParseableError):
        parse_artifact(
            storage,
            artifact,
            profile_version_id=CISCO_IOS_XE_17.profile_version_id,
            organization_id=organization_id,
        )


def test_profile_references_reader_and_production_audit_jobs_remain_unclaimed():
    assert CISCO_IOS_XE_17.structural_reader_name == INDENTATION_CLI_READER_ID
    assert "structural_parsing" in CISCO_IOS_XE_17.capabilities
    assert CISCO_IOS_XE_17.coverage_manifest["structural_parsing"] is True
    assert JobType.AUDIT not in PRODUCTION_HANDLERS
