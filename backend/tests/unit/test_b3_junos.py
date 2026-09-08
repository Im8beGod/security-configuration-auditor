from hashlib import sha256
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from app.interpretation.models import InterpretationContext
from app.interpretation.service import interpret_xml_structural_ir
from app.knowledge_packs.juniper_junos_18 import JUNIPER_JUNOS_18_KNOWLEDGE_PACK
from app.db.models import Artifact, ArtifactContentFamily, ArtifactEvidenceType, ArtifactStatus
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.parsing.exceptions import ArtifactNotParseableError
from app.parsing.models import ArtifactProvenance, StructuralParseRequest
from app.parsing.readers.xml_tree import XmlTreeReader
from app.parsing.service import parse_artifact
from app.profile_resolution import CISCO_IOS_XE_17
from app.profile_resolution import ResolutionStatus, resolve_profile
from app.profile_resolution.evidence import EvidenceDocument, SnapshotEvidence
from app.db.models import ArtifactEvidenceType
from app.training.dsl import MappingDefinition, matches_xml, xml_match_has_unsupported_qualifier
from app.training.service import _validate_against_artifact


def _source():
    return ArtifactProvenance(UUID(int=1), UUID(int=2), UUID(int=3), "junos.xml", "a" * 64, {})


def _ir(text: str):
    return XmlTreeReader().parse(StructuralParseRequest(text, _source()))


def test_junos_profile_is_conservative_and_xml_pack_maps_reviewed_fields():
    evidence = EvidenceDocument(UUID(int=1), UUID(int=2), UUID(int=3), UUID(int=4), ArtifactEvidenceType.VERSION_OUTPUT, "version.txt", "a" * 64, {}, "JUNOS Software Release [18.4R1-S2.4]", 36, False)
    resolved = resolve_profile(SnapshotEvidence(UUID(int=3), UUID(int=2), UUID(int=4), (evidence,), (), 36))
    assert resolved.resolution_status is ResolutionStatus.RESOLVED
    assert resolved.selected_profile_version_id == "juniper.junos.18@1.0.0"
    ir = _ir("<configuration><system><services><ssh/></services><syslog><host><name>host111</name></host></syslog><ntp><server><name>66.129.233.81</name></server><server><name>192.0.2.10</name></server></ntp></system></configuration>")
    result = interpret_xml_structural_ir(ir, InterpretationContext(UUID(int=5), UUID(int=6), UUID(int=3)), profile_version_id="juniper.junos.18@1.0.0", knowledge_pack=JUNIPER_JUNOS_18_KNOWLEDGE_PACK)
    assert [(item.field_id, item.value.value) for item in result.facts] == [
        ("management.remote.ssh.enabled", True), ("logging.remote.destination", "host111"),
        ("time.ntp.server", "66.129.233.81"), ("time.ntp.server", "192.0.2.10"),
    ]


def test_manifest_selectors_resolve_junos_xml_identity_with_path_provenance():
    text = "<rpc-reply><configuration><version>18.4R1-S2.4</version><system><host-name>vsrx</host-name></system></configuration></rpc-reply>"
    document = EvidenceDocument(UUID(int=10), UUID(int=2), UUID(int=3), UUID(int=4), ArtifactEvidenceType.CONFIGURATION, "development-junos.xml", "b" * 64, {}, text, len(text), False)
    resolved = resolve_profile(SnapshotEvidence(UUID(int=3), UUID(int=2), UUID(int=4), (document,), (), len(text)))
    assert resolved.os_version == "18.4R1-S2.4"
    assert resolved.vendor == "Juniper"
    assert resolved.selected_profile_version_id == "juniper.junos.18@1.0.0"
    assert resolved.identity_provenance["os_version"][0]["artifact_id"] == str(document.artifact_id)
    assert resolved.identity_provenance["os_version"][0]["path"] == ["rpc-reply[1]", "configuration[1]", "version[1]"]
    assert resolved.identity_provenance["hostname"][0]["path"][-1] == "host-name[1]"


def test_generic_unknown_xml_does_not_gain_a_profile_from_manifest_selectors():
    text = "<rpc-reply><configuration><system><services><ssh/></services></system></configuration></rpc-reply>"
    document = EvidenceDocument(UUID(int=11), UUID(int=2), UUID(int=3), UUID(int=4), ArtifactEvidenceType.CONFIGURATION, "unknown.xml", "c" * 64, {}, text, len(text), False)
    resolved = resolve_profile(SnapshotEvidence(UUID(int=3), UUID(int=2), UUID(int=4), (document,), (), len(text)))
    assert resolved.resolution_status is ResolutionStatus.UNRESOLVED
    assert resolved.selected_profile_version_id is None


def test_manifest_routes_structured_xml_only_to_declared_reader(tmp_path):
    organization_id, snapshot_id, artifact_id = UUID(int=20), UUID(int=21), UUID(int=22)
    content = b"<rpc-reply><configuration><version>18.4R1-S2.4</version></configuration></rpc-reply>"
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    reference = storage.write(content, organization_id=organization_id, artifact_id=artifact_id)
    artifact = Artifact(
        artifact_id=artifact_id,
        organization_id=organization_id,
        snapshot_id=snapshot_id,
        original_filename="parsed.cfg",
        storage_reference=reference,
        byte_size=len(content),
        sha256=sha256(content).hexdigest(),
        encoding="utf-8",
        content_family=ArtifactContentFamily.XML,
        evidence_type=ArtifactEvidenceType.STRUCTURED_EXPORT,
        status=ArtifactStatus.READY,
    )

    ir = parse_artifact(
        storage,
        artifact,
        profile_version_id="juniper.junos.18@1.0.0",
        organization_id=organization_id,
    )
    assert ir.reader_id == "xml_tree.v1"
    assert ir.source.artifact_id == artifact_id
    with pytest.raises(ArtifactNotParseableError, match="incompatible"):
        parse_artifact(
            storage,
            artifact,
            profile_version_id=CISCO_IOS_XE_17.profile_version_id,
            organization_id=organization_id,
        )


def test_xml_path_namespace_uri_ignores_prefix_and_wrong_path_does_not_match():
    payload = {
        "profile_applicability": {"profile_version_ids": ["juniper.junos.18@1.0.0"]},
        "structural_match": {"operation": "xml_path", "command": "xml", "xml_path": {"path": [{"local_name": "configuration", "namespace_uri": "urn:junos"}, {"local_name": "system", "namespace_uri": "urn:junos"}, {"local_name": "services", "namespace_uri": "urn:junos"}, {"local_name": "ssh", "namespace_uri": "urn:junos"}], "source": "presence", "start_mode": "document_root"}},
        "target_field_id": "management.remote.ssh.enabled", "value_extraction": {"operation": "boolean_from_presence", "output_type": "boolean"}, "unit_conversion": {"operation": "none"}, "scope_resolution": {"strategy": "device"}, "negation_behavior": {"operation": "unsupported"}, "removal_behavior": {"operation": "unsupported"}, "default_behavior": {"operation": "unknown"}, "examples": [],
    }
    definition = MappingDefinition.model_validate(payload)
    assert len(matches_xml(definition, _ir('<j:configuration xmlns:j="urn:junos"><j:system><j:services><j:ssh/></j:services></j:system></j:configuration>'))) == 1
    assert not matches_xml(definition, _ir("<configuration><unrelated><ssh/></unrelated></configuration>"))


def test_xml_scope_qualifier_fails_closed_for_global_ntp_mapping():
    definition = _semantic_definition(
        "time.ntp.server",
        ["rpc-reply", "configuration", "system", "ntp", "server", "name"],
        "text",
        "string",
        "server",
    )
    definition = definition.model_copy(update={
        "scope_resolution": definition.scope_resolution.model_copy(update={
            "xml_unsupported_qualifier_paths": [["routing-instance"]],
        }),
    })
    matches = matches_xml(definition, _ir(
        "<rpc-reply><configuration><system><ntp>"
        "<server><name>48.46.194.186</name><routing-instance>rt1</routing-instance></server>"
        "<server><name>48.45.194.186</name></server>"
        "</ntp></system></configuration></rpc-reply>"
    ))
    assert len(matches) == 2
    assert [xml_match_has_unsupported_qualifier(definition, _ir(
        "<rpc-reply><configuration><system><ntp>"
        "<server><name>48.46.194.186</name><routing-instance>rt1</routing-instance></server>"
        "<server><name>48.45.194.186</name></server>"
        "</ntp></system></configuration></rpc-reply>"
    ), node) for node, _ in matches] == [True, False]


def _semantic_definition(field_id: str, path: list[str], source: str, output: str, capture: str | None = None) -> MappingDefinition:
    return MappingDefinition.model_validate({
        "profile_applicability": {"profile_version_ids": ["juniper.junos.18@1.0.0"]},
        "structural_match": {"operation": "xml_path", "command": "xml", "xml_path": {"path": [{"local_name": item, "occurrence": "any" if item == "server" else "exact"} for item in path], "source": source, "capture": capture, "value_type": output, "start_mode": "document_root"}},
        "target_field_id": field_id,
        "value_extraction": {"operation": "boolean_from_presence" if source == "presence" else "capture", "capture": capture, "output_type": output},
        "unit_conversion": {"operation": "none"}, "scope_resolution": {"strategy": "device"},
        "negation_behavior": {"operation": "unsupported"}, "removal_behavior": {"operation": "unsupported"}, "default_behavior": {"operation": "unknown"}, "examples": [],
    })


def test_review_center_validation_executes_xml_facts_and_effective_states_without_persistence(tmp_path, monkeypatch):
    from app.db.models import Artifact, ArtifactContentFamily, ArtifactEvidenceType, ArtifactStatus
    from app.ingestion.storage import LocalFilesystemArtifactStorage

    organization_id, snapshot_id, artifact_id = uuid4(), uuid4(), uuid4()
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    content = b"<rpc-reply><configuration><system><services><ssh/></services><syslog><host><name>host111</name></host></syslog><ntp><server><name>66.129.233.81</name></server><server><name>192.0.2.10</name></server></ntp></system></configuration></rpc-reply>"
    reference = storage.write(content, organization_id=organization_id, artifact_id=artifact_id)
    artifact = Artifact(artifact_id=artifact_id, organization_id=organization_id, snapshot_id=snapshot_id, original_filename="dev-logging.xml", storage_reference=reference, byte_size=len(content), sha256=sha256(content).hexdigest(), encoding="utf-8", content_family=ArtifactContentFamily.XML, evidence_type=ArtifactEvidenceType.STRUCTURED_EXPORT, status=ArtifactStatus.READY)
    snapshot = SimpleNamespace(snapshot_id=snapshot_id, organization_id=organization_id, device_id=uuid4(), status="locked")
    db = SimpleNamespace(scalar=lambda _statement: artifact, get=lambda _model, _id: snapshot)
    monkeypatch.setattr("app.ingestion.storage.get_artifact_storage", lambda: storage)

    # Build each candidate from the same immutable definition contract.
    for field_id, path, source, output, capture, expected in (
        ("management.remote.ssh.enabled", ["rpc-reply", "configuration", "system", "services", "ssh"], "presence", "boolean", None, True),
        ("logging.remote.destination", ["rpc-reply", "configuration", "system", "syslog", "host", "name"], "text", "string", "destination", "host111"),
        ("time.ntp.server", ["rpc-reply", "configuration", "system", "ntp", "server", "name"], "text", "string", "server", ["66.129.233.81", "192.0.2.10"]),
    ):
        definition = _semantic_definition(field_id, path, source, output, capture)
        candidate = SimpleNamespace(mapping_version_id=uuid4(), mapping_id=uuid4(), organization_id=organization_id, **definition.model_dump(mode="python"))
        result = _validate_against_artifact(db, candidate, definition, artifact_id)
        assert result["status"] == "matched"
        assert [item["value"]["value"] for item in result["facts"]] == ([expected] if not isinstance(expected, list) else expected)
        assert result["effective_states"]
        assert result["matched_paths"][0]["path"][0] == "rpc-reply[1]"

    negative = _semantic_definition("time.ntp.server", ["rpc-reply", "configuration", "system", "ntp", "missing", "name"], "text", "string", "server")
    negative_candidate = SimpleNamespace(mapping_version_id=uuid4(), mapping_id=uuid4(), organization_id=organization_id, **negative.model_dump(mode="python"))
    no_match = _validate_against_artifact(db, negative_candidate, negative, artifact_id)
    assert no_match["status"] == "no_match"
    assert no_match["facts"] == []
    assert no_match["effective_states"] == []
