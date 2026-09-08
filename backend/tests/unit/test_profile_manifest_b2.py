from uuid import UUID

import pytest

from app.parsing.models import ArtifactProvenance, StructuralParseRequest
from app.parsing.readers.xml_tree import XML_TREE_READER_ID, XmlTreeReader
from app.profile_resolution import ResolutionStatus
from app.profile_resolution.evidence import EvidenceDocument, SnapshotEvidence
from app.db.models import ArtifactEvidenceType
from app.profile_resolution.models import EvidenceSignal, SignalStrength
from app.profile_resolution.registry import VersionConstraint, compatible_manifests
from app.profile_resolution.resolver import resolve_profile


def _doc(text: str, number: int = 1) -> EvidenceDocument:
    return EvidenceDocument(UUID(int=number), UUID(int=2), UUID(int=3), UUID(int=4), ArtifactEvidenceType.VERSION_OUTPUT, "show-version.txt", "a" * 64, {}, text, len(text), False)


def test_version_boundaries_exclusions_and_unknown_are_explicit():
    constraint = VersionConstraint(frozenset({17}), minimum_version=(17, 3), maximum_version=(17, 12), excluded_versions=frozenset({"17.9.4a"}))
    assert constraint.accepts("17.3")
    assert constraint.accepts("17.12.3")
    assert not constraint.accepts("17.2")
    assert not constraint.accepts("17.9.4a")
    assert constraint.parse("not-a-version") is None


def test_missing_version_and_conflicting_identity_remain_reviewable():
    missing = resolve_profile(SnapshotEvidence(UUID(int=3), UUID(int=2), UUID(int=4), (_doc("Cisco IOS XE Software"),), (), 20))
    assert missing.resolution_status.value == "partially_resolved"
    assert missing.to_persisted()["identity_provenance"]
    conflict = resolve_profile(SnapshotEvidence(UUID(int=3), UUID(int=2), UUID(int=4), (_doc("Cisco IOS XE Software, Version 17.9.4a"), _doc("FortiOS v7.4.3", 5)), (), 40))
    assert conflict.resolution_status == ResolutionStatus.CONFLICT


def test_xml_tree_preserves_namespaces_attributes_repetition_and_provenance():
    source = ArtifactProvenance(UUID(int=8), UUID(int=2), UUID(int=3), "unknown.xml", "a" * 64, {})
    result = XmlTreeReader().parse(StructuralParseRequest('<r xmlns="urn:test"><item id="a">one</item><item id="b">two</item></r>', source))
    assert result.reader_id == XML_TREE_READER_ID
    assert [node.path for node in result.nodes] == [("{urn:test}r[1]",), ("{urn:test}r[1]", "{urn:test}item[1]"), ("{urn:test}r[1]", "{urn:test}item[2]")]
    assert result.nodes[1].attributes == (("id", "a"),)
    assert result.nodes[2].source.source_label == "unknown.xml"


def test_xml_tree_rejects_dtd_malformed_and_bounds():
    source = ArtifactProvenance(UUID(int=8), UUID(int=2), UUID(int=3), "unknown.xml", "a" * 64, {})
    with pytest.raises(ValueError, match="DTD"):
        XmlTreeReader().parse(StructuralParseRequest('<!DOCTYPE r [<!ENTITY x "x">]><r>&x;</r>', source))
    with pytest.raises(ValueError, match="Malformed"):
        XmlTreeReader().parse(StructuralParseRequest("<r>", source))
    with pytest.raises(ValueError, match="size"):
        XmlTreeReader().parse(StructuralParseRequest("<r>" + "x" * (2 * 1024 * 1024) + "</r>", source))
