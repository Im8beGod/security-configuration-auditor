from types import SimpleNamespace
from uuid import UUID, uuid4

from app.interpretation.knowledge_pack import KnowledgePack
from app.interpretation.models import InterpretationContext
from app.interpretation.service import _training_mapping, interpret_json_structural_ir, load_validated_knowledge_pack
from app.parsing.models import ArtifactProvenance, StructuralParseRequest
from app.parsing.readers.json_tree import JsonTreeReader
from app.profile_resolution import GENERIC_JSON, ResolutionStatus, SnapshotEvidence, resolve_profile
from app.profile_resolution.evidence import EvidenceDocument
from app.db.models import ArtifactEvidenceType
from app.training.dsl import MappingDefinition, matches_json


def _definition() -> MappingDefinition:
    return MappingDefinition.model_validate({
        "profile_applicability": {"profile_version_ids": [GENERIC_JSON.profile_version_id]},
        "structural_match": {
            "operation": "json_path", "command": "json",
            "json_path": {
                "path": [{"key": "management"}, {"key": "ssh"}, {"key": "enabled"}],
                "source": "value", "capture": "enabled", "value_type": "boolean",
            },
        },
        "target_field_id": "management.remote.ssh.enabled",
        "value_extraction": {"operation": "capture", "capture": "enabled", "output_type": "boolean"},
        "scope_resolution": {"strategy": "device"},
        "negation_behavior": {"operation": "unsupported"},
        "removal_behavior": {"operation": "unsupported"},
        "default_behavior": {"operation": "unknown"},
        "examples": [],
    })


def _ir(text: str):
    source = ArtifactProvenance(UUID(int=1), UUID(int=2), UUID(int=3), "unknown.json", "a" * 64, {})
    return JsonTreeReader().parse(StructuralParseRequest(text, source))


def test_unknown_json_resolves_to_bounded_profile_and_exact_path_matches():
    text = '{"management":{"ssh":{"enabled":false}}}'
    document = EvidenceDocument(
        UUID(int=1), UUID(int=2), UUID(int=3), UUID(int=4),
        ArtifactEvidenceType.STRUCTURED_EXPORT, "unknown.json", "a" * 64,
        {"vendor_label": "Nebula", "os_label": "API OS"}, text, len(text), False,
    )
    resolved = resolve_profile(SnapshotEvidence(UUID(int=3), UUID(int=2), UUID(int=4), (document,), (), len(text)))
    assert resolved.resolution_status is ResolutionStatus.RESOLVED
    assert resolved.selected_profile_version_id == GENERIC_JSON.profile_version_id
    assert resolved.metadata["administrator_labels"] == {"vendor": "Nebula", "os": "API OS"}
    matches = matches_json(_definition(), _ir(text))
    assert len(matches) == 1 and matches[0][1] == {"enabled": False}
    assert matches_json(_definition(), _ir('{"management":{"ssh":{"other":false}}}')) == ()


def test_published_json_mapping_produces_provenanced_fact():
    definition = _definition()
    row = SimpleNamespace(
        mapping_id=uuid4(), mapping_version_id=uuid4(), target_field_id=definition.target_field_id,
        profile_applicability=definition.profile_applicability.model_dump(mode="json"),
        structural_match=definition.structural_match.model_dump(mode="json"),
        value_extraction=definition.value_extraction.model_dump(mode="json"),
        unit_conversion=definition.unit_conversion.model_dump(mode="json"),
        scope_resolution=definition.scope_resolution.model_dump(mode="json"),
        negation_behavior=definition.negation_behavior.model_dump(mode="json"),
        removal_behavior=definition.removal_behavior.model_dump(mode="json"),
        default_behavior=definition.default_behavior.model_dump(mode="json"), examples=[],
    )
    baseline = load_validated_knowledge_pack(GENERIC_JSON.profile_version_id)
    mapping = _training_mapping(row, GENERIC_JSON.profile_version_id)
    pack = KnowledgePack(
        baseline.knowledge_pack_id, uuid4(), baseline.name, "1.0.1", baseline.schema_version,
        baseline.profile_id, baseline.profile_version_id, (mapping,),
    )
    result = interpret_json_structural_ir(
        _ir('{"management":{"ssh":{"enabled":false}}}'),
        InterpretationContext(UUID(int=10), UUID(int=4), UUID(int=3)),
        profile_version_id=GENERIC_JSON.profile_version_id, knowledge_pack=pack,
    )
    assert len(result.facts) == 1
    assert result.facts[0].value.value is False
    assert result.facts[0].evidence_refs[0].artifact_id == UUID(int=1)
    assert result.facts[0].evidence_refs[0].evidence_type is ArtifactEvidenceType.STRUCTURED_EXPORT
