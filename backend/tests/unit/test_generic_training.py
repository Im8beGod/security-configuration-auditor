from types import SimpleNamespace
from uuid import UUID, uuid4

from app.compliance.rule_registry import GENERIC_RULE_PACK
from app.compliance.service import evaluate_audit_compliance
from app.compliance.verdicts import FindingVerdict
from app.db.models import ArtifactEvidenceType, AuditStatus
from app.interpretation.models import InterpretationContext
from app.interpretation.service import (
    _training_mapping,
    interpret_structural_ir,
    load_validated_knowledge_pack,
)
from app.interpretation.knowledge_pack import KnowledgePack
from app.parsing import ArtifactProvenance, parse_configuration_text
from app.profile_resolution import GENERIC_CLI, ResolutionStatus, SnapshotEvidence, resolve_profile
from app.profile_resolution.evidence import EvidenceDocument
from app.training.dsl import MappingDefinition
from app.training.service import validate_definition


def _definition() -> MappingDefinition:
    examples = []
    for family, command, scope, expected in (
        ("positive", "nebula-ssh", "device", True),
        ("alternate_values", "nebula-ssh", "device", True),
        ("negative", "hostname", "device", False),
        ("wrong_scope", "nebula-ssh", "interface", False),
        ("negation", "nebula-ssh", "device", True),
        ("conflict", "nebula-ssh", "device", True),
        ("regression", "login", "device", False),
    ):
        examples.append({
            "family": family,
            "node": {"command": command, "arguments": ["enable"], "scope_type": scope, "negated": family == "negation"},
            "expected_match": expected,
            "expected_value": True if expected else None,
        })
    return MappingDefinition.model_validate({
        "profile_applicability": {"profile_version_ids": [GENERIC_CLI.profile_version_id]},
        "structural_match": {
            "command": "nebula-ssh", "scope_type": "device",
            "arguments": [{"operation": "literal", "value": "enable"}],
        },
        "target_field_id": "management.remote.ssh.enabled",
        "value_extraction": {"operation": "constant", "value": True, "output_type": "boolean"},
        "scope_resolution": {"strategy": "device"},
        "negation_behavior": {"operation": "emit_value"},
        "removal_behavior": {"operation": "remove_value"},
        "default_behavior": {"operation": "unknown"},
        "examples": examples,
    })


def _ir():
    source = ArtifactProvenance(UUID(int=1), UUID(int=2), UUID(int=3), "unknown.cfg", "a" * 64, {})
    return parse_configuration_text("nebula-ssh enable\n", source=source, reader_id="indentation_cli.v1")


def test_unknown_configuration_resolves_to_generic_and_retains_labels():
    document = EvidenceDocument(
        UUID(int=1), UUID(int=2), UUID(int=3), UUID(int=4),
        ArtifactEvidenceType.CONFIGURATION, "unknown.cfg", "a" * 64,
        {"vendor_label": "Nebula Networks", "os_label": "StarOS"},
        "nebula-ssh enable\n", 18, False,
    )
    result = resolve_profile(SnapshotEvidence(UUID(int=3), UUID(int=2), UUID(int=4), (document,), (), 18))
    assert result.resolution_status is ResolutionStatus.RESOLVED
    assert result.selected_profile_version_id == GENERIC_CLI.profile_version_id
    assert result.to_persisted()["metadata"]["administrator_labels"] == {"vendor": "Nebula Networks", "os": "StarOS"}


def test_unknown_command_is_unresolved_and_cannot_produce_pass():
    ir = _ir()
    context = InterpretationContext(UUID(int=10), UUID(int=4), UUID(int=3))
    result = interpret_structural_ir(ir, context, profile_version_id=GENERIC_CLI.profile_version_id)
    assert result.facts == ()
    assert result.unresolved_node_ids == (ir.nodes[0].node_id,)

    audit = SimpleNamespace(
        audit_id=context.audit_id, device_id=context.device_id,
        status=AuditStatus.PROCESSING,
        profile_resolution={"resolution_status": "resolved", "profile_version_id": GENERIC_CLI.profile_version_id},
    )
    db = SimpleNamespace(scalar=lambda _statement: audit)
    findings = evaluate_audit_compliance(
        db, audit_id=context.audit_id, organization_id=UUID(int=2),
        rule_pack=GENERIC_RULE_PACK, organization_policy=None, effective_states=(),
    )
    assert findings and {item.verdict for item in findings} == {FindingVerdict.UNKNOWN}


def test_validated_training_mapping_is_applied_with_evidence_provenance(monkeypatch):
    definition = _definition()
    row = SimpleNamespace(
        mapping_id=uuid4(), mapping_version_id=uuid4(), organization_id=uuid4(),
        target_field_id=definition.target_field_id,
        profile_applicability=definition.profile_applicability.model_dump(mode="json"),
        structural_match=definition.structural_match.model_dump(mode="json"),
        value_extraction=definition.value_extraction.model_dump(mode="json"),
        unit_conversion=definition.unit_conversion.model_dump(mode="json"),
        scope_resolution=definition.scope_resolution.model_dump(mode="json"),
        negation_behavior=definition.negation_behavior.model_dump(mode="json"),
        removal_behavior=definition.removal_behavior.model_dump(mode="json"),
        default_behavior=definition.default_behavior.model_dump(mode="json"),
        examples=[item.model_dump(mode="json") for item in definition.examples],
    )
    monkeypatch.setattr("app.training.repository.published_mappings", lambda _db, _organization_id: [])
    assert validate_definition(None, row, definition)["passed"] is True
    baseline = load_validated_knowledge_pack(GENERIC_CLI.profile_version_id)
    mapping = _training_mapping(row, GENERIC_CLI.profile_version_id)
    pack = KnowledgePack(
        baseline.knowledge_pack_id, uuid4(), baseline.name, "1.0.1", baseline.schema_version,
        baseline.profile_id, baseline.profile_version_id, (mapping,),
    )
    context = InterpretationContext(UUID(int=10), UUID(int=4), UUID(int=3))
    result = interpret_structural_ir(_ir(), context, profile_version_id=GENERIC_CLI.profile_version_id, knowledge_pack=pack)
    assert len(result.facts) == 1
    assert result.facts[0].field_id == "management.remote.ssh.enabled"
    assert result.facts[0].value.value is True
    assert result.facts[0].evidence_refs[0].artifact_id == UUID(int=1)
