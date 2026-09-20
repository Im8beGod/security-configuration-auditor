from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from app.db.models import ArtifactEvidenceType, DeviceClass
from app.interpretation import InterpretationContext, interpret_structural_ir
from app.parsing import ArtifactProvenance, parse_configuration_text
from app.profile_resolution import ARISTA_EOS_4, ResolutionStatus, SnapshotEvidence, resolve_profile
from app.profile_resolution.evidence import EvidenceDocument
from app.remediation.service import RemediationError, preview_remediation


FIXTURES = Path(__file__).parents[1] / "fixtures" / "arista_eos"


def _document(text, number=1, evidence_type=ArtifactEvidenceType.VERSION_OUTPUT):
    return EvidenceDocument(
        artifact_id=UUID(int=number), organization_id=UUID(int=10),
        snapshot_id=UUID(int=11), device_id=UUID(int=12),
        evidence_type=evidence_type, original_filename="evidence.txt",
        sha256="a" * 64, source_metadata={}, text=text,
        inspected_bytes=len(text.encode()), truncated=False,
    )


def _resolve(*documents):
    return resolve_profile(SnapshotEvidence(
        UUID(int=11), UUID(int=10), UUID(int=12), documents, (),
        sum(item.inspected_bytes for item in documents),
    ))


def _interpret(text):
    source = ArtifactProvenance(
        UUID(int=20), UUID(int=10), UUID(int=11), "representative.cfg",
        "b" * 64, {"ingestion": "test"},
    )
    ir = parse_configuration_text(
        text, source=source, reader_id="indentation_cli.v1"
    )
    result = interpret_structural_ir(
        ir, InterpretationContext(UUID(int=21), UUID(int=12), UUID(int=11)),
        profile_version_id=ARISTA_EOS_4.profile_version_id,
    )
    return ir, result


def test_arista_profile_requires_bounded_version_output():
    version = (FIXTURES / "show-version.txt").read_text(encoding="utf-8")
    result = _resolve(_document(version))
    assert result.selected_profile_version_id == "arista.eos.4@1.0.0"
    assert (result.vendor, result.os, result.os_version) == ("Arista", "EOS", "4.31.2F")
    assert result.device_class == DeviceClass.SWITCH

    config_claim = _resolve(_document(
        "! Arista EOS version 4.31.2F\nmanagement ssh\n   no shutdown\n",
        evidence_type=ArtifactEvidenceType.CONFIGURATION,
    ))
    assert config_claim.selected_profile_version_id is None
    assert config_claim.resolution_status == ResolutionStatus.UNRESOLVED


def test_arista_conflicting_version_evidence_fails_closed():
    first = "Arista vEOS-lab\nSoftware image version: 4.31.2F\n"
    second = "Arista DCS-7050SX3\nSoftware image version: 4.30.7M\n"
    result = _resolve(_document(first, 1), _document(second, 2))
    assert result.resolution_status == ResolutionStatus.CONFLICT
    assert result.selected_profile_version_id is None


def test_arista_structure_normalization_and_provenance_are_bounded():
    text = (FIXTURES / "representative.cfg").read_text(encoding="utf-8")
    ir, result = _interpret(text)
    idle = next(node for node in ir.nodes if node.command == "idle-timeout")
    assert ir.node(idle.parent_id).command == "management"
    assert ir.node(idle.parent_id).arguments == ("ssh",)

    facts = {item.field_id: item for item in result.facts}
    assert facts["management.remote.ssh.enabled"].value.value is True
    assert facts["management.remote.telnet.enabled"].value.value is True
    assert facts["management.session.idle_timeout"].value.value == 600
    assert facts["logging.remote.destination"].value.value == "192.0.2.40"
    assert facts["time.ntp.server"].value.value == "time.example.invalid"
    assert facts["management.remote.source.restriction.configured"].value.value is True
    assert all(ref.artifact_id == UUID(int=20) for fact in result.facts for ref in fact.evidence_refs)
    assert all(ref.source_path == "representative.cfg" for fact in result.facts for ref in fact.evidence_refs)
    assert result.unresolved_node_ids


def test_arista_unsupported_syntax_stays_unresolved():
    _ir, result = _interpret("management ssh\n   ip access-group MGMT-SOURCES out\n")
    assert not any(
        fact.field_id == "management.remote.source.restriction.configured"
        for fact in result.facts
    )
    assert "invalid_arista_service_acl" in {item.code for item in result.diagnostics}
    assert result.unresolved_node_ids


class _EmptyDb:
    def scalars(self, _statement): return ()
    def scalar(self, _statement): return self.finding
    def get(self, _model, _identifier): return self.audit


def test_arista_remediation_rule_binding_and_parameter_validation():
    db = _EmptyDb()
    db.audit = SimpleNamespace(
        version_refs={"device_profile_version_id": ARISTA_EOS_4.profile_version_id},
        profile_resolution={"profile_version_id": ARISTA_EOS_4.profile_version_id, "resolution_status": "resolved"},
    )
    db.finding = SimpleNamespace(
        finding_id=uuid4(), audit_id=UUID(int=30),
        rule_id="logging.remote.destination.configured",
        remediation_procedure_id=None, verdict="fail",
    )
    preview = preview_remediation(
        db, SimpleNamespace(organization_id=UUID(int=10)), db.finding.finding_id,
        {"destination": "Logs.Example.Invalid"},
    )
    assert preview["procedure_key"] == "arista.eos.4.remote-logging-host"
    assert "logging host logs.example.invalid" in preview["rendered_steps"]
    with pytest.raises(RemediationError):
        preview_remediation(
            db, SimpleNamespace(organization_id=UUID(int=10)), db.finding.finding_id,
            {"destination": "bad value"},
        )
