"""Focused B6 checks for the scoped NIST SP 800-53 Rev. 5 AssessmentPack."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from app.compliance.evaluator import evaluate_condition
from app.compliance.rule_registry import FORTIOS_RULE_PACK, JUNOS_RULE_PACK, RULE_PACK
from app.compliance.service import evaluate_audit_compliance
from app.compliance.verdicts import FindingVerdict
from app.db.models import AuditStatus
from app.reporting.pdf import build_device_compliance_pdf
from app.security_model import FIELD_REGISTRY


ROOT = Path(__file__).resolve().parents[3]
SUBSET = json.loads((ROOT / "backend/app/assessment_packs/nist_sp80053_rev5_subset.json").read_text(encoding="utf-8"))
SPEC = importlib.util.spec_from_file_location("b6_migration", ROOT / "database/migrations/versions/20260909_0014_seed_nist_sp80053_rev5_pack.py")
assert SPEC is not None and SPEC.loader is not None
B6 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B6)


def _rule(pack, rule_id):
    return next(item for item in pack.rules if item.rule_id == rule_id)


def _value(type_, value):
    return {"type": type_, "value": value, "unit": None, "original_value": None, "original_unit": None}


def test_official_nist_subset_provenance_and_selected_control_ids_are_immutable():
    assert SUBSET["framework"] == "NIST SP 800-53"
    assert SUBSET["catalog_version"] == "5.2.0"
    assert SUBSET["source_sha256"] == "01f37cf90ea99d92242c936cbfbdebcc338eef1f71454e2acac36cc56e9bc062"
    controls = {item["id"]: item["title"] for item in SUBSET["controls"]}
    assert controls == {"AC-11": "Device Lock", "AC-17": "Remote Access", "AU-8": "Time Stamps", "AU-12": "Audit Record Generation"}
    assert B6.SOURCE["official_source_url"] == SUBSET["source_url"]
    assert B6.SOURCE["source_sha256"] == SUBSET["source_sha256"]
    assert {item["source_reference"]["control_id"] for item in B6.OBLIGATIONS} == set(controls)
    assert all(item["source_reference"]["control_title"] == controls[item["source_reference"]["control_id"]] for item in B6.OBLIGATIONS)


def test_b6_obligations_are_unique_honest_and_bound_to_valid_canonical_fields():
    assert len(B6.OBLIGATIONS) == 10
    assert len({item["assessment_obligation_id"] for item in B6.OBLIGATIONS}) == 10
    assert len({item["obligation_key"] for item in B6.OBLIGATIONS}) == 10
    automatic = [item for item in B6.OBLIGATIONS if item["assessment_method"] == "automatic"]
    manual = [item for item in B6.OBLIGATIONS if item["assessment_method"] == "manual"]
    assert len(automatic) == 8 and len(manual) == 2
    assert all(item["implementation_status"] == "implemented" and item["evaluator_rule_id"] for item in automatic)
    assert all(item["implementation_status"] == "manual" and item["evaluator_rule_id"] is None for item in manual)
    for obligation in automatic:
        fields = obligation["policy_parameters"]["required_canonical_fields"]
        assert fields and all(field in FIELD_REGISTRY for field in fields)
        for pack in (RULE_PACK, FORTIOS_RULE_PACK, JUNOS_RULE_PACK):
            assert _rule(pack, obligation["evaluator_rule_id"]).required_effective_states == tuple(fields)


def test_same_nist_technical_obligations_evaluate_across_cisco_fortios_and_junos():
    shared = {
        "management.ssh.enabled": _value("boolean", True),
        "logging.remote.destination.configured": _value("list", [{"value": "logs.example.invalid"}]),
        "time.ntp.server.configured": _value("list", [{"value": "time.example.invalid"}]),
        "time.ntp.configured": _value("boolean", True),
    }
    for pack in (RULE_PACK, FORTIOS_RULE_PACK, JUNOS_RULE_PACK):
        for rule_id, value in shared.items():
            assert evaluate_condition(_rule(pack, rule_id), value) is FindingVerdict.PASS


def test_b6_pass_fail_and_missing_evidence_unknown_are_deterministic():
    assert evaluate_condition(_rule(RULE_PACK, "management.ssh.enabled"), _value("boolean", True)) is FindingVerdict.PASS
    assert evaluate_condition(_rule(RULE_PACK, "management.ssh.enabled"), _value("boolean", False)) is FindingVerdict.FAIL
    audit = SimpleNamespace(audit_id=UUID(int=601), device_id=UUID(int=602), status=AuditStatus.PROCESSING, profile_resolution={"resolution_status": "resolved", "profile_version_id": RULE_PACK.profile_version_id})
    drafts = evaluate_audit_compliance(SimpleNamespace(scalar=lambda _statement: audit), audit_id=audit.audit_id, organization_id=UUID(int=603), rule_pack=RULE_PACK, organization_policy=None, effective_states=())
    assert next(item for item in drafts if item.rule_id == "management.ssh.enabled").verdict is FindingVerdict.UNKNOWN


def test_b6_has_no_ai_or_executable_verdict_path():
    root = ROOT / "backend/app"
    sources = "\n".join((root / relative).read_text(encoding="utf-8") for relative in ("assessment_packs/service.py", "compliance/evaluator.py"))
    assert "eval(" not in sources and "openai" not in sources.lower() and "ollama" not in sources.lower()


def test_b6_report_projection_represents_control_mode_verdict_and_state():
    document = {
        "device": {"display_name": "B6 device"},
        "audit": {"audit_id": "b6", "revision_number": 1, "status": "completed", "profile": "cisco.ios_xe.17@1.0.0", "verdict_counts": {}, "severity_counts": {}, "coverage": {"automatic_verdicts": {"pass": 1}, "manual": 2}, "assessment": {"name": "NIST SP 800-53 Rev. 5 Scoped Technical Pack", "version": 1}},
        "findings": [],
        "assessment_results": [{"obligation_key": "ac-17.remote-ssh-enabled", "control_id": "AC-17", "control_title": "Remote Access", "assessment_method": "automatic", "implementation_status": "implemented", "verdict": "pass", "details": {"effective_state": {"field_id": "management.remote.ssh.enabled", "value": {"type": "boolean", "value": True}}}}],
    }
    assert build_device_compliance_pdf(document).startswith(b"%PDF-")
