"""Focused B8 checks for the scoped CIS Cisco IOS XE 17.x pack."""
import importlib.util
import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from app.assessment_packs.contracts import AssessmentMethod, ImplementationStatus
from app.compliance.evaluator import evaluate_condition
from app.compliance.rule_registry import RULE_PACK
from app.compliance.service import evaluate_audit_compliance
from app.compliance.verdicts import FindingVerdict
from app.db.models import AuditStatus
from app.security_model import FIELD_REGISTRY


ROOT = Path(__file__).resolve().parents[3]
SUBSET = json.loads((ROOT / "backend/app/assessment_packs/cis_cisco_ios_xe_17_v2_2_1_subset.json").read_text(encoding="utf-8"))
SPEC = importlib.util.spec_from_file_location("b8_migration", ROOT / "database/migrations/versions/20260909_0016_seed_cis_cisco_ios_xe_17_pack.py")
assert SPEC is not None and SPEC.loader is not None
B8 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B8)


def _rule(rule_id):
    return next(item for item in RULE_PACK.rules if item.rule_id == rule_id)


def _value(type_, value):
    return {"type": type_, "value": value, "unit": None, "original_value": None, "original_unit": None}


def test_b8_exact_authorized_benchmark_metadata_and_selected_identifiers_are_compact():
    assert SUBSET["benchmark_title"] == "CIS Cisco IOS XE 17.x Benchmark"
    assert SUBSET["version"] == "2.2.1" and SUBSET["release_date"] == "2025-07-17"
    assert SUBSET["artifact_filename"] == "CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf"
    assert SUBSET["source_sha256"] == "e5330afdf64cc7a44ba051733e7b3a5b835d7d341610dddb5d5292eabe126b25"
    metadata = {item["id"]: item for item in SUBSET["recommendations"]}
    assert {item["source_reference"]["recommendation_id"] for item in B8.OBLIGATIONS} == set(metadata)
    assert all(item["source_reference"]["cis_level"] == metadata[item["source_reference"]["recommendation_id"]]["level"] for item in B8.OBLIGATIONS)
    assert B8.SOURCE["source_sha256"] == SUBSET["source_sha256"]


def test_b8_pack_is_cisco_only_unique_and_honest_about_automation():
    assert B8.PACK_ID == "9c1d2f0d-4c28-5c7d-9b7d-0000000000b8"
    assert B8.PROFILES == ["cisco.ios_xe.17@1.0.0"]
    assert len(B8.OBLIGATIONS) == len({item["assessment_obligation_id"] for item in B8.OBLIGATIONS}) == 11
    assert len({item["obligation_key"] for item in B8.OBLIGATIONS}) == 11
    automatic = [item for item in B8.OBLIGATIONS if item["assessment_method"] == AssessmentMethod.AUTOMATIC.value]
    manual = [item for item in B8.OBLIGATIONS if item["assessment_method"] == AssessmentMethod.MANUAL.value]
    assert len(automatic) == 6 and len(manual) == 5
    assert Counter(item["source_reference"]["cis_level"] for item in B8.OBLIGATIONS) == {"Level 1": 10, "Level 2": 1}
    assert all(item["implementation_status"] == ImplementationStatus.IMPLEMENTED.value and item["evaluator_rule_id"] for item in automatic)
    assert all(item["implementation_status"] == ImplementationStatus.MANUAL.value and item["evaluator_rule_id"] is None for item in manual)
    assert all(item["source_reference"]["cis_assessment_status"] in {"Automated", "Manual"} for item in B8.OBLIGATIONS)


def test_b8_automatic_bindings_use_existing_cisco_canonical_fields_only():
    for obligation in B8.OBLIGATIONS:
        fields = obligation["policy_parameters"]["required_canonical_fields"]
        assert all(field in FIELD_REGISTRY for field in fields)
        if obligation["assessment_method"] == "automatic":
            assert _rule(obligation["evaluator_rule_id"]).required_effective_states == tuple(fields)


def test_b8_pass_fail_unknown_and_manual_boundaries_are_deterministic():
    source = _rule("management.source.restriction.configured")
    assert evaluate_condition(source, _value("boolean", True)) is FindingVerdict.PASS
    assert evaluate_condition(source, _value("boolean", False)) is FindingVerdict.FAIL
    audit = SimpleNamespace(audit_id=UUID(int=801), device_id=UUID(int=802), status=AuditStatus.PROCESSING, profile_resolution={"resolution_status": "resolved", "profile_version_id": RULE_PACK.profile_version_id})
    drafts = evaluate_audit_compliance(SimpleNamespace(scalar=lambda _statement: audit), audit_id=audit.audit_id, organization_id=UUID(int=803), rule_pack=RULE_PACK, organization_policy=None, effective_states=())
    assert next(item for item in drafts if item.rule_id == source.rule_id).verdict is FindingVerdict.UNKNOWN
    assert all(item["assessment_method"] == "manual" and item["evaluator_rule_id"] is None for item in B8.OBLIGATIONS if item["implementation_status"] == "manual")


def test_b8_has_no_ai_or_executable_verdict_path_and_prior_pack_seeds_are_independent():
    sources = "\n".join((ROOT / "backend/app" / relative).read_text(encoding="utf-8") for relative in ("assessment_packs/service.py", "compliance/evaluator.py"))
    assert "eval(" not in sources and "openai" not in sources.lower() and "ollama" not in sources.lower()
    for filename, pack_id in (("20260909_0014_seed_nist_sp80053_rev5_pack.py", "9c1d2f0d-4c28-5c7d-9b7d-0000000000b6"), ("20260909_0015_seed_disa_ndm_srg_pack.py", "9c1d2f0d-4c28-5c7d-9b7d-0000000000b7")):
        spec = importlib.util.spec_from_file_location(filename, ROOT / "database/migrations/versions" / filename)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        assert module.PACK_ID == pack_id and module._digest() == module._digest()
