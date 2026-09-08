"""Focused B7 checks for the scoped DISA Network Device Management SRG pack."""
import importlib.util
import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from app.compliance.evaluator import evaluate_condition
from app.compliance.rule_registry import FORTIOS_RULE_PACK, JUNOS_RULE_PACK, RULE_PACK
from app.compliance.service import evaluate_audit_compliance
from app.compliance.verdicts import FindingVerdict
from app.db.models import AuditStatus
from app.security_model import FIELD_REGISTRY


ROOT = Path(__file__).resolve().parents[3]
SUBSET = json.loads((ROOT / "backend/app/assessment_packs/disa_ndm_srg_v5r5_subset.json").read_text(encoding="utf-8"))
SPEC = importlib.util.spec_from_file_location("b7_migration", ROOT / "database/migrations/versions/20260909_0015_seed_disa_ndm_srg_pack.py")
assert SPEC is not None and SPEC.loader is not None
B7 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B7)


def _rule(pack, rule_id):
    return next(item for item in pack.rules if item.rule_id == rule_id)


def _value(type_, value):
    return {"type": type_, "value": value, "unit": None, "original_value": None, "original_unit": None}


def test_b7_official_disa_provenance_and_selected_xccdf_identifiers_match_frozen_subset():
    assert SUBSET["benchmark_id"] == "Network_Device_Management_SRG"
    assert SUBSET["version"] == SUBSET["release"] == "5"
    assert SUBSET["source_sha256"] == "d6f4415ed5cb4d4c5e589b3e8060203f43742b490aa30be479c774c6ef292a92"
    metadata = {(item["v_number"], item["rule_id"]): item for item in SUBSET["rules"]}
    selected = {(item["source_reference"]["v_number"], item["source_reference"]["rule_id"]) for item in B7.OBLIGATIONS}
    assert selected <= set(metadata)
    assert all(item["source_reference"]["severity"] == metadata[(item["source_reference"]["v_number"], item["source_reference"]["rule_id"])]["severity"] for item in B7.OBLIGATIONS)
    assert B7.SOURCE["source_sha256"] == SUBSET["source_sha256"]


def test_b7_pack_is_unique_honest_and_references_only_registered_canonical_fields():
    assert len(B7.OBLIGATIONS) == 8
    assert len({item["assessment_obligation_id"] for item in B7.OBLIGATIONS}) == 8
    assert len({item["obligation_key"] for item in B7.OBLIGATIONS}) == 8
    automatic = [item for item in B7.OBLIGATIONS if item["assessment_method"] == "automatic"]
    manual = [item for item in B7.OBLIGATIONS if item["assessment_method"] == "manual"]
    assert len(automatic) == 6 and len(manual) == 2
    assert Counter(item["source_reference"]["cat"] for item in B7.OBLIGATIONS) == {"CAT I": 4, "CAT II": 4}
    assert all(item["implementation_status"] == "manual" and item["evaluator_rule_id"] is None for item in manual)
    for obligation in automatic:
        fields = obligation["policy_parameters"]["required_canonical_fields"]
        assert fields and all(field in FIELD_REGISTRY for field in fields)
        for pack in (RULE_PACK, FORTIOS_RULE_PACK, JUNOS_RULE_PACK):
            assert _rule(pack, obligation["evaluator_rule_id"]).required_effective_states == tuple(fields)


def test_b7_pass_fail_and_missing_evidence_unknown_are_deterministic():
    timeout = _rule(RULE_PACK, "management.idle_timeout.maximum")
    assert evaluate_condition(timeout, _value("duration", 300), 300) is FindingVerdict.PASS
    assert evaluate_condition(timeout, _value("duration", 301), 300) is FindingVerdict.FAIL
    audit = SimpleNamespace(audit_id=UUID(int=701), device_id=UUID(int=702), status=AuditStatus.PROCESSING, profile_resolution={"resolution_status": "resolved", "profile_version_id": RULE_PACK.profile_version_id})
    drafts = evaluate_audit_compliance(SimpleNamespace(scalar=lambda _statement: audit), audit_id=audit.audit_id, organization_id=UUID(int=703), rule_pack=RULE_PACK, organization_policy=None, effective_states=())
    assert next(item for item in drafts if item.rule_id == "time.ntp.authentication.enabled").verdict is FindingVerdict.UNKNOWN


def test_same_disa_obligations_evaluate_over_cisco_fortios_and_junos_canonical_states():
    shared = {"management.idle_timeout.maximum": (_value("duration", 300), 300), "logging.enabled": (_value("boolean", True), None), "logging.remote.destination.configured": (_value("list", [{"value": "logs.example.invalid"}]), None), "time.ntp.configured": (_value("boolean", True), None), "time.ntp.server.configured": (_value("list", [{"value": "time.example.invalid"}]), None)}
    for pack in (RULE_PACK, FORTIOS_RULE_PACK, JUNOS_RULE_PACK):
        for rule_id, (value, parameter) in shared.items():
            assert evaluate_condition(_rule(pack, rule_id), value, parameter) is FindingVerdict.PASS


def test_b7_has_no_ai_or_executable_verdict_path_and_b6_seed_remains_independent():
    sources = "\n".join((ROOT / "backend/app" / relative).read_text(encoding="utf-8") for relative in ("assessment_packs/service.py", "compliance/evaluator.py"))
    assert "eval(" not in sources and "openai" not in sources.lower() and "ollama" not in sources.lower()
    b6_spec = importlib.util.spec_from_file_location("b6_migration", ROOT / "database/migrations/versions/20260909_0014_seed_nist_sp80053_rev5_pack.py")
    assert b6_spec is not None and b6_spec.loader is not None
    b6 = importlib.util.module_from_spec(b6_spec)
    b6_spec.loader.exec_module(b6)
    assert b6.PACK_ID == "9c1d2f0d-4c28-5c7d-9b7d-0000000000b6" and b6._digest() == b6._digest()
