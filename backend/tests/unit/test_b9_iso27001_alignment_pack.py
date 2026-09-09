import importlib.util
import json
from pathlib import Path
from uuid import UUID

from app.compliance.evaluator import evaluate_condition
from app.compliance.rule_registry import FORTIOS_RULE_PACK, JUNOS_RULE_PACK, RULE_PACK
from app.compliance.verdicts import FindingVerdict
from app.security_model import FIELD_REGISTRY

ROOT = Path(__file__).resolve().parents[3]
SUBSET = json.loads((ROOT / "backend/app/assessment_packs/iso27001_2022_nist_olir_subset.json").read_text())
spec = importlib.util.spec_from_file_location("b9", ROOT / "database/migrations/versions/20260909_0017_seed_iso27001_nist_olir_alignment_pack.py")
B9 = importlib.util.module_from_spec(spec); spec.loader.exec_module(B9)

def _rule(pack, rule_id): return next(x for x in pack.rules if x.rule_id == rule_id)
def _value(type_, value): return {"type": type_, "value": value}

def test_b9_public_metadata_and_nist_olir_relationships_are_compact_and_exact():
    assert SUBSET["iso_open_data"]["reference"] == "ISO/IEC 27001:2022"
    assert SUBSET["iso_open_data"]["edition"] == 3 and SUBSET["iso_open_data"]["publication_date"] == "2022-10-25"
    assert SUBSET["iso_open_data"]["amendment"]["reference"] == "ISO/IEC 27001:2022/Amd 1:2024"
    assert SUBSET["olir"]["version"] == "1.0.0" and SUBSET["olir"]["sha3_256"] == B9.OLIR_DIGEST
    relationships = {(x["nist_control_id"], x["iso_annex_a_id"]) for x in SUBSET["relationships"]}
    assert {(x["source_reference"]["nist_control_id"], x["source_reference"]["iso_annex_a_control_id"]) for x in B9.OBLIGATIONS} <= relationships

def test_b9_reuses_b6_bindings_without_iso_evaluation_and_is_honest():
    assert B9.PACK_ID.endswith("0000000000b9") and len(B9.OBLIGATIONS) == 10
    assert len({x["assessment_obligation_id"] for x in B9.OBLIGATIONS}) == 10
    automatic = [x for x in B9.OBLIGATIONS if x["assessment_method"] == "automatic"]
    manual = [x for x in B9.OBLIGATIONS if x["assessment_method"] == "manual"]
    assert len(automatic) == 8 and len(manual) == 2
    for x in automatic:
        fields = x["policy_parameters"]["required_canonical_fields"]
        assert all(field in FIELD_REGISTRY for field in fields)
        assert all(_rule(pack, x["evaluator_rule_id"]).required_effective_states == tuple(fields) for pack in (RULE_PACK, FORTIOS_RULE_PACK, JUNOS_RULE_PACK))
    assert all(x["evaluator_rule_id"] is None for x in manual)
    assert "certification" not in " ".join(x["title"].lower() for x in B9.OBLIGATIONS)

def test_b9_pass_fail_unknown_capability_is_shared_across_vendors():
    for pack in (RULE_PACK, FORTIOS_RULE_PACK, JUNOS_RULE_PACK):
        rule = _rule(pack, "management.ssh.enabled")
        assert evaluate_condition(rule, _value("boolean", True)) is FindingVerdict.PASS
        assert evaluate_condition(rule, _value("boolean", False)) is FindingVerdict.FAIL
    assert B9.SOURCE["relationship_disclaimer"].startswith("NIST OLIR")
    assert "eval(" not in (ROOT / "backend/app/compliance/evaluator.py").read_text()
