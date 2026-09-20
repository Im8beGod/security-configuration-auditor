from types import SimpleNamespace
from uuid import UUID

import pytest

from app.assessment_packs.catalog import load_all_source_catalogs, validate_persisted_obligation
from app.assessment_packs.service import FRAMEWORK_FAMILIES
from app.compliance.evaluator import evaluate_condition
from app.compliance.rule_registry import FORTIOS_RULE_PACK, RULE_PACK_BY_PROFILE
from app.compliance.verdicts import FindingVerdict
from app.interpretation.models import InterpretationContext
from app.interpretation.service import interpret_structural_ir
from app.parsing import ArtifactProvenance, parse_configuration_text


def test_all_available_source_catalog_items_load_with_versioned_provenance():
    catalogs = {item.framework: item for item in load_all_source_catalogs()}
    assert {key: len(value.obligations) for key, value in catalogs.items()} == {
        "nist": 4, "disa": 7, "cis": 11, "iso": 4,
    }
    assert catalogs["nist"].metadata["source_sha256"]
    assert catalogs["disa"].metadata["source_url"].startswith("https://")
    assert catalogs["cis"].metadata["official_source_url"].startswith("https://")
    assert catalogs["iso"].metadata["olir"]["sha3_256"]
    assert set(FRAMEWORK_FAMILIES.values()) == {
        "CIS Benchmark", "NIST SP 800-53", "DISA SRG", "ISO/IEC 27001 Alignment",
    }


def test_catalog_provenance_requires_source_control_severity_and_scope():
    row = SimpleNamespace(
        framework_version="Rev. 5", source_url="https://example.invalid/catalog.json",
        source_digest="a" * 64, control_id="AC-17", title="Remote Access",
        severity="not_assigned", scope="device configuration",
    )
    validate_persisted_obligation(row)
    row.source_url = "file:///catalog.json"
    with pytest.raises(ValueError):
        validate_persisted_obligation(row)


def test_ordered_tls_rule_and_cross_vendor_applicability_are_bounded():
    rule = next(item for item in FORTIOS_RULE_PACK.rules if item.rule_id == "management.tls.minimum_1_2")
    assert evaluate_condition(rule, {"type": "enum", "value": "tlsv1-3"}) is FindingVerdict.PASS
    assert evaluate_condition(rule, {"type": "enum", "value": "tlsv1-1"}) is FindingVerdict.FAIL
    for profile, pack in RULE_PACK_BY_PROFILE.items():
        assert pack.profile_version_id == profile
        assert all(item.applicability["profile_version_id"] == profile for item in pack.rules)


def test_fortios_http_evidence_normalizes_without_inventing_other_fields():
    source = ArtifactProvenance(UUID(int=1), UUID(int=2), UUID(int=3), "fortios.conf", "a" * 64, {})
    ir = parse_configuration_text(
        'config system interface\n edit "port1"\n  set allowaccess ping https ssh\n next\nend\n',
        source=source, reader_id="fortios_cli.v1",
    )
    result = interpret_structural_ir(
        ir, InterpretationContext(UUID(int=4), UUID(int=5), UUID(int=3)),
        profile_version_id="fortinet.fortios.7@1.0.0",
    )
    facts = {item.field_id: item for item in result.facts}
    assert facts["management.remote.http.enabled"].value.value is False
    assert "management.remote.ssh.strong_crypto.configured" not in facts
    assert facts["management.remote.http.enabled"].evidence_refs[0].artifact_id == UUID(int=1)
