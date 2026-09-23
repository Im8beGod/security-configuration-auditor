import importlib.util
from pathlib import Path

import app.interpretation.service  # noqa: F401
from app.compliance.rule_registry import RULE_PACK_BY_PROFILE
from app.knowledge_packs.arista_eos_4 import ARISTA_EOS_4_KNOWLEDGE_PACK
from app.knowledge_packs.cisco_iosxe_17.manifest import CISCO_IOS_XE_17_KNOWLEDGE_PACK
from app.knowledge_packs.fortios_7 import FORTIOS_7_KNOWLEDGE_PACK
from app.profile_resolution import PROFILE_REGISTRY


ROOT = Path(__file__).parents[3]
SPEC = importlib.util.spec_from_file_location(
    "stage6", ROOT / "database/migrations/versions/20260923_0026_expand_scoped_technical_framework_packs.py"
)
stage6 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage6)

ACTIVE_MAPPINGS = {
    "cisco.ios_xe.17@1.0.0": CISCO_IOS_XE_17_KNOWLEDGE_PACK.mappings,
    "fortinet.fortios.7@1.0.0": FORTIOS_7_KNOWLEDGE_PACK.mappings,
    "arista.eos.4@1.0.0": ARISTA_EOS_4_KNOWLEDGE_PACK.mappings,
}


def test_stage6_automatic_obligations_are_source_bound_and_executable():
    assert {item["key"] for item in stage6.NIST_ADDITIONS} == {
        "ac-17.management-source-restriction", "ac-17.http-disabled",
        "ac-17.https-enabled", "ac-17.tls-minimum-1-2",
    }
    assert {item["key"] for item in stage6.ISO_ADDITIONS} == {
        "iso27001-a.5.14-management-source-restriction", "iso27001-a.5.14-http-disabled",
        "iso27001-a.5.14-https-enabled", "iso27001-a.5.14-tls-minimum-1-2",
    }
    for item in (*stage6.NIST_ADDITIONS, *stage6.ISO_ADDITIONS):
        for profile_id in item["profiles"]:
            profile = PROFILE_REGISTRY[profile_id]
            assert item["field"] in profile.coverage_manifest["canonical_fields"]
            assert any(mapping.field_id == item["field"] for mapping in ACTIVE_MAPPINGS[profile_id])
            assert any(rule.rule_id == item["rule"] for rule in RULE_PACK_BY_PROFILE[profile_id].rules)
    assert stage6.NIST_URL.startswith("https://") and len(stage6.NIST_DIGEST) == 64
    assert stage6.OLIR_URL.startswith("https://") and len(stage6.OLIR_DIGEST) == 64
