import json
from uuid import uuid4

import pytest

from app.assessment_packs.catalog import CatalogImportError, parse_external_catalog
from app.assessment_packs.contracts import (
    ApplicabilityStatus, AssessmentMethod, AssessmentResult, ImplementationStatus,
    coverage_summary,
)


def _catalog():
    return {
        "schema_version": "1.0.0", "framework": "cis",
        "catalog_id": "customer-cis-iosxe", "name": "Customer CIS catalog",
        "source_version": "v1", "source_url": "https://example.invalid/cis.json",
        "profile_version_ids": ["cisco.ios_xe.17@1.0.0"],
        "controls": [
            {"control_id": "1.1", "title": "Reviewed control", "severity": "high", "scope": "device", "implementation_status": "manual"},
            {"control_id": "1.2", "title": "Unavailable control", "severity": "medium", "scope": "device", "implementation_status": "unimplemented"},
        ],
    }


def test_external_catalog_preserves_provenance_and_never_binds_automation():
    content = json.dumps(_catalog(), sort_keys=True).encode()
    catalog = parse_external_catalog(content, "catalog.json")
    assert catalog.framework == "cis" and catalog.source_url.startswith("https://")
    assert len(catalog.source_digest) == 64
    assert [item["implementation_status"] for item in catalog.controls] == ["manual", "unimplemented"]

    payload = _catalog()
    payload["controls"][0]["evaluator_rule_id"] = "management.telnet.disabled"
    with pytest.raises(CatalogImportError, match="automatic"):
        parse_external_catalog(json.dumps(payload).encode(), "unsafe.json")


def test_unimplemented_coverage_is_not_reported_as_manual_or_pass():
    result = AssessmentResult(
        result_identity="external:1.2", obligation_id=uuid4(),
        applicability_status=ApplicabilityStatus.APPLICABLE,
        assessment_method=AssessmentMethod.MANUAL,
        implementation_status=ImplementationStatus.UNIMPLEMENTED,
        verdict=None, technical_finding_id=None, policy_digest="a" * 64, details={},
    )
    coverage = coverage_summary([result])
    assert coverage["unimplemented"] == 1
    assert coverage["manual"] == coverage["pass"] == coverage["automatic"] == 0
