from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.assessment_packs.contracts import (
    ApplicabilityStatus,
    AssessmentMethod,
    AssessmentObligation,
    AssessmentPackVersion,
    AssessmentResult,
    ImplementationStatus,
    coverage_summary,
    policy_digest,
)
from app.assessment_packs.service import (
    AssessmentPackError,
    AssessmentPackRegistry,
    _automatic_evidence_supported,
)


def test_assessment_pack_and_obligation_contracts_are_immutable_and_test_scoped():
    pack = AssessmentPackVersion(
        assessment_pack_version_id=uuid4(), pack_key="synthetic", family="TEST/INFRASTRUCTURE",
        name="Synthetic", version=1, profile_version_ids=("cisco.ios_xe.17@1.0.0",),
        source_metadata={"notice": "TEST/INFRASTRUCTURE ONLY"}, source_version_label="synthetic@1",
        content_digest="a" * 64, applicability={"profile_version_ids": ["cisco.ios_xe.17@1.0.0"]},
    )
    with pytest.raises(FrozenInstanceError):
        pack.name = "changed"
    with pytest.raises(ValueError, match="evaluator"):
        AssessmentObligation(
            assessment_obligation_id=uuid4(), obligation_key="bad", title="Bad", applicability={},
            assessment_method=AssessmentMethod.AUTOMATIC, implementation_status=ImplementationStatus.IMPLEMENTED,
            evaluator_rule_id=None, policy_parameters={}, source_reference={},
        )


def test_coverage_keeps_manual_unimplemented_and_automatic_verdicts_separate():
    results = [
        AssessmentResult("a", uuid4(), ApplicabilityStatus.APPLICABLE, AssessmentMethod.AUTOMATIC, ImplementationStatus.IMPLEMENTED, "pass", None, policy_digest({}), {}),
        AssessmentResult("b", uuid4(), ApplicabilityStatus.APPLICABLE, AssessmentMethod.MANUAL, ImplementationStatus.MANUAL, None, None, policy_digest({}), {}),
        AssessmentResult("c", uuid4(), ApplicabilityStatus.APPLICABLE, AssessmentMethod.AUTOMATIC, ImplementationStatus.UNIMPLEMENTED, None, None, policy_digest({}), {}),
        AssessmentResult("d", uuid4(), ApplicabilityStatus.NOT_APPLICABLE, AssessmentMethod.AUTOMATIC, ImplementationStatus.IMPLEMENTED, None, None, policy_digest({}), {}),
        AssessmentResult("e", uuid4(), ApplicabilityStatus.UNKNOWN, AssessmentMethod.AUTOMATIC, ImplementationStatus.IMPLEMENTED, "unknown", None, policy_digest({}), {}),
    ]
    assert coverage_summary(results) == {
        "selected_obligation_count": 5, "applicable": 3, "not_applicable": 1,
        "applicability_unknown": 1, "automatic_implemented": 3, "manual": 1,
        "unimplemented": 1, "automatic_verdicts": {"pass": 1, "fail": 0, "unknown": 1},
        "automatic": 3, "pass": 1, "fail": 0, "unknown": 1,
    }


def test_policy_digest_distinguishes_same_rule_with_different_parameters():
    assert policy_digest({"expected": True}) != policy_digest({"expected": False})


@pytest.mark.parametrize(("profile", "field", "expected"), [
    ("cisco.ios_xe.17@1.0.0", "management.remote.ssh.version", True),
    ("fortinet.fortios.7@1.0.0", "management.remote.ssh.version", False),
    ("juniper.junos.18@1.0.0", "logging.remote.destination", True),
    ("arista.eos.4@1.0.0", "logging.enabled", False),
])
def test_automatic_obligations_require_profile_supported_canonical_evidence(profile, field, expected):
    obligation = SimpleNamespace(policy_parameters={"required_canonical_fields": [field]})
    assert _automatic_evidence_supported(obligation, profile) is expected


def test_assessment_pack_registry_validates_persisted_version_identity():
    profile = "cisco.ios_xe.17@1.0.0"
    row = SimpleNamespace(
        schema_version="1.0.0", assessment_pack_version_id=uuid4(),
        pack_key="pack", family="family", name="name", version=1,
        profile_version_ids=[profile], applicability={"profile_version_ids": [profile]},
        content_digest="a" * 64,
        source_metadata={"official_source_url": "https://example.invalid/catalog", "source_sha256": "b" * 64},
    )
    assert AssessmentPackRegistry.validate(row) is row
    row.applicability = {"profile_version_ids": ["other"]}
    with pytest.raises(AssessmentPackError, match="invalid"):
        AssessmentPackRegistry.validate(row)
