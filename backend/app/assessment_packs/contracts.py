from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Mapping
from uuid import UUID


class AssessmentMethod(str, Enum):
    AUTOMATIC = "automatic"
    MANUAL = "manual"


class ImplementationStatus(str, Enum):
    IMPLEMENTED = "implemented"
    MANUAL = "manual"
    UNIMPLEMENTED = "unimplemented"


class ApplicabilityStatus(str, Enum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "applicability_unknown"


def policy_digest(parameters: Mapping[str, Any]) -> str:
    payload = json.dumps(dict(parameters), sort_keys=True, separators=(",", ":"), default=str)
    return sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AssessmentPackVersion:
    assessment_pack_version_id: UUID
    pack_key: str
    family: str
    name: str
    version: int
    profile_version_ids: tuple[str, ...]
    source_metadata: Mapping[str, Any]
    source_version_label: str
    content_digest: str
    applicability: Mapping[str, Any]
    status: str = "published"

    def __post_init__(self) -> None:
        if not self.pack_key.strip() or not self.family.strip() or not self.name.strip():
            raise ValueError("Assessment Pack identity is required")
        if self.version < 1 or not self.profile_version_ids:
            raise ValueError("Assessment Pack version or applicability is invalid")
        if len(self.content_digest) != 64:
            raise ValueError("Assessment Pack content digest is invalid")
        object.__setattr__(self, "source_metadata", MappingProxyType(dict(self.source_metadata)))
        object.__setattr__(self, "applicability", MappingProxyType(dict(self.applicability)))


@dataclass(frozen=True)
class AssessmentObligation:
    assessment_obligation_id: UUID
    obligation_key: str
    title: str
    applicability: Mapping[str, Any]
    assessment_method: AssessmentMethod
    implementation_status: ImplementationStatus
    evaluator_rule_id: str | None
    policy_parameters: Mapping[str, Any]
    source_reference: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.obligation_key.strip() or not self.title.strip():
            raise ValueError("Assessment obligation identity is required")
        if self.assessment_method is AssessmentMethod.AUTOMATIC and self.implementation_status is ImplementationStatus.IMPLEMENTED and not self.evaluator_rule_id:
            raise ValueError("Implemented automatic obligations require an evaluator binding")
        object.__setattr__(self, "applicability", MappingProxyType(dict(self.applicability)))
        object.__setattr__(self, "policy_parameters", MappingProxyType(dict(self.policy_parameters)))
        object.__setattr__(self, "source_reference", MappingProxyType(dict(self.source_reference)))


@dataclass(frozen=True)
class AssessmentResult:
    result_identity: str
    obligation_id: UUID
    applicability_status: ApplicabilityStatus
    assessment_method: AssessmentMethod
    implementation_status: ImplementationStatus
    verdict: str | None
    technical_finding_id: UUID | None
    policy_digest: str
    details: Mapping[str, Any]


def coverage_summary(results: tuple[AssessmentResult, ...] | list[AssessmentResult]) -> dict[str, Any]:
    counts = {
        "selected_obligation_count": len(results),
        "applicable": 0,
        "not_applicable": 0,
        "applicability_unknown": 0,
        "automatic_implemented": 0,
        "manual": 0,
        "unimplemented": 0,
        "automatic_verdicts": {"pass": 0, "fail": 0, "unknown": 0},
    }
    for result in results:
        counts[result.applicability_status.value] += 1
        if result.implementation_status is ImplementationStatus.IMPLEMENTED and result.assessment_method is AssessmentMethod.AUTOMATIC:
            counts["automatic_implemented"] += 1
            if result.verdict in counts["automatic_verdicts"]:
                counts["automatic_verdicts"][result.verdict] += 1
        elif result.implementation_status is ImplementationStatus.MANUAL or result.assessment_method is AssessmentMethod.MANUAL:
            counts["manual"] += 1
        elif result.implementation_status is ImplementationStatus.UNIMPLEMENTED:
            counts["unimplemented"] += 1
    return counts
