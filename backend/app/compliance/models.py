from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping
from uuid import UUID, uuid5

from app.compliance.verdicts import FindingSeverity, FindingVerdict
from app.effective_state.contracts import UnresolvedReason
from app.security_model import ScopeRef


FINDING_NAMESPACE = UUID("f523ecac-29ae-5ed3-88f8-59a30521f8fe")
RULE_PACK_NAMESPACE = UUID("753fcba1-4141-58c9-a75a-323c1a8b4acb")
POLICY_NAMESPACE = UUID("d4b44bbc-c35e-57fb-9e17-7b2f933f8972")
UNSCOPED_SCOPE_KEY = "unscoped::rule"


class ApplicabilityStatus(str, Enum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class ApplicabilityResult:
    status: ApplicabilityStatus
    reason: UnresolvedReason | None = None


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    title: str
    description: str
    security_domain: str
    severity: FindingSeverity
    severity_reason: str
    applicability: Mapping[str, Any]
    required_effective_states: tuple[str, ...]
    condition: Mapping[str, Any]
    required_policy_parameters: tuple[str, ...]
    framework_references: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class RulePack:
    rule_pack_version_id: UUID
    name: str
    version: str
    profile_version_id: str
    rules: tuple[RuleDefinition, ...]
    schema_version: str = "1.0.0"


@dataclass(frozen=True)
class OrganizationPolicyVersion:
    organization_id: UUID
    organization_policy_version_id: UUID
    name: str
    version: str
    parameters: Mapping[str, Any]
    schema_version: str = "1.0.0"


@dataclass(frozen=True)
class FindingDraft:
    finding_id: UUID
    audit_id: UUID
    device_id: UUID
    comparison_key: str
    rule_id: str
    rule_pack_version_id: UUID
    title: str
    security_domain: str
    verdict: FindingVerdict
    severity: FindingSeverity
    expected_state: dict[str, Any] | None
    observed_state: dict[str, Any] | None
    explanation: str
    affected_scope: ScopeRef | None
    effective_state_refs: tuple[UUID, ...]
    evidence_refs: tuple[dict[str, Any], ...]
    unknown_reason: UnresolvedReason | None
    framework_references: tuple[dict[str, Any], ...]
    remediation_procedure_id: UUID | None = None
    schema_version: str = "1.0.0"


def canonical_scope_key(scope: ScopeRef | None) -> str:
    return UNSCOPED_SCOPE_KEY if scope is None else f"{scope.type}::{scope.key}"


def deterministic_finding_id(audit_id: UUID, rule_id: str, scope: ScopeRef | None) -> UUID:
    if not isinstance(audit_id, UUID) or audit_id.int == 0 or not rule_id.strip():
        raise ValueError("Finding identity is malformed")
    return uuid5(FINDING_NAMESPACE, f"{audit_id}:{rule_id}:{canonical_scope_key(scope)}")


def comparison_key(rule_id: str, scope: ScopeRef | None) -> str:
    if not rule_id.strip():
        raise ValueError("Finding comparison key is malformed")
    return f"{rule_id}::{canonical_scope_key(scope)}"


def deterministic_policy_version_id(
    organization_id: UUID, name: str, version: str, parameters: Mapping[str, Any]
) -> UUID:
    payload = json.dumps(dict(parameters), sort_keys=True, separators=(",", ":"))
    return uuid5(POLICY_NAMESPACE, f"{organization_id}:{name}:{version}:{payload}")
