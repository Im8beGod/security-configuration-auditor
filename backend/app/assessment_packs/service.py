from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.assessment_packs.contracts import (
    ApplicabilityStatus, AssessmentMethod, AssessmentResult, ImplementationStatus,
    coverage_summary, policy_digest,
)
from app.compliance.evaluator import EvaluationError, evaluate_condition
from app.compliance.models import RuleDefinition
from app.compliance.rule_registry import RULE_REGISTRY
from app.compliance.verdicts import FindingVerdict
from app.db.models import (
    AssessmentObligation as AssessmentObligationRow,
    AssessmentPackVersion as AssessmentPackVersionRow,
    AssessmentResult as AssessmentResultRow,
    Audit, AuditAssessment, EffectiveState, Finding,
)
from app.effective_state.contracts import ResolutionStatus, UnresolvedReason


class AssessmentPackError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def _visible(statement, organization_id: UUID):
    return statement.where(
        (AssessmentPackVersionRow.organization_id == organization_id)
        | (AssessmentPackVersionRow.organization_id.is_(None))
    )


def get_pack(db: Session, organization_id: UUID, pack_id: UUID) -> AssessmentPackVersionRow:
    pack = db.scalar(_visible(select(AssessmentPackVersionRow).where(
        AssessmentPackVersionRow.assessment_pack_version_id == pack_id,
    ), organization_id))
    if pack is None:
        raise AssessmentPackError("assessment_pack_not_found", "Assessment Pack is not available")
    return pack


def compatible_packs(db: Session, organization_id: UUID, profile_version_id: str) -> list[AssessmentPackVersionRow]:
    packs = list(db.scalars(_visible(select(AssessmentPackVersionRow).where(
        AssessmentPackVersionRow.status == "published",
    ), organization_id)))
    return sorted(
        [item for item in packs if profile_version_id in (item.profile_version_ids or [])],
        key=lambda item: (item.family, item.name, item.version, str(item.assessment_pack_version_id)),
    )


def validate_requested_pack(db: Session, organization_id: UUID, pack_id: UUID) -> AssessmentPackVersionRow:
    pack = get_pack(db, organization_id, pack_id)
    if pack.status != "published":
        raise AssessmentPackError("assessment_pack_unavailable", "Assessment Pack is not published")
    return pack


def _obligation(row: AssessmentObligationRow):
    return row


def pin_assessment(db: Session, audit: Audit, profile_version_id: str) -> AuditAssessment | None:
    requested = (audit.version_refs or {}).get("assessment_pack_version_id")
    if requested is None:
        return None
    try:
        pack_id = UUID(str(requested))
    except (TypeError, ValueError):
        raise AssessmentPackError("assessment_pack_invalid", "Selected Assessment Pack identity is invalid") from None
    pack = validate_requested_pack(db, audit.organization_id, pack_id)
    if profile_version_id not in (pack.profile_version_ids or []):
        raise AssessmentPackError("assessment_pack_incompatible", "Selected Assessment Pack is incompatible with the resolved device profile")
    existing = db.get(AuditAssessment, audit.audit_id)
    identity = {
        "assessment_pack_version_id": str(pack.assessment_pack_version_id),
        "pack_key": pack.pack_key,
        "family": pack.family,
        "name": pack.name,
        "version": pack.version,
        "source_version_label": pack.source_version_label,
        "content_digest": pack.content_digest,
    }
    if existing is not None:
        if existing.assessment_pack_version_id != pack.assessment_pack_version_id or existing.profile_version_id != profile_version_id:
            raise AssessmentPackError("assessment_pack_conflict", "Audit Assessment Pack pin cannot change")
        return existing
    pinned = AuditAssessment(
        audit_id=audit.audit_id, organization_id=audit.organization_id,
        assessment_pack_version_id=pack.assessment_pack_version_id,
        profile_version_id=profile_version_id, pinned_identity=identity,
    )
    db.add(pinned)
    db.flush()
    return pinned


def _rule_for(rule_id: str, profile_version_id: str) -> RuleDefinition:
    from app.compliance.rule_registry import RULE_PACK_BY_PROFILE
    pack = RULE_PACK_BY_PROFILE.get(profile_version_id)
    if pack is None:
        raise AssessmentPackError("assessment_evaluator_unavailable", "Assessment evaluator is unavailable for this profile")
    for rule in pack.rules:
        if rule.rule_id == rule_id:
            return rule
    raise AssessmentPackError("assessment_evaluator_unavailable", "Assessment evaluator binding is unavailable")


def _result_identity(obligation: AssessmentObligationRow) -> tuple[str, str]:
    digest = policy_digest(obligation.policy_parameters or {})
    return f"{obligation.obligation_key}:{digest}", digest


def persist_assessment_results(
    db: Session, *, audit_id: UUID, organization_id: UUID,
    profile_version_id: str, findings: tuple[Finding, ...] | list[Finding],
) -> dict[str, Any] | None:
    audit = db.scalar(select(Audit).where(Audit.audit_id == audit_id, Audit.organization_id == organization_id).with_for_update())
    if audit is None:
        raise AssessmentPackError("audit_not_found", "Audit was not found")
    pinned = db.get(AuditAssessment, audit_id)
    if pinned is None:
        return None
    pack = db.scalar(select(AssessmentPackVersionRow).where(
        AssessmentPackVersionRow.assessment_pack_version_id == pinned.assessment_pack_version_id,
    ))
    if pack is None or pack.organization_id not in {None, organization_id}:
        raise AssessmentPackError("assessment_pack_not_found", "Pinned Assessment Pack is unavailable")
    obligations = list(db.scalars(select(AssessmentObligationRow).where(
        AssessmentObligationRow.assessment_pack_version_id == pack.assessment_pack_version_id,
    ).order_by(AssessmentObligationRow.obligation_key)))
    states = list(db.scalars(select(EffectiveState).where(
        EffectiveState.audit_id == audit_id,
    ).order_by(EffectiveState.field_id, EffectiveState.scope_key)))
    finding_by_rule = {}
    for finding in findings:
        finding_by_rule.setdefault(finding.rule_id, finding)
    db.execute(delete(AssessmentResultRow).where(AssessmentResultRow.audit_id == audit_id))
    results: list[AssessmentResult] = []
    for obligation in obligations:
        identity, digest = _result_identity(obligation)
        profiles = (obligation.applicability or {}).get("profile_version_ids", pack.profile_version_ids or [])
        applicability = ApplicabilityStatus.APPLICABLE if profile_version_id in profiles else ApplicabilityStatus.NOT_APPLICABLE
        verdict = None
        finding_id = None
        details: dict[str, Any] = {"title": obligation.title}
        if applicability is ApplicabilityStatus.APPLICABLE and obligation.implementation_status == ImplementationStatus.IMPLEMENTED.value and obligation.assessment_method == AssessmentMethod.AUTOMATIC.value:
            rule = _rule_for(obligation.evaluator_rule_id or "", profile_version_id)
            field_states = [state for state in states if state.field_id in rule.required_effective_states]
            finding = finding_by_rule.get(rule.rule_id)
            finding_id = finding.finding_id if finding else None
            if not field_states:
                verdict = FindingVerdict.UNKNOWN.value
                details["unknown_reason"] = UnresolvedReason.MISSING_EVIDENCE.value
            elif len(field_states) != 1:
                # A pack obligation is never allowed to turn several native scopes
                # into one device-wide claim by selecting an arbitrary state.
                verdict = FindingVerdict.UNKNOWN.value
                details["unknown_reason"] = UnresolvedReason.AMBIGUOUS_SCOPE.value
            else:
                state = field_states[0]
                details["effective_state"] = {
                    "field_id": state.field_id,
                    "scope": state.scope,
                    "value": state.effective_value,
                    "resolution_status": state.resolution_status.value,
                    "source_fact_ids": [str(item) for item in state.source_fact_ids],
                    "resolution_trace": state.resolution_trace,
                }
                if state.resolution_status is not ResolutionStatus.RESOLVED:
                    verdict = FindingVerdict.UNKNOWN.value
                    reason = state.unresolved_reason or UnresolvedReason.CONFLICTING_EVIDENCE
                    details["unknown_reason"] = reason.value if isinstance(reason, UnresolvedReason) else str(reason)
                else:
                    condition = dict(rule.condition)
                    if "expected" in obligation.policy_parameters:
                        condition["expected"] = obligation.policy_parameters["expected"]
                    try:
                        parameter = obligation.policy_parameters.get(condition.get("parameter")) if condition.get("parameter") else None
                        verdict = evaluate_condition(replace(rule, condition=condition), state.effective_value, parameter).value
                    except EvaluationError:
                        verdict = FindingVerdict.UNKNOWN.value
                        details["unknown_reason"] = "assessment_evaluation_error"
        elif applicability is ApplicabilityStatus.APPLICABLE and obligation.implementation_status == ImplementationStatus.MANUAL.value:
            details["state"] = "manual"
        elif applicability is ApplicabilityStatus.APPLICABLE and obligation.implementation_status == ImplementationStatus.UNIMPLEMENTED.value:
            details["state"] = "unimplemented"
        result = AssessmentResult(
            result_identity=identity, obligation_id=obligation.assessment_obligation_id,
            applicability_status=applicability, assessment_method=AssessmentMethod(obligation.assessment_method),
            implementation_status=ImplementationStatus(obligation.implementation_status), verdict=verdict,
            technical_finding_id=finding_id, policy_digest=digest, details=details,
        )
        results.append(result)
        db.add(AssessmentResultRow(
            audit_id=audit_id, organization_id=organization_id,
            assessment_obligation_id=obligation.assessment_obligation_id,
            technical_finding_id=finding_id, result_identity=identity,
            applicability_status=applicability.value, assessment_method=obligation.assessment_method,
            implementation_status=obligation.implementation_status, verdict=verdict,
            policy_digest=digest, result_details=details,
        ))
    coverage = coverage_summary(results)
    coverage["assessment_pack"] = {
        "assessment_pack_version_id": str(pack.assessment_pack_version_id),
        "family": pack.family, "name": pack.name, "version": pack.version,
        "source_version_label": pack.source_version_label, "content_digest": pack.content_digest,
    }
    audit.coverage = coverage
    db.flush()
    return coverage
