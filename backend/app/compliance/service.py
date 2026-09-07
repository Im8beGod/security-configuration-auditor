from __future__ import annotations

from collections import defaultdict
from typing import Iterable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.compliance.applicability import determine_applicability
from app.compliance.evaluator import EvaluationError, evaluate_condition
from app.compliance.models import (
    ApplicabilityStatus, FindingDraft, OrganizationPolicyVersion, RuleDefinition,
    RulePack, canonical_scope_key, comparison_key, deterministic_finding_id,
)
from app.compliance.policy import resolve_parameter
from app.compliance.verdicts import FindingVerdict
from app.db.models import Audit, AuditStatus, EffectiveState, Finding
from app.effective_state.contracts import ResolutionStatus, UnresolvedReason
from app.security_model import ScopeRef


class ComplianceError(ValueError):
    pass


def _scope(state: EffectiveState) -> ScopeRef:
    data = state.scope
    return ScopeRef(data["type"], data["key"], data.get("attributes", {}))


def _expected(rule: RuleDefinition, parameter: object | None) -> dict[str, object] | None:
    if "expected" in rule.condition:
        return {"operator": rule.condition["operator"], "value": rule.condition["expected"]}
    if parameter is not None:
        return {"operator": rule.condition["operator"], "parameter": rule.condition.get("parameter"), "value": parameter}
    return {"operator": rule.condition["operator"]}


def _explanation(verdict: FindingVerdict, rule: RuleDefinition, observed: dict | None, reason: UnresolvedReason | None) -> str:
    if verdict is FindingVerdict.UNKNOWN:
        return f"The required EffectiveState is unresolved because {reason.value.replace('_', ' ')}."
    if verdict is FindingVerdict.MANUAL_REVIEW:
        return "The required organization policy parameter is unavailable."
    if verdict is FindingVerdict.NOT_APPLICABLE:
        return "This technical baseline does not apply to the resolved device profile."
    if verdict is FindingVerdict.PROCESS_ERROR:
        return "Deterministic evaluation could not validate the canonical EffectiveState contract."
    actual = None if observed is None else observed.get("value")
    return f"Observed canonical value is {actual!r}; rule {rule.condition['operator']} {'satisfied' if verdict is FindingVerdict.PASS else 'not satisfied'}."


def _draft(rule: RuleDefinition, pack: RulePack, audit: Audit, *, verdict: FindingVerdict,
           scope: ScopeRef | None, states: tuple[EffectiveState, ...] = (), observed: dict | None = None,
           expected: dict | None = None, reason: UnresolvedReason | None = None) -> FindingDraft:
    return FindingDraft(
        finding_id=deterministic_finding_id(audit.audit_id, rule.rule_id, scope), audit_id=audit.audit_id,
        device_id=audit.device_id, comparison_key=comparison_key(rule.rule_id, scope), rule_id=rule.rule_id,
        rule_pack_version_id=pack.rule_pack_version_id, title=rule.title, security_domain=rule.security_domain,
        verdict=verdict, severity=rule.severity, expected_state=expected, observed_state=observed,
        explanation=_explanation(verdict, rule, observed, reason), affected_scope=scope,
        effective_state_refs=tuple(state.effective_state_id for state in states), evidence_refs=(),
        unknown_reason=reason, framework_references=rule.framework_references,
    )


def evaluate_audit_compliance(
    db: Session, *, audit_id: UUID, organization_id: UUID, rule_pack: RulePack,
    organization_policy: OrganizationPolicyVersion | None,
    effective_states: tuple[EffectiveState, ...] | None = None,
) -> tuple[FindingDraft, ...]:
    """Evaluate persisted EffectiveStates only; no parser or SecurityFact dependency exists here."""
    audit = db.scalar(select(Audit).where(Audit.audit_id == audit_id, Audit.organization_id == organization_id))
    if audit is None:
        raise ComplianceError("Audit was not found")
    if audit.status is not AuditStatus.PROCESSING:
        raise ComplianceError("Only still-processing Audits are eligible for compliance evaluation")
    if organization_policy is not None and organization_policy.organization_id != organization_id:
        raise ComplianceError("Organization policy crosses the Audit boundary")
    states = effective_states if effective_states is not None else tuple(db.scalars(
        select(EffectiveState).where(EffectiveState.audit_id == audit_id).order_by(
            EffectiveState.field_id, EffectiveState.scope_key
        )
    ))
    by_field: dict[str, list[EffectiveState]] = defaultdict(list)
    for state in states:
        if state.device_id != audit.device_id:
            raise ComplianceError("EffectiveState crosses the Audit boundary")
        by_field[state.field_id].append(state)
    applicability = determine_applicability(audit, rule_pack)
    drafts: list[FindingDraft] = []
    for rule in rule_pack.rules:
        if applicability.status is ApplicabilityStatus.NOT_APPLICABLE:
            drafts.append(_draft(rule, rule_pack, audit, verdict=FindingVerdict.NOT_APPLICABLE, scope=None))
            continue
        if applicability.status is ApplicabilityStatus.UNRESOLVED:
            drafts.append(_draft(rule, rule_pack, audit, verdict=FindingVerdict.UNKNOWN, scope=None, reason=applicability.reason))
            continue
        field_states = by_field[rule.required_effective_states[0]]
        if not field_states:
            drafts.append(_draft(rule, rule_pack, audit, verdict=FindingVerdict.UNKNOWN, scope=None, reason=UnresolvedReason.MISSING_EVIDENCE))
            continue
        for state in field_states:
            scope = _scope(state)
            if state.resolution_status is not ResolutionStatus.RESOLVED:
                reason = UnresolvedReason.CONFLICTING_EVIDENCE if state.resolution_status is ResolutionStatus.CONFLICTING else state.unresolved_reason
                drafts.append(_draft(rule, rule_pack, audit, verdict=FindingVerdict.UNKNOWN, scope=scope, states=(state,), reason=reason))
                continue
            parameter = resolve_parameter(organization_policy, rule.condition.get("parameter", "")) if rule.required_policy_parameters else None
            if rule.required_policy_parameters and parameter is None:
                drafts.append(_draft(rule, rule_pack, audit, verdict=FindingVerdict.MANUAL_REVIEW, scope=scope, states=(state,), observed=state.effective_value, expected=_expected(rule, None)))
                continue
            try:
                verdict = evaluate_condition(rule, state.effective_value, parameter)
                drafts.append(_draft(rule, rule_pack, audit, verdict=verdict, scope=scope, states=(state,), observed=state.effective_value, expected=_expected(rule, parameter)))
            except EvaluationError:
                drafts.append(_draft(rule, rule_pack, audit, verdict=FindingVerdict.PROCESS_ERROR, scope=scope, states=(state,), observed=state.effective_value))
    return tuple(drafts)


def persist_audit_findings(db: Session, *, audit_id: UUID, organization_id: UUID,
                           rule_pack: RulePack, organization_policy: OrganizationPolicyVersion | None,
                           effective_states: tuple[EffectiveState, ...] | None = None) -> tuple[Finding, ...]:
    drafts = evaluate_audit_compliance(
        db, audit_id=audit_id, organization_id=organization_id, rule_pack=rule_pack,
        organization_policy=organization_policy, effective_states=effective_states,
    )
    audit = db.scalar(select(Audit).where(Audit.audit_id == audit_id, Audit.organization_id == organization_id).with_for_update())
    if audit is None or audit.status is not AuditStatus.PROCESSING:
        raise ComplianceError("Only still-processing Audits are eligible for Finding persistence")
    for finding in db.scalars(select(Finding).where(Finding.audit_id == audit_id)):
        db.delete(finding)
    db.flush()
    findings = tuple(Finding(
        finding_id=draft.finding_id, audit_id=draft.audit_id, device_id=draft.device_id,
        comparison_key=draft.comparison_key, rule_id=draft.rule_id, rule_pack_version_id=draft.rule_pack_version_id,
        title=draft.title, security_domain=draft.security_domain, verdict=draft.verdict, severity=draft.severity,
        expected_state=draft.expected_state, observed_state=draft.observed_state, explanation=draft.explanation,
        affected_scope=draft.affected_scope.to_dict() if draft.affected_scope else None,
        effective_state_refs=[str(item) for item in draft.effective_state_refs], evidence_refs=list(draft.evidence_refs),
        unknown_reason=draft.unknown_reason, framework_references=list(draft.framework_references),
        remediation_procedure_id=None, schema_version=draft.schema_version,
    ) for draft in drafts)
    db.add_all(findings)
    db.flush()
    # The coordinator owns its checkpoint commit; return stable read-only results.
    for finding in findings:
        db.expunge(finding)
    return findings
