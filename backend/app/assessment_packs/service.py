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
from app.assessment_packs.catalog import validate_persisted_obligation
from app.compliance.evaluator import EvaluationError, evaluate_condition
from app.compliance.models import RuleDefinition
from app.compliance.rule_registry import RULE_REGISTRY
from app.compliance.verdicts import FindingVerdict
from app.db.models import (
    AssessmentObligation as AssessmentObligationRow,
    AssessmentPackVersion as AssessmentPackVersionRow,
    AssessmentResult as AssessmentResultRow,
    Audit, AuditAssessment, AuditFrameworkAssessment, EffectiveState, Finding,
    SecurityFact,
)
from app.effective_state.contracts import ResolutionStatus, UnresolvedReason


class AssessmentPackError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


class AssessmentPackRegistry:
    """Validated lookup boundary for immutable persisted AssessmentPack versions."""

    SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0.0"})

    @classmethod
    def validate(cls, pack: AssessmentPackVersionRow) -> AssessmentPackVersionRow:
        profiles = pack.profile_version_ids
        applicability_profiles = (pack.applicability or {}).get("profile_version_ids")
        source = getattr(pack, "source_metadata", None) or {}
        source_url = source.get("official_source_url") or source.get("source_url") or source.get("iso_open_data_url")
        source_digest = source.get("source_sha256") or source.get("olir_sha3_256")
        source_invalid = pack.family != "TEST/INFRASTRUCTURE" and (
            not isinstance(source_url, str) or not source_url.startswith("https://")
            or not isinstance(source_digest, str) or len(source_digest) < 32
        )
        if (
            getattr(pack, "schema_version", None) not in cls.SUPPORTED_SCHEMA_VERSIONS
            or not isinstance(pack.assessment_pack_version_id, UUID)
            or pack.assessment_pack_version_id.int == 0
            or not pack.pack_key.strip()
            or not pack.family.strip()
            or not pack.name.strip()
            or pack.version < 1
            or not isinstance(profiles, list)
            or not profiles
            or any(not isinstance(item, str) or not item.strip() for item in profiles)
            or not isinstance(applicability_profiles, list)
            or set(applicability_profiles) != set(profiles)
            or not isinstance(pack.content_digest, str)
            or len(pack.content_digest) != 64
            or any(character not in "0123456789abcdef" for character in pack.content_digest.lower())
            or source_invalid
        ):
            raise AssessmentPackError(
                "assessment_pack_invalid", "Assessment Pack registry entry is invalid"
            )
        return pack

    def get(
        self, db: Session, organization_id: UUID, pack_id: UUID
    ) -> AssessmentPackVersionRow:
        pack = db.scalar(_visible(select(AssessmentPackVersionRow).where(
            AssessmentPackVersionRow.assessment_pack_version_id == pack_id,
        ), organization_id))
        if pack is None:
            raise AssessmentPackError(
                "assessment_pack_not_found", "Assessment Pack is not available"
            )
        return self.validate(pack)

    def compatible(
        self, db: Session, organization_id: UUID, profile_version_id: str
    ) -> list[AssessmentPackVersionRow]:
        packs = list(db.scalars(_visible(select(AssessmentPackVersionRow).where(
            AssessmentPackVersionRow.status == "published",
        ), organization_id)))
        validated = [self.validate(pack) for pack in packs]
        return sorted(
            [item for item in validated if profile_version_id in item.profile_version_ids],
            key=lambda item: (
                item.family, item.name, item.version,
                str(item.assessment_pack_version_id),
            ),
        )


ASSESSMENT_PACK_REGISTRY = AssessmentPackRegistry()

FRAMEWORK_FAMILIES = {
    "cis": "CIS Benchmark",
    "cis_benchmarks": "CIS Benchmark",
    "cis benchmarks": "CIS Benchmark",
    "nist": "NIST SP 800-53",
    "nist_sp_800_53": "NIST SP 800-53",
    "nist sp 800-53": "NIST SP 800-53",
    "disa": "DISA SRG",
    "disa_stig_srg": "DISA SRG",
    "disa stig/srg": "DISA SRG",
    "iso": "ISO/IEC 27001 Alignment",
    "iso_iec_27001": "ISO/IEC 27001 Alignment",
    "iso/iec 27001": "ISO/IEC 27001 Alignment",
}


def _visible(statement, organization_id: UUID):
    return statement.where(
        (AssessmentPackVersionRow.organization_id == organization_id)
        | (AssessmentPackVersionRow.organization_id.is_(None))
    )


def get_pack(db: Session, organization_id: UUID, pack_id: UUID) -> AssessmentPackVersionRow:
    return ASSESSMENT_PACK_REGISTRY.get(db, organization_id, pack_id)


def compatible_packs(db: Session, organization_id: UUID, profile_version_id: str) -> list[AssessmentPackVersionRow]:
    return ASSESSMENT_PACK_REGISTRY.compatible(
        db, organization_id, profile_version_id
    )


def validate_requested_pack(db: Session, organization_id: UUID, pack_id: UUID) -> AssessmentPackVersionRow:
    pack = get_pack(db, organization_id, pack_id)
    if pack.status != "published":
        raise AssessmentPackError("assessment_pack_unavailable", "Assessment Pack is not published")
    return pack


def _obligation(row: AssessmentObligationRow):
    return row


def pin_assessment(db: Session, audit: Audit, profile_version_id: str) -> AuditAssessment | AuditFrameworkAssessment | None:
    requested = (audit.version_refs or {}).get("assessment_pack_version_id")
    selected: list[AssessmentPackVersionRow] = []
    if requested is not None:
        try:
            pack_id = UUID(str(requested))
        except (TypeError, ValueError):
            raise AssessmentPackError("assessment_pack_invalid", "Selected Assessment Pack identity is invalid") from None
        selected = [validate_requested_pack(db, audit.organization_id, pack_id)]
    elif audit.selected_frameworks:
        compatible = compatible_packs(db, audit.organization_id, profile_version_id)
        seen_families: set[str] = set()
        for requested_family in audit.selected_frameworks:
            family = FRAMEWORK_FAMILIES.get(requested_family.strip().lower())
            if family is None:
                raise AssessmentPackError("framework_unsupported", f"Unsupported framework selection: {requested_family}")
            if family in seen_families:
                raise AssessmentPackError("framework_duplicate", f"Framework selected more than once: {family}")
            seen_families.add(family)
            candidates = [item for item in compatible if item.family == family]
            if not candidates:
                raise AssessmentPackError("assessment_pack_incompatible", f"No compatible {family} catalog is available")
            selected.append(max(candidates, key=lambda item: (item.version, item.published_at or item.created_at)))
    else:
        return None
    if any(profile_version_id not in (pack.profile_version_ids or []) for pack in selected):
        raise AssessmentPackError("assessment_pack_incompatible", "Selected Assessment Pack is incompatible with the resolved device profile")
    first = None
    for pack in selected:
        identity = {
            "assessment_pack_version_id": str(pack.assessment_pack_version_id),
            "pack_key": pack.pack_key, "family": pack.family, "name": pack.name,
            "version": pack.version, "source_version_label": pack.source_version_label,
            "content_digest": pack.content_digest, "source_metadata": pack.source_metadata,
        }
        if requested is not None:
            existing = db.get(AuditAssessment, audit.audit_id)
            if existing is None:
                existing = AuditAssessment(audit_id=audit.audit_id, organization_id=audit.organization_id, assessment_pack_version_id=pack.assessment_pack_version_id, profile_version_id=profile_version_id, pinned_identity=identity)
                db.add(existing)
            elif existing.assessment_pack_version_id != pack.assessment_pack_version_id or existing.profile_version_id != profile_version_id:
                raise AssessmentPackError("assessment_pack_conflict", "Audit Assessment Pack pin cannot change")
        else:
            existing = db.scalar(select(AuditFrameworkAssessment).where(AuditFrameworkAssessment.audit_id == audit.audit_id, AuditFrameworkAssessment.assessment_pack_version_id == pack.assessment_pack_version_id))
            if existing is None:
                existing = AuditFrameworkAssessment(audit_id=audit.audit_id, organization_id=audit.organization_id, assessment_pack_version_id=pack.assessment_pack_version_id, profile_version_id=profile_version_id, pinned_identity=identity)
                db.add(existing)
        first = first or existing
    audit.version_refs = {**(audit.version_refs or {}), "assessment_pack_version_ids": [str(item.assessment_pack_version_id) for item in selected]}
    db.flush()
    return first


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
    framework_pins = list(db.scalars(select(AuditFrameworkAssessment).where(AuditFrameworkAssessment.audit_id == audit_id)))
    legacy_pin = db.get(AuditAssessment, audit_id)
    pack_ids = [item.assessment_pack_version_id for item in framework_pins]
    if legacy_pin is not None:
        pack_ids.append(legacy_pin.assessment_pack_version_id)
    if not pack_ids:
        return None
    packs = list(db.scalars(select(AssessmentPackVersionRow).where(AssessmentPackVersionRow.assessment_pack_version_id.in_(pack_ids))))
    if len(packs) != len(set(pack_ids)) or any(pack.organization_id not in {None, organization_id} for pack in packs):
        raise AssessmentPackError("assessment_pack_not_found", "Pinned Assessment Pack is unavailable")
    for pack in packs:
        ASSESSMENT_PACK_REGISTRY.validate(pack)
    pack_by_id = {item.assessment_pack_version_id: item for item in packs}
    obligations = list(db.scalars(select(AssessmentObligationRow).where(
        AssessmentObligationRow.assessment_pack_version_id.in_(pack_ids),
    ).order_by(AssessmentObligationRow.obligation_key)))
    states = list(db.scalars(select(EffectiveState).where(
        EffectiveState.audit_id == audit_id,
    ).order_by(EffectiveState.field_id, EffectiveState.scope_key)))
    fact_ids = {
        UUID(str(fact_id)) for state in states for fact_id in state.source_fact_ids
    }
    facts = list(db.scalars(select(SecurityFact).where(
        SecurityFact.audit_id == audit_id,
        SecurityFact.fact_id.in_(fact_ids),
    ))) if fact_ids else []
    evidence_by_fact = {str(fact.fact_id): fact.evidence_refs for fact in facts}

    def state_evidence(state: EffectiveState) -> list[dict[str, Any]]:
        unique: dict[str, dict[str, Any]] = {}
        for fact_id in state.source_fact_ids:
            for reference in evidence_by_fact.get(str(fact_id), []):
                if isinstance(reference, dict):
                    unique[repr(sorted(reference.items()))] = reference
        return list(unique.values())
    findings_by_rule: dict[str, list[Finding]] = {}
    for finding in findings:
        findings_by_rule.setdefault(finding.rule_id, []).append(finding)
    db.execute(delete(AssessmentResultRow).where(AssessmentResultRow.audit_id == audit_id))
    results: list[AssessmentResult] = []
    for obligation in obligations:
        pack = pack_by_id[obligation.assessment_pack_version_id]
        if pack.family != "TEST/INFRASTRUCTURE":
            try:
                validate_persisted_obligation(obligation)
            except ValueError:
                raise AssessmentPackError("assessment_catalog_invalid", "Catalog obligation provenance is invalid") from None
        identity, digest = _result_identity(obligation)
        if len(packs) > 1:
            identity = f"{pack.pack_key}:{identity}"
        profiles = (obligation.applicability or {}).get("profile_version_ids", pack.profile_version_ids or [])
        applicability = ApplicabilityStatus.APPLICABLE if profile_version_id in profiles else ApplicabilityStatus.NOT_APPLICABLE
        verdict = None
        finding_id = None
        details: dict[str, Any] = {
            "title": obligation.title, "framework": pack.family,
            "framework_version": obligation.framework_version,
            "control_id": obligation.control_id, "severity": obligation.severity,
            "scope": obligation.scope, "source_url": obligation.source_url,
            "source_digest": obligation.source_digest,
        }
        if applicability is ApplicabilityStatus.APPLICABLE and obligation.implementation_status == ImplementationStatus.IMPLEMENTED.value and obligation.assessment_method == AssessmentMethod.AUTOMATIC.value:
            rule = _rule_for(obligation.evaluator_rule_id or "", profile_version_id)
            field_states = [state for state in states if state.field_id in rule.required_effective_states]
            rule_findings = findings_by_rule.get(rule.rule_id, [])
            finding = next(
                (item for item in rule_findings if item.verdict == FindingVerdict.UNKNOWN),
                rule_findings[0] if rule_findings else None,
            )
            if finding is not None and finding.verdict == FindingVerdict.UNKNOWN:
                verdict = FindingVerdict.UNKNOWN.value
                details["evidence_refs"] = list(finding.evidence_refs)
                reason = finding.unknown_reason or UnresolvedReason.UNKNOWN_SEMANTICS
                details["unknown_reason"] = (
                    reason.value if isinstance(reason, UnresolvedReason) else str(reason)
                )
            elif not field_states:
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
                details["evidence_refs"] = state_evidence(state)
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
            if finding is not None:
                details["baseline_finding"] = {
                    "finding_id": str(finding.finding_id),
                    "verdict": finding.verdict.value,
                }
                if finding.verdict.value == verdict:
                    finding_id = finding.finding_id
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
    coverage["assessment_packs"] = [{
        "assessment_pack_version_id": str(pack.assessment_pack_version_id), "family": pack.family,
        "name": pack.name, "version": pack.version, "source_version_label": pack.source_version_label,
        "content_digest": pack.content_digest,
    } for pack in sorted(packs, key=lambda item: item.family)]
    if len(packs) == 1:
        coverage["assessment_pack"] = coverage["assessment_packs"][0]
    audit.coverage = coverage
    db.flush()
    return coverage
