from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.audit.errors import (
    AuditConflictError,
    AuditInfrastructureError,
    AuditNotFoundError,
)
from app.audit.service import resolve_audit_profile
from app.compliance.policy import PolicyRegistryError, select_policy_version
from app.compliance.rule_registry import RULE_PACK_BY_PROFILE, RULE_REGISTRY, RuleRegistryError
from app.compliance.service import ComplianceError, persist_audit_findings
from app.compliance.verdicts import FindingVerdict
from app.db.models import Audit, AuditProcessingStage, AuditStatus, EffectiveState, Finding
from app.db.models.common import utc_now
from app.ingestion.storage import ArtifactStorage
from app.interpretation import (
    AuditInterpretationResult,
    interpret_audit,
    load_validated_knowledge_pack,
)
from app.interpretation.service import load_published_knowledge_pack
from app.effective_state.service import resolve_audit_effective_states
from app.profile_resolution import ProfileResolutionResult, ResolutionStatus, ResolutionConfidence


@dataclass(frozen=True)
class AuditPipelineResult:
    profile_resolution: ProfileResolutionResult
    interpretation: AuditInterpretationResult | None
    effective_states: tuple[EffectiveState, ...] | None
    findings: tuple[Finding, ...] | None
    stages: tuple[AuditProcessingStage, ...]


class AuditPipelineCoordinator:
    """Compose the implemented Audit pipeline without owning worker lifecycle."""

    def __init__(
        self,
        factory: sessionmaker[Session],
        storage: ArtifactStorage,
    ) -> None:
        self._factory = factory
        self._storage = storage

    def run(self, audit_id: UUID, organization_id: UUID) -> AuditPipelineResult:
        stages = [AuditProcessingStage.IDENTIFYING]
        self._begin_processing(audit_id, organization_id)

        with self._factory() as db:
            audit = db.scalar(select(Audit).where(Audit.audit_id == audit_id, Audit.organization_id == organization_id))
            if audit is None:
                raise AuditNotFoundError("audit_not_found", "Audit not found")
            resolution = self._pinned_resolution(audit)
        if resolution is None:
            with self._factory() as db:
                resolution = resolve_audit_profile(db, self._storage, audit_id, organization_id)
        if (
            resolution.resolution_status != ResolutionStatus.RESOLVED
            or resolution.selected_profile_version_id is None
        ):
            self._finalize_failure(audit_id, organization_id, stage=AuditProcessingStage.IDENTIFYING)
            return AuditPipelineResult(resolution, None, None, None, tuple(stages))

        pack = self._load_audit_pack(
            audit_id, organization_id, resolution.selected_profile_version_id
        )
        self._pin_versions_and_set_stage(
            audit_id,
            organization_id,
            profile_version_id=resolution.selected_profile_version_id,
            knowledge_pack_version_id=pack.knowledge_pack_version_id,
            stage=AuditProcessingStage.PARSING,
        )
        stages.append(AuditProcessingStage.PARSING)

        def begin_interpreting() -> None:
            self._pin_versions_and_set_stage(
                audit_id,
                organization_id,
                profile_version_id=resolution.selected_profile_version_id,
                knowledge_pack_version_id=pack.knowledge_pack_version_id,
                stage=AuditProcessingStage.INTERPRETING,
            )
            stages.append(AuditProcessingStage.INTERPRETING)

        with self._factory() as db:
            interpretation = interpret_audit(
                db,
                self._storage,
                audit_id,
                organization_id,
                before_interpret=begin_interpreting,
                knowledge_pack=pack,
            )
        self._pin_versions_and_set_stage(
            audit_id,
            organization_id,
            profile_version_id=resolution.selected_profile_version_id,
            knowledge_pack_version_id=pack.knowledge_pack_version_id,
            stage=AuditProcessingStage.RESOLVING_STATE,
        )
        stages.append(AuditProcessingStage.RESOLVING_STATE)
        with self._factory() as db:
            effective_states = resolve_audit_effective_states(
                db, audit_id=audit_id, organization_id=organization_id
            )
            self._commit(db, "effective_state_persistence_failed")
        self._pin_compliance_versions_and_set_stage(
            audit_id, organization_id, resolution.selected_profile_version_id
        )
        stages.append(AuditProcessingStage.EVALUATING)
        with self._factory() as db:
            # Compliance receives a fresh canonical database read, never resolver output.
            persisted_states = tuple(db.scalars(select(EffectiveState).where(
                EffectiveState.audit_id == audit_id
            ).order_by(EffectiveState.field_id, EffectiveState.scope_key)))
            audit = db.scalar(select(Audit).where(
                Audit.audit_id == audit_id, Audit.organization_id == organization_id
            ))
            if audit is None:
                raise AuditNotFoundError("audit_not_found", "Audit not found")
            try:
                rule_pack = RULE_REGISTRY.get(UUID(audit.version_refs["rule_pack_versions"][0]))
                policy = select_policy_version(
                    organization_id, audit.version_refs.get("organization_policy_version_id")
                )
            except (KeyError, TypeError, ValueError, RuleRegistryError, PolicyRegistryError):
                raise AuditConflictError(
                    "audit_version_conflict", "Audit compliance versions are already pinned differently"
                ) from None
            findings = persist_audit_findings(
                db, audit_id=audit_id, organization_id=organization_id, rule_pack=rule_pack,
                organization_policy=policy, effective_states=persisted_states,
            )
            self._commit(db, "finding_persistence_failed")
        self._finalize(audit_id, organization_id, findings)
        return AuditPipelineResult(
            resolution, interpretation, effective_states, findings, tuple(stages)
        )

    def _pin_compliance_versions_and_set_stage(self, audit_id: UUID, organization_id: UUID, profile_version_id: str) -> None:
        with self._factory() as db:
            audit = db.scalar(select(Audit).where(
                Audit.audit_id == audit_id, Audit.organization_id == organization_id
            ).with_for_update())
            if audit is None or audit.status is not AuditStatus.PROCESSING:
                raise AuditConflictError("audit_not_processing", "Audit is not processing")
            existing_packs = audit.version_refs.get("rule_pack_versions")
            expected_rule_pack = RULE_PACK_BY_PROFILE.get(profile_version_id)
            if expected_rule_pack is None:
                raise AuditConflictError("audit_version_conflict", "Audit compliance versions are unavailable")
            expected_pack = str(expected_rule_pack.rule_pack_version_id)
            if existing_packs is None:
                packs = [expected_pack]
            elif isinstance(existing_packs, list) and expected_pack in existing_packs:
                packs = existing_packs
            else:
                raise AuditConflictError("audit_version_conflict", "Audit compliance versions are already pinned differently")
            try:
                policy = select_policy_version(
                    organization_id, audit.version_refs.get("organization_policy_version_id")
                )
            except PolicyRegistryError:
                raise AuditConflictError("audit_version_conflict", "Audit compliance versions are already pinned differently") from None
            pinned_policy = audit.version_refs.get("organization_policy_version_id")
            policy_id = str(policy.organization_policy_version_id)
            if pinned_policy is not None and pinned_policy != policy_id:
                raise AuditConflictError("audit_version_conflict", "Audit compliance versions are already pinned differently")
            audit.version_refs = {
                **audit.version_refs, "rule_pack_versions": packs,
                "organization_policy_version_id": policy_id,
            }
            audit.processing_stage = AuditProcessingStage.EVALUATING
            self._commit(db, "audit_pipeline_checkpoint_failed")

    def _finalize(self, audit_id: UUID, organization_id: UUID, findings: tuple[Finding, ...]) -> None:
        """Persist the already-modelled terminal state after successful deterministic evaluation."""
        verdict_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        for finding in findings:
            verdict_counts[finding.verdict.value] = verdict_counts.get(finding.verdict.value, 0) + 1
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
        if verdict_counts.get(FindingVerdict.PROCESS_ERROR.value):
            terminal = AuditStatus.COMPLETED_WITH_ERRORS
        elif any(verdict_counts.get(value) for value in (FindingVerdict.UNKNOWN.value, FindingVerdict.MANUAL_REVIEW.value)):
            terminal = AuditStatus.COMPLETED_WITH_UNKNOWNS
        else:
            terminal = AuditStatus.COMPLETED
        with self._factory() as db:
            audit = db.scalar(select(Audit).where(
                Audit.audit_id == audit_id, Audit.organization_id == organization_id
            ).with_for_update())
            if audit is None:
                raise AuditNotFoundError("audit_not_found", "Audit not found")
            if audit.status is not AuditStatus.PROCESSING:
                raise AuditConflictError("audit_not_processing", "Audit is not processing")
            audit.processing_stage = AuditProcessingStage.FINALIZING
            audit.verdict_counts = verdict_counts
            audit.severity_counts = severity_counts
            audit.status = terminal
            audit.completed_at = utc_now()
            self._commit(db, "audit_finalization_failed")

    def _finalize_failure(
        self,
        audit_id: UUID,
        organization_id: UUID,
        *,
        stage: AuditProcessingStage | None = None,
    ) -> None:
        """Persist a truthful terminal failure when the profile cannot be processed."""
        with self._factory() as db:
            audit = db.scalar(select(Audit).where(
                Audit.audit_id == audit_id, Audit.organization_id == organization_id
            ).with_for_update())
            if audit is None:
                raise AuditNotFoundError("audit_not_found", "Audit not found")
            if audit.status is not AuditStatus.PROCESSING:
                raise AuditConflictError("audit_not_processing", "Audit is not processing")
            if audit.completed_at is None:
                audit.processing_stage = stage or audit.processing_stage or AuditProcessingStage.IDENTIFYING
                audit.status = AuditStatus.FAILED
                audit.completed_at = utc_now()
                self._commit(db, "audit_finalization_failed")

    def mark_failed(self, audit_id: UUID, organization_id: UUID) -> None:
        """Expose a bounded failure terminalizer for controlled handler exceptions."""
        with self._factory() as db:
            audit = db.scalar(select(Audit).where(
                Audit.audit_id == audit_id, Audit.organization_id == organization_id
            ))
            stage = audit.processing_stage if audit is not None else None
        self._finalize_failure(audit_id, organization_id, stage=stage)

    def _load_audit_pack(
        self, audit_id: UUID, organization_id: UUID, profile_version_id: str
    ):
        with self._factory() as db:
            audit = db.scalar(select(Audit).where(
                Audit.audit_id == audit_id, Audit.organization_id == organization_id
            ))
            if audit is None:
                raise AuditNotFoundError("audit_not_found", "Audit not found")
            pinned = audit.version_refs.get("knowledge_pack_version_id")
        if pinned is None:
            return load_validated_knowledge_pack(profile_version_id)
        try:
            with self._factory() as db:
                pack = load_published_knowledge_pack(db, organization_id, UUID(pinned), profile_version_id)
        except (TypeError, ValueError):
            raise AuditConflictError(
                "audit_version_conflict", "Audit processing versions are already pinned differently"
            ) from None
        if pack.profile_version_id != profile_version_id:
            raise AuditConflictError(
                "audit_version_conflict", "Audit processing versions are already pinned differently"
            )
        return pack

    @staticmethod
    def _pinned_resolution(audit: Audit) -> ProfileResolutionResult | None:
        """Re-evaluation retains the source's resolved profile; it never re-identifies evidence."""
        if audit.reevaluation_reason.value == "initial":
            return None
        data = audit.profile_resolution
        profile_id, profile_version_id = data.get("profile_id"), data.get("profile_version_id")
        if not isinstance(profile_id, str) or not isinstance(profile_version_id, str):
            raise AuditConflictError("audit_profile_missing", "Re-evaluation source profile is unavailable")
        try:
            status = ResolutionStatus(data.get("resolution_status"))
            confidence = ResolutionConfidence(data.get("confidence"))
        except ValueError:
            raise AuditConflictError("audit_profile_invalid", "Re-evaluation source profile is invalid") from None
        return ProfileResolutionResult(
            vendor=data.get("vendor"), product_family=data.get("product_family"), os=data.get("os"),
            os_version=data.get("os_version"), model=data.get("model"), serial_number=data.get("serial_number"),
            device_class=None, selected_profile_id=profile_id, selected_profile_version_id=profile_version_id,
            confidence=confidence, resolution_status=status, supporting_signals=(), unresolved_reasons=(), conflicts=(),
        )

    def _begin_processing(self, audit_id: UUID, organization_id: UUID) -> None:
        with self._factory() as db:
            audit = db.scalar(
                select(Audit)
                .where(
                    Audit.audit_id == audit_id,
                    Audit.organization_id == organization_id,
                )
                .with_for_update()
            )
            if audit is None:
                raise AuditNotFoundError("audit_not_found", "Audit not found")
            if audit.status not in {AuditStatus.QUEUED, AuditStatus.PROCESSING}:
                raise AuditConflictError(
                    "audit_not_processable", "Audit is not available for processing"
                )
            audit.status = AuditStatus.PROCESSING
            audit.processing_stage = AuditProcessingStage.IDENTIFYING
            if audit.started_at is None:
                audit.started_at = utc_now()
            audit.completed_at = None
            self._commit(db, "audit_pipeline_start_failed")

    def _pin_versions_and_set_stage(
        self,
        audit_id: UUID,
        organization_id: UUID,
        *,
        profile_version_id: str,
        knowledge_pack_version_id: UUID,
        stage: AuditProcessingStage,
    ) -> None:
        expected_refs = {
            "schema_version": "1.0.0",
            "device_profile_version_id": profile_version_id,
            "knowledge_pack_version_id": str(knowledge_pack_version_id),
        }
        with self._factory() as db:
            audit = db.scalar(
                select(Audit)
                .where(
                    Audit.audit_id == audit_id,
                    Audit.organization_id == organization_id,
                )
                .with_for_update()
            )
            if audit is None:
                raise AuditNotFoundError("audit_not_found", "Audit not found")
            if audit.status != AuditStatus.PROCESSING:
                raise AuditConflictError(
                    "audit_not_processing", "Audit is not processing"
                )
            if (
                audit.profile_resolution.get("profile_version_id")
                != profile_version_id
            ):
                raise AuditConflictError(
                    "audit_profile_changed", "Audit profile resolution changed"
                )
            for key, value in expected_refs.items():
                pinned = audit.version_refs.get(key)
                if pinned is not None and pinned != value:
                    raise AuditConflictError(
                        "audit_version_conflict",
                        "Audit processing versions are already pinned differently",
                    )
            audit.version_refs = {**audit.version_refs, **expected_refs}
            audit.processing_stage = stage
            self._commit(db, "audit_pipeline_checkpoint_failed")

    @staticmethod
    def _commit(db: Session, code: str) -> None:
        try:
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            raise AuditInfrastructureError(
                code, "Audit pipeline state could not be persisted"
            ) from None
