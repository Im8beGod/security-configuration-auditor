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
from app.db.models import Audit, AuditProcessingStage, AuditStatus, EffectiveState
from app.db.models.common import utc_now
from app.ingestion.storage import ArtifactStorage
from app.interpretation import (
    AuditInterpretationResult,
    interpret_audit,
    load_validated_knowledge_pack,
)
from app.interpretation.service import load_validated_knowledge_pack_by_version
from app.effective_state.service import resolve_audit_effective_states
from app.profile_resolution import ProfileResolutionResult, ResolutionStatus


@dataclass(frozen=True)
class AuditPipelineResult:
    profile_resolution: ProfileResolutionResult
    interpretation: AuditInterpretationResult | None
    effective_states: tuple[EffectiveState, ...] | None
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
            resolution = resolve_audit_profile(
                db, self._storage, audit_id, organization_id
            )
        if (
            resolution.resolution_status != ResolutionStatus.RESOLVED
            or resolution.selected_profile_version_id is None
        ):
            return AuditPipelineResult(resolution, None, None, tuple(stages))

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
        return AuditPipelineResult(
            resolution, interpretation, effective_states, tuple(stages)
        )

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
            pack = load_validated_knowledge_pack_by_version(UUID(pinned))
        except (TypeError, ValueError):
            raise AuditConflictError(
                "audit_version_conflict", "Audit processing versions are already pinned differently"
            ) from None
        if pack.profile_version_id != profile_version_id:
            raise AuditConflictError(
                "audit_version_conflict", "Audit processing versions are already pinned differently"
            )
        return pack

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
