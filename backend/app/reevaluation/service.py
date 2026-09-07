from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.audit.errors import AuditConflictError, AuditNotFoundError, AuditValidationError, AuditInfrastructureError
from app.audit.service import validate_snapshot_evidence
from app.db.models import Audit, AuditReevaluationReason, AuditStatus, KnowledgePackVersionRecord, MappingVersion, Snapshot, SnapshotStatus, User, UserRole
from app.jobs.enums import JobType
from app.jobs.service import enqueue_job
from app.profile_resolution import PROFILE_REGISTRY


COMPLETED_STATUSES = frozenset({AuditStatus.COMPLETED, AuditStatus.COMPLETED_WITH_UNKNOWNS, AuditStatus.COMPLETED_WITH_ERRORS})


@dataclass(frozen=True)
class ReevaluationEligibility:
    eligible: bool
    reason: str | None
    source: Audit
    candidates: tuple[KnowledgePackVersionRecord, ...]


def _require_privileged(user: User) -> None:
    if user.role not in {UserRole.ADMIN, UserRole.MAPPING_ADMIN}:
        raise AuditValidationError("reevaluation_forbidden", "Administrator permission is required")


def _source(db: Session, user: User, audit_id: UUID, *, lock: bool = False) -> Audit:
    statement = select(Audit).where(Audit.audit_id == audit_id, Audit.organization_id == user.organization_id)
    audit = db.scalar(statement.with_for_update() if lock else statement)
    if audit is None:
        raise AuditNotFoundError("audit_not_found", "Audit not found")
    return audit


def _candidates(db: Session, source: Audit) -> tuple[KnowledgePackVersionRecord, ...]:
    profile = source.version_refs.get("device_profile_version_id") or source.profile_resolution.get("profile_version_id")
    if not isinstance(profile, str) or PROFILE_REGISTRY.get(profile) is None:
        return ()
    current = source.version_refs.get("knowledge_pack_version_id")
    packs = list(db.scalars(select(KnowledgePackVersionRecord).where(
        KnowledgePackVersionRecord.organization_id == source.organization_id
    ).order_by(KnowledgePackVersionRecord.published_at.desc(), KnowledgePackVersionRecord.version.desc())))
    eligible: list[KnowledgePackVersionRecord] = []
    for pack in packs:
        if str(pack.knowledge_pack_version_id) == current or not pack.mapping_version_ids:
            continue
        try:
            ids = [UUID(value) for value in pack.mapping_version_ids]
        except (TypeError, ValueError):
            continue
        mappings = list(db.scalars(select(MappingVersion).where(
            MappingVersion.mapping_version_id.in_(ids), MappingVersion.organization_id == source.organization_id
        )))
        if len(mappings) == len(ids) and all(profile in item.profile_applicability.get("profile_version_ids", []) for item in mappings):
            eligible.append(pack)
    return tuple(eligible)


def eligibility(db: Session, user: User, audit_id: UUID) -> ReevaluationEligibility:
    source = _source(db, user, audit_id)
    if source.status not in COMPLETED_STATUSES:
        return ReevaluationEligibility(False, "source_audit_not_completed", source, ())
    snapshot = db.get(Snapshot, source.snapshot_id)
    if snapshot is None or snapshot.organization_id != source.organization_id or snapshot.device_id != source.device_id:
        return ReevaluationEligibility(False, "source_snapshot_invalid", source, ())
    if snapshot.status not in {SnapshotStatus.READY, SnapshotStatus.LOCKED}:
        return ReevaluationEligibility(False, "source_snapshot_not_immutable", source, ())
    try:
        validate_snapshot_evidence(db, snapshot)
    except AuditValidationError:
        return ReevaluationEligibility(False, "source_evidence_unavailable", source, ())
    candidates = _candidates(db, source)
    return ReevaluationEligibility(bool(candidates), None if candidates else "no_compatible_newer_knowledge_pack", source, candidates)


def start(db: Session, user: User, audit_id: UUID, target_knowledge_pack_version_id: UUID) -> tuple[Audit, object]:
    _require_privileged(user)
    source = _source(db, user, audit_id, lock=True)
    check = eligibility(db, user, audit_id)
    if not check.eligible:
        raise AuditConflictError("reevaluation_unavailable", check.reason or "Re-evaluation is unavailable")
    target = db.scalar(select(KnowledgePackVersionRecord).where(
        KnowledgePackVersionRecord.knowledge_pack_version_id == target_knowledge_pack_version_id,
        KnowledgePackVersionRecord.organization_id == user.organization_id,
    ).with_for_update())
    if target is None or target not in check.candidates:
        raise AuditValidationError("knowledge_pack_ineligible", "Selected Knowledge Pack is not eligible")
    snapshot = db.scalar(select(Snapshot).where(Snapshot.snapshot_id == source.snapshot_id).with_for_update())
    if snapshot is None:
        raise AuditValidationError("source_snapshot_invalid", "Source Snapshot is unavailable")
    validate_snapshot_evidence(db, snapshot, lock=True)
    # Serialize revisions through the immutable Snapshot row lock.
    latest = db.scalar(select(func.max(Audit.revision_number)).where(Audit.snapshot_id == source.snapshot_id)) or 0
    existing = db.scalar(select(Audit).where(
        Audit.previous_audit_id == source.audit_id,
        Audit.version_refs["knowledge_pack_version_id"].astext == str(target_knowledge_pack_version_id),
        Audit.status.in_([AuditStatus.DRAFT, AuditStatus.QUEUED, AuditStatus.PROCESSING]),
    ))
    if existing is not None:
        return existing, db.scalar(select(__import__('app.db.models', fromlist=['Job']).Job).where(__import__('app.db.models', fromlist=['Job']).Job.audit_id == existing.audit_id).order_by(__import__('app.db.models', fromlist=['Job']).Job.created_at.desc()).limit(1))
    audit = Audit(
        organization_id=source.organization_id, device_id=source.device_id, snapshot_id=source.snapshot_id,
        audit_batch_id=source.audit_batch_id, revision_number=latest + 1, previous_audit_id=source.audit_id,
        reevaluation_reason=AuditReevaluationReason.KNOWLEDGE_PACK_UPDATE, status=AuditStatus.QUEUED,
        processing_stage=None, selected_frameworks=list(source.selected_frameworks),
        version_refs={**source.version_refs, "knowledge_pack_version_id": str(target_knowledge_pack_version_id)},
        # Profile resolution is historical pinned context, not a new identification pass.
        profile_resolution=dict(source.profile_resolution), verdict_counts={}, severity_counts={}, coverage={}, created_by=user.user_id,
        schema_version=source.schema_version,
    )
    db.add(audit)
    try:
        db.flush()
        job = enqueue_job(db, JobType.RE_EVALUATION, audit_id=audit.audit_id, device_id=audit.device_id,
                          payload={"source_audit_id": str(source.audit_id), "knowledge_pack_version_id": str(target_knowledge_pack_version_id)})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise AuditConflictError("reevaluation_conflict", "A re-evaluation was created concurrently") from None
    except SQLAlchemyError:
        db.rollback()
        raise AuditInfrastructureError("reevaluation_persistence_failed", "Re-evaluation could not be started") from None
    db.refresh(audit); db.refresh(job)
    return audit, job


def history(db: Session, user: User, audit_id: UUID) -> list[Audit]:
    source = _source(db, user, audit_id)
    return list(db.scalars(select(Audit).where(Audit.snapshot_id == source.snapshot_id, Audit.organization_id == user.organization_id).order_by(Audit.revision_number)))
