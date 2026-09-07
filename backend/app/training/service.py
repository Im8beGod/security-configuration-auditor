from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.compliance.verdicts import FindingVerdict
from app.db.models import (
    Audit, Finding, Job, KnowledgePackRecord, KnowledgePackVersionRecord,
    MappingOrigin, MappingStatus, MappingValidationRun, MappingVersion,
    UnresolvedBlock, UnresolvedReviewStatus, User, UserRole, ValidationRunStatus,
)
from app.db.models.common import utc_now
from app.jobs.enums import JobType
from app.jobs.service import enqueue_job
from app.profile_resolution.registry import PROFILE_REGISTRY
from app.security_model import FIELD_REGISTRY
from app.training import repository
from app.training.ai import AISuggestionProvider, MappingSuggestion, sanitized_context
from app.training.dsl import MappingDefinition, ValidationNode, extract, matches


VALIDATION_FAMILIES = frozenset({"positive", "alternate_values", "negative", "wrong_scope", "negation", "conflict", "regression"})
MUTABLE_STATUSES = frozenset({MappingStatus.SUGGESTED, MappingStatus.DRAFT, MappingStatus.TESTING})


class TrainingError(ValueError):
    pass


class TrainingNotFound(TrainingError):
    pass


class TrainingConflict(TrainingError):
    pass


def list_unresolved(db: Session, user: User, status: UnresolvedReviewStatus | None = None) -> list[UnresolvedBlock]:
    statement = select(UnresolvedBlock).where(UnresolvedBlock.organization_id == user.organization_id)
    if status:
        statement = statement.where(UnresolvedBlock.review_status == status)
    return list(db.scalars(statement.order_by(UnresolvedBlock.created_at.desc())))


def get_unresolved(db: Session, user: User, block_id: UUID) -> UnresolvedBlock:
    block = repository.unresolved_by_id(db, block_id, user.organization_id)
    if block is None:
        raise TrainingNotFound("Unresolved block not found")
    return block


def update_review_status(db: Session, user: User, block_id: UUID, status: UnresolvedReviewStatus) -> UnresolvedBlock:
    block = get_unresolved(db, user, block_id)
    allowed = {
        UnresolvedReviewStatus.OPEN: {UnresolvedReviewStatus.UNDER_REVIEW, UnresolvedReviewStatus.DISMISSED, UnresolvedReviewStatus.NOT_ACTIONABLE},
        UnresolvedReviewStatus.UNDER_REVIEW: {UnresolvedReviewStatus.DISMISSED, UnresolvedReviewStatus.NOT_ACTIONABLE},
    }
    if status not in allowed.get(block.review_status, set()):
        raise TrainingConflict("Unresolved review transition is not allowed")
    block.review_status = status
    db.commit()
    return block


def similar_published(db: Session, block: UnresolvedBlock) -> list[dict[str, Any]]:
    candidates = repository.published_mappings(db, block.organization_id)
    fields = set(block.candidate_field_ids)
    ranked = sorted(candidates, key=lambda item: (item.target_field_id not in fields, item.mapping_key, item.version))
    return [{"mapping_version_id": str(item.mapping_version_id), "mapping_key": item.mapping_key, "target_field_id": item.target_field_id, "structural_match": item.structural_match} for item in ranked[:10]]


def suggest_mapping(db: Session, user: User, block_id: UUID, provider: AISuggestionProvider) -> MappingVersion:
    block = get_unresolved(db, user, block_id)
    context = sanitized_context(block.raw_text, block.surrounding_context, block.profile_version_id, block.candidate_field_ids, similar_published(db, block))
    suggestion = provider.suggest_mapping(context)
    if not isinstance(suggestion, MappingSuggestion):
        suggestion = MappingSuggestion.model_validate(suggestion)
    mapping = _new_mapping(db, user, f"suggested-{block.fingerprint[:16]}", suggestion.description, suggestion.definition, MappingOrigin.AI_ASSISTED, MappingStatus.SUGGESTED, {"confidence": suggestion.confidence, "similar_mapping_refs": suggestion.similar_mapping_refs, "provider": suggestion.provider_metadata})
    block.review_status = UnresolvedReviewStatus.UNDER_REVIEW
    block.assigned_mapping_version_id = mapping.mapping_version_id
    db.commit()
    return mapping


def create_mapping(db: Session, user: User, *, mapping_key: str, title: str, description: str, definition: MappingDefinition, previous_mapping_version_id: UUID | None = None, unresolved_block_id: UUID | None = None) -> MappingVersion:
    previous = None
    if previous_mapping_version_id:
        previous = repository.mapping_by_id(db, previous_mapping_version_id, user.organization_id, lock=True)
        if previous is None:
            raise TrainingNotFound("Previous mapping version not found")
        mapping_id, version = previous.mapping_id, previous.version + 1
    else:
        mapping_id, version = uuid4(), 1
    mapping = _new_mapping(db, user, mapping_key, description, definition, MappingOrigin.ADMINISTRATOR, MappingStatus.DRAFT, None, title=title, mapping_id=mapping_id, version=version, previous=previous)
    if unresolved_block_id:
        block = get_unresolved(db, user, unresolved_block_id)
        block.review_status = UnresolvedReviewStatus.UNDER_REVIEW
        block.assigned_mapping_version_id = mapping.mapping_version_id
    db.commit()
    return mapping


def get_mapping(db: Session, user: User, mapping_version_id: UUID) -> MappingVersion:
    return _mapping(db, user, mapping_version_id)


def update_mapping(db: Session, user: User, mapping_version_id: UUID, *, title: str, description: str, definition: MappingDefinition) -> MappingVersion:
    mapping = _mapping(db, user, mapping_version_id, lock=True)
    if mapping.status not in MUTABLE_STATUSES:
        raise TrainingConflict("Published or approved mapping versions are immutable")
    _apply_definition(mapping, definition)
    mapping.title, mapping.description = title, description
    mapping.status = MappingStatus.DRAFT
    mapping.validation_results = {}
    db.commit()
    return mapping


def request_validation(db: Session, user: User, mapping_version_id: UUID) -> tuple[MappingValidationRun, Job]:
    mapping = _mapping(db, user, mapping_version_id, lock=True)
    if mapping.status not in {MappingStatus.DRAFT, MappingStatus.TESTING}:
        raise TrainingConflict("Mapping is not eligible for validation")
    MappingDefinition.model_validate(_definition_payload(mapping))
    run = MappingValidationRun(organization_id=user.organization_id, mapping_version_id=mapping.mapping_version_id, status=ValidationRunStatus.PENDING, results={})
    db.add(run)
    db.flush()
    job = enqueue_job(db, JobType.MAPPING_VALIDATION, payload={"mapping_version_id": str(mapping.mapping_version_id), "validation_run_id": str(run.validation_run_id), "organization_id": str(user.organization_id)}, stage="mapping_validation")
    mapping.status = MappingStatus.TESTING
    db.commit()
    return run, job


def execute_validation(db: Session, validation_run_id: UUID, mapping_version_id: UUID, organization_id: UUID) -> MappingValidationRun:
    run = db.scalar(select(MappingValidationRun).where(MappingValidationRun.validation_run_id == validation_run_id, MappingValidationRun.mapping_version_id == mapping_version_id, MappingValidationRun.organization_id == organization_id).with_for_update())
    mapping = repository.mapping_by_id(db, mapping_version_id, organization_id, lock=True)
    if run is None or mapping is None or run.status != ValidationRunStatus.PENDING:
        raise TrainingConflict("Mapping validation payload is invalid")
    run.status = ValidationRunStatus.RUNNING
    definition = MappingDefinition.model_validate(_definition_payload(mapping))
    results = validate_definition(db, mapping, definition)
    run.status = ValidationRunStatus.PASSED if results["passed"] else ValidationRunStatus.FAILED
    run.results = results
    run.completed_at = utc_now()
    mapping.validation_results = results
    db.flush()
    return run


def validate_definition(db: Session, mapping: MappingVersion, definition: MappingDefinition) -> dict[str, Any]:
    families: dict[str, list[dict[str, Any]]] = {name: [] for name in VALIDATION_FAMILIES}
    for example in definition.examples:
        matched, captures = matches(definition, example.node)
        value: Any = None
        error: str | None = None
        if matched:
            try:
                value = extract(definition, captures)
            except (KeyError, TypeError, ValueError):
                error = "extraction_failed"
        passed = matched == example.expected_match and (not matched or example.expected_value is None or value == example.expected_value) and error is None
        families[example.family].append({"passed": passed, "matched": matched, "value": value, "error": error})
    relevant = repository.published_mappings(db, mapping.organization_id)
    regressions = families["regression"]
    collision = any(item.mapping_id != mapping.mapping_id and item.target_field_id == mapping.target_field_id and item.structural_match == mapping.structural_match for item in relevant)
    family_results = {family: bool(cases) and all(case["passed"] for case in cases) for family, cases in families.items()}
    if collision:
        family_results["regression"] = False
        regressions.append({"passed": False, "error": "published_mapping_collision"})
    digest = _digest(definition)
    return {"passed": all(family_results.values()), "families": family_results, "cases": families, "definition_digest": digest}


def approve_mapping(db: Session, user: User, mapping_version_id: UUID) -> MappingVersion:
    _require_admin(user)
    mapping = _mapping(db, user, mapping_version_id, lock=True)
    validation = repository.latest_validation(db, mapping.mapping_version_id)
    definition = MappingDefinition.model_validate(_definition_payload(mapping))
    if mapping.status != MappingStatus.TESTING or validation is None or validation.status != ValidationRunStatus.PASSED or validation.results.get("definition_digest") != _digest(definition):
        raise TrainingConflict("Current successful validation is required")
    mapping.status, mapping.approved_by, mapping.approved_at = MappingStatus.APPROVED, user.user_id, utc_now()
    db.commit()
    return mapping


def reject_mapping(db: Session, user: User, mapping_version_id: UUID) -> MappingVersion:
    _require_admin(user)
    mapping = _mapping(db, user, mapping_version_id, lock=True)
    if mapping.status not in MUTABLE_STATUSES:
        raise TrainingConflict("Only an unpublished Mapping may be rejected")
    mapping.status = MappingStatus.REJECTED
    db.commit()
    return mapping


def publish_mapping(db: Session, user: User, mapping_version_id: UUID) -> tuple[MappingVersion, KnowledgePackVersionRecord]:
    _require_admin(user)
    mapping = _mapping(db, user, mapping_version_id, lock=True)
    definition = MappingDefinition.model_validate(_definition_payload(mapping))
    validation = repository.latest_validation(db, mapping.mapping_version_id)
    if mapping.status != MappingStatus.APPROVED or mapping.approved_by is None or validation is None or validation.status != ValidationRunStatus.PASSED or validation.results.get("definition_digest") != _digest(definition):
        raise TrainingConflict("Approved, currently validated mapping is required")
    profile_ids = definition.profile_applicability.profile_version_ids
    if not profile_ids or any(profile_id not in PROFILE_REGISTRY for profile_id in profile_ids):
        raise TrainingConflict("Profile applicability is required")
    pack_key = "administrator-mappings:" + ",".join(sorted(profile_ids))
    pack = db.scalar(select(KnowledgePackRecord).where(KnowledgePackRecord.organization_id == user.organization_id, KnowledgePackRecord.pack_key == pack_key).with_for_update())
    if pack is None:
        pack = KnowledgePackRecord(organization_id=user.organization_id, pack_key=pack_key, name="Administrator validated mappings")
        db.add(pack); db.flush()
    previous_pack = db.scalar(select(KnowledgePackVersionRecord).where(KnowledgePackVersionRecord.knowledge_pack_id == pack.knowledge_pack_id).order_by(KnowledgePackVersionRecord.version.desc()).limit(1).with_for_update())
    retained: list[str] = []
    if previous_pack:
        prior = list(db.scalars(select(MappingVersion).where(MappingVersion.mapping_version_id.in_([UUID(item) for item in previous_pack.mapping_version_ids])))) if previous_pack.mapping_version_ids else []
        retained = [str(item.mapping_version_id) for item in prior if item.mapping_id != mapping.mapping_id]
    pack_version = KnowledgePackVersionRecord(knowledge_pack_id=pack.knowledge_pack_id, organization_id=user.organization_id, version=(previous_pack.version + 1 if previous_pack else 1), previous_knowledge_pack_version_id=(previous_pack.knowledge_pack_version_id if previous_pack else None), mapping_version_ids=sorted([*retained, str(mapping.mapping_version_id)]), published_by=user.user_id)
    db.add(pack_version); db.flush()
    previous_mapping = db.scalar(select(MappingVersion).where(MappingVersion.organization_id == user.organization_id, MappingVersion.mapping_id == mapping.mapping_id, MappingVersion.status == MappingStatus.PUBLISHED).with_for_update())
    if previous_mapping:
        previous_mapping.status = MappingStatus.SUPERSEDED
    mapping.status, mapping.published_at, mapping.knowledge_pack_version_id = MappingStatus.PUBLISHED, utc_now(), pack_version.knowledge_pack_version_id
    for block in db.scalars(select(UnresolvedBlock).where(UnresolvedBlock.organization_id == user.organization_id, UnresolvedBlock.assigned_mapping_version_id == mapping.mapping_version_id).with_for_update()):
        block.review_status = UnresolvedReviewStatus.MAPPED
    db.commit()
    return mapping, pack_version


def impact_analysis(db: Session, user: User, mapping_version_id: UUID) -> dict[str, Any]:
    mapping = _mapping(db, user, mapping_version_id)
    if mapping.status not in {MappingStatus.PUBLISHED, MappingStatus.SUPERSEDED}:
        raise TrainingConflict("Impact analysis requires a published mapping")
    definition = MappingDefinition.model_validate(_definition_payload(mapping))
    blocks = list(db.scalars(select(UnresolvedBlock).where(UnresolvedBlock.organization_id == user.organization_id)))
    matched = [block for block in blocks if _block_matches(definition, block)]
    audit_ids = sorted({block.audit_id for block in matched}, key=str)
    device_ids = sorted({block.device_id for block in matched}, key=str)
    unknown_count = db.scalar(select(func.count(Finding.finding_id)).where(Finding.audit_id.in_(audit_ids), Finding.verdict == FindingVerdict.UNKNOWN)) if audit_ids else 0
    profile_ids = definition.profile_applicability.profile_version_ids
    profile_audits = list(db.scalars(select(Audit.audit_id).where(Audit.organization_id == user.organization_id)))
    return {"mapping_version_id": mapping.mapping_version_id, "matching_unresolved_block_ids": [item.unresolved_block_id for item in matched], "affected_device_ids": device_ids, "affected_historical_audit_ids": audit_ids, "potentially_affected_unknown_findings": int(unknown_count or 0), "historical_profile_audit_count": sum(1 for audit_id in profile_audits if _audit_profile(db, audit_id) in profile_ids), "creates_audit_revision": False}


def list_packs(db: Session, user: User) -> list[KnowledgePackRecord]:
    return list(db.scalars(select(KnowledgePackRecord).where(KnowledgePackRecord.organization_id == user.organization_id).order_by(KnowledgePackRecord.created_at)))


def pack_versions(db: Session, user: User, pack_id: UUID) -> list[KnowledgePackVersionRecord]:
    pack = db.scalar(select(KnowledgePackRecord).where(KnowledgePackRecord.knowledge_pack_id == pack_id, KnowledgePackRecord.organization_id == user.organization_id))
    if pack is None:
        raise TrainingNotFound("Knowledge pack not found")
    return list(db.scalars(select(KnowledgePackVersionRecord).where(KnowledgePackVersionRecord.knowledge_pack_id == pack_id).order_by(KnowledgePackVersionRecord.version.desc())))


def _new_mapping(db: Session, user: User, mapping_key: str, description: str, definition: MappingDefinition, origin: MappingOrigin, status: MappingStatus, ai_metadata: dict[str, Any] | None, *, title: str | None = None, mapping_id: UUID | None = None, version: int = 1, previous: MappingVersion | None = None) -> MappingVersion:
    if not mapping_key.strip() or len(mapping_key) > 255:
        raise TrainingError("Mapping key is invalid")
    mapping = MappingVersion(mapping_id=mapping_id or uuid4(), organization_id=user.organization_id, mapping_key=mapping_key.strip(), version=version, previous_mapping_version_id=previous.mapping_version_id if previous else None, title=title or description[:255], description=description, status=status, origin=origin, ai_suggestion_metadata=ai_metadata, created_by=user.user_id, validation_results={})
    _apply_definition(mapping, definition)
    db.add(mapping); db.flush()
    return mapping


def _apply_definition(mapping: MappingVersion, definition: MappingDefinition) -> None:
    data = definition.model_dump(mode="json")
    mapping.profile_applicability = data["profile_applicability"]
    mapping.structural_match = data["structural_match"]
    mapping.target_field_id = data["target_field_id"]
    mapping.value_extraction = data["value_extraction"]
    mapping.unit_conversion = data["unit_conversion"]
    mapping.scope_resolution = data["scope_resolution"]
    mapping.negation_behavior = data["negation_behavior"]
    mapping.removal_behavior = data["removal_behavior"]
    mapping.default_behavior = data["default_behavior"]
    mapping.examples = data["examples"]


def _definition_payload(mapping: MappingVersion) -> dict[str, Any]:
    return {name: getattr(mapping, name) for name in ("profile_applicability", "structural_match", "target_field_id", "value_extraction", "unit_conversion", "scope_resolution", "negation_behavior", "removal_behavior", "default_behavior", "examples")}


def _mapping(db: Session, user: User, mapping_version_id: UUID, *, lock: bool = False) -> MappingVersion:
    mapping = repository.mapping_by_id(db, mapping_version_id, user.organization_id, lock=lock)
    if mapping is None:
        raise TrainingNotFound("Mapping version not found")
    return mapping


def _require_admin(user: User) -> None:
    if user.role not in {UserRole.MAPPING_ADMIN, UserRole.ADMIN}:
        raise TrainingError("Mapping administrator role is required")


def _digest(definition: MappingDefinition) -> str:
    return hashlib.sha256(json.dumps(definition.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _block_matches(definition: MappingDefinition, block: UnresolvedBlock) -> bool:
    occurrence = block.occurrence
    try:
        node = ValidationNode.model_validate({"command": occurrence.get("command", "unknown"), "arguments": occurrence.get("arguments", []), "parent_command": occurrence.get("parent_command"), "ancestor_commands": occurrence.get("ancestor_commands", []), "scope_type": occurrence.get("scope_type"), "negated": occurrence.get("negated", False)})
    except ValidationError:
        return False
    return matches(definition, node)[0]


def _audit_profile(db: Session, audit_id: UUID) -> str | None:
    audit = db.get(Audit, audit_id)
    return (audit.version_refs or {}).get("device_profile_version_id") if audit else None
