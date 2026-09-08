from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any
from uuid import UUID, NAMESPACE_URL, uuid4, uuid5

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.compliance.verdicts import FindingVerdict
from app.db.models import (
    Artifact, ArtifactStatus, Audit, Finding, Job, KnowledgePackRecord, KnowledgePackVersionRecord,
    MappingOrigin, MappingStatus, MappingValidationRun, MappingVersion,
    Snapshot, SnapshotStatus, UnresolvedBlock, UnresolvedReviewStatus, User, UserRole, ValidationRunStatus,
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


def request_validation(db: Session, user: User, mapping_version_id: UUID, *, evidence_artifact_id: UUID | None = None) -> tuple[MappingValidationRun, Job]:
    mapping = _mapping(db, user, mapping_version_id, lock=True)
    if mapping.status not in {MappingStatus.DRAFT, MappingStatus.TESTING}:
        raise TrainingConflict("Mapping is not eligible for validation")
    MappingDefinition.model_validate(_definition_payload(mapping))
    if evidence_artifact_id is not None:
        artifact = db.scalar(select(Artifact).where(Artifact.artifact_id == evidence_artifact_id, Artifact.organization_id == user.organization_id))
        if artifact is None or artifact.status is not ArtifactStatus.READY:
            raise TrainingConflict("Selected evidence artifact is not ready")
        profile_ids = set((mapping.profile_applicability or {}).get("profile_version_ids", []))
        if not profile_ids:
            raise TrainingConflict("Profile applicability is required for evidence validation")
        if artifact.snapshot_id is None:
            raise TrainingConflict("Selected evidence must belong to a snapshot")
        snapshot = db.get(Snapshot, artifact.snapshot_id)
        if snapshot is None or snapshot.organization_id != user.organization_id or snapshot.status not in {SnapshotStatus.READY, SnapshotStatus.LOCKED}:
            raise TrainingConflict("Selected evidence snapshot is not ready")
    run = MappingValidationRun(organization_id=user.organization_id, mapping_version_id=mapping.mapping_version_id, status=ValidationRunStatus.PENDING, results={"evidence_artifact_id": str(evidence_artifact_id) if evidence_artifact_id else None})
    db.add(run)
    db.flush()
    job = enqueue_job(db, JobType.MAPPING_VALIDATION, payload={"mapping_version_id": str(mapping.mapping_version_id), "validation_run_id": str(run.validation_run_id), "organization_id": str(user.organization_id), "evidence_artifact_id": str(evidence_artifact_id) if evidence_artifact_id else None}, stage="mapping_validation")
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
    evidence_artifact_id = run.results.get("evidence_artifact_id")
    results = validate_definition(db, mapping, definition, evidence_artifact_id=UUID(evidence_artifact_id) if evidence_artifact_id else None)
    run.status = ValidationRunStatus.PASSED if results["passed"] else ValidationRunStatus.FAILED
    run.results = results
    run.completed_at = utc_now()
    mapping.validation_results = results
    db.flush()
    return run


def validate_definition(db: Session, mapping: MappingVersion, definition: MappingDefinition, *, evidence_artifact_id: UUID | None = None) -> dict[str, Any]:
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
    semantic: dict[str, Any] | None = None
    if evidence_artifact_id is not None:
        semantic = _validate_against_artifact(db, mapping, definition, evidence_artifact_id)
    relevant = repository.published_mappings(db, mapping.organization_id)
    regressions = families["regression"]
    collision = any(item.mapping_id != mapping.mapping_id and item.target_field_id == mapping.target_field_id and item.structural_match == mapping.structural_match for item in relevant)
    family_results = {family: bool(cases) and all(case["passed"] for case in cases) for family, cases in families.items()}
    if evidence_artifact_id is not None and not definition.examples:
        family_results = {family: True for family in VALIDATION_FAMILIES}
    if collision:
        family_results["regression"] = False
        regressions.append({"passed": False, "error": "published_mapping_collision"})
    digest = _digest(definition)
    profile_digest = _profile_digest(definition)
    content_digest = _content_digest(definition)
    passed = all(family_results.values()) and (semantic is None or semantic["status"] == "matched")
    return {"passed": passed, "families": family_results, "cases": families, "semantic": semantic, "definition_digest": digest, "profile_digest": profile_digest, "content_digest": content_digest, "validation_digest": _validation_digest(digest, profile_digest, content_digest, semantic.get("evidence_digest") if semantic else None)}


def approve_mapping(db: Session, user: User, mapping_version_id: UUID) -> MappingVersion:
    _require_admin(user)
    mapping = _mapping(db, user, mapping_version_id, lock=True)
    validation = repository.latest_validation(db, mapping.mapping_version_id)
    definition = MappingDefinition.model_validate(_definition_payload(mapping))
    if mapping.status != MappingStatus.TESTING or validation is None or validation.status != ValidationRunStatus.PASSED or not _validation_is_current(db, mapping, validation.results, definition):
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
    if mapping.status != MappingStatus.APPROVED or mapping.approved_by is None or validation is None or validation.status != ValidationRunStatus.PASSED or not _validation_is_current(db, mapping, validation.results, definition):
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


def _profile_digest(definition: MappingDefinition) -> str:
    payload = []
    for profile_id in sorted(definition.profile_applicability.profile_version_ids):
        profile = PROFILE_REGISTRY.get(profile_id)
        payload.append({"profile_version_id": profile_id, "manifest": profile.coverage_manifest if profile else None})
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


def _content_digest(definition: MappingDefinition) -> str:
    examples = [item.model_dump(mode="json") for item in definition.examples]
    return hashlib.sha256(json.dumps(examples, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _validation_digest(definition_digest: str, profile_digest: str, content_digest: str, evidence_digest: str | None = None) -> str:
    return hashlib.sha256(f"{definition_digest}:{profile_digest}:{content_digest}:{evidence_digest or ''}".encode()).hexdigest()


def _validation_is_current(db: Session, mapping: MappingVersion, results: dict[str, Any], definition: MappingDefinition) -> bool:
    definition_digest = _digest(definition)
    profile_digest = _profile_digest(definition)
    content_digest = _content_digest(definition)
    evidence_digest = None
    semantic = results.get("semantic") or {}
    evidence_id = semantic.get("evidence_artifact_id")
    if evidence_id:
        artifact = db.scalar(select(Artifact).where(Artifact.artifact_id == UUID(evidence_id), Artifact.organization_id == mapping.organization_id))
        if artifact is None:
            return False
        evidence_digest = artifact.sha256
    return results.get("definition_digest") == definition_digest and results.get("profile_digest") == profile_digest and results.get("content_digest") == content_digest and results.get("validation_digest") == _validation_digest(definition_digest, profile_digest, content_digest, evidence_digest)


def _validate_against_artifact(db: Session, mapping: MappingVersion, definition: MappingDefinition, evidence_artifact_id: UUID) -> dict[str, Any]:
    from app.effective_state.policy import FactOperation
    from app.effective_state.resolver import resolve_security_facts
    from app.ingestion.storage import get_artifact_storage
    from app.interpretation.knowledge_pack import KnowledgePack
    from app.interpretation.service import _to_orm, _training_mapping, interpret_xml_structural_ir
    from app.parsing import parse_artifact

    artifact = db.scalar(select(Artifact).where(Artifact.artifact_id == evidence_artifact_id, Artifact.organization_id == mapping.organization_id))
    if artifact is None or artifact.status is not ArtifactStatus.READY or artifact.snapshot_id is None:
        raise TrainingConflict("Selected evidence artifact is not eligible")
    snapshot = db.get(Snapshot, artifact.snapshot_id)
    if snapshot is None or snapshot.organization_id != mapping.organization_id or snapshot.status not in {SnapshotStatus.READY, SnapshotStatus.LOCKED}:
        raise TrainingConflict("Selected evidence snapshot is not eligible")
    profile_version_id = (definition.profile_applicability.profile_version_ids or [None])[0]
    if profile_version_id is None:
        raise TrainingConflict("Evidence validation requires a profile version")
    ir = parse_artifact(get_artifact_storage(), artifact, profile_version_id=profile_version_id, organization_id=mapping.organization_id)
    mapping_adapter = _training_mapping(mapping, profile_version_id)
    pack_id = uuid5(NAMESPACE_URL, f"validation-pack:{mapping.mapping_version_id}")
    pack = KnowledgePack(pack_id, pack_id, "Validation candidate", "validation", "1.0.0", profile_version_id.split("@", 1)[0], profile_version_id, (mapping_adapter,))
    context_id = uuid5(NAMESPACE_URL, f"validation-audit:{mapping.mapping_version_id}:{artifact.artifact_id}")
    from app.interpretation.models import InterpretationContext
    result = interpret_xml_structural_ir(ir, InterpretationContext(context_id, snapshot.device_id, snapshot.snapshot_id), profile_version_id=profile_version_id, knowledge_pack=pack)
    transient_facts = tuple(_to_orm(item) for item in result.facts)
    states = resolve_security_facts(audit_id=context_id, device_id=snapshot.device_id, facts=transient_facts, operations={item.fact_id: FactOperation.ASSIGN for item in transient_facts})
    matches = []
    from app.training.dsl import matches_xml, xml_match_has_unsupported_qualifier
    for node, captures in matches_xml(definition, ir):
        matches.append({"path": list(node.path), "node_id": node.node_id, "captures": captures, "status": "excluded_unsupported_scope" if xml_match_has_unsupported_qualifier(definition, ir, node) else "matched"})
    facts = [{"field_id": item.field_id, "value": item.value, "state": item.state, "evidence_refs": item.evidence_refs, "mapping_version_id": str(item.mapping_version_id)} for item in transient_facts]
    effective_states = [{"field_id": item.field_id, "scope": item.scope.to_dict(), "resolution_status": item.resolution_status.value, "effective_value": item.effective_value.to_dict() if item.effective_value else None, "source_fact_ids": [str(value) for value in item.source_fact_ids]} for item in states]
    status = "matched" if matches else "no_match"
    return {"status": status, "evidence_artifact_id": str(artifact.artifact_id), "evidence_filename": artifact.original_filename, "evidence_digest": artifact.sha256, "snapshot_id": str(snapshot.snapshot_id), "profile_version_id": profile_version_id, "reader_id": ir.reader_id, "matched_paths": matches, "facts": facts, "effective_states": effective_states, "diagnostics": [{"code": item.code, "node_id": item.node_id} for item in result.diagnostics]}


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
