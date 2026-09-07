from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.db.models import UnresolvedReviewStatus, User, UserRole
from app.db.session import get_db
from app.training.ai import AISuggestionProvider, AISuggestionUnavailable, DisabledAISuggestionProvider
from app.training.schemas import (
    CanonicalFieldResponse, ImpactResponse, KnowledgePackResponse, KnowledgePackVersionResponse,
    MappingCreateRequest, MappingResponse, MappingUpdateRequest, ReviewUpdateRequest,
    PublicationResponse, UnresolvedResponse, ValidationRequestResponse,
)
from app.training.service import (
    TrainingConflict, TrainingError, TrainingNotFound, approve_mapping,
    create_mapping, get_mapping, get_unresolved, impact_analysis, list_packs,
    list_unresolved, pack_versions, publish_mapping, reject_mapping, request_validation,
    suggest_mapping, update_mapping, update_review_status,
)
from app.security_model import FIELD_REGISTRY


router = APIRouter(prefix="/training", tags=["training"])
TrainingAdmin = Annotated[User, Depends(require_roles(UserRole.MAPPING_ADMIN, UserRole.ADMIN))]


def get_ai_suggestion_provider() -> AISuggestionProvider:
    return DisabledAISuggestionProvider()


@router.get("/canonical-fields", response_model=list[CanonicalFieldResponse])
def canonical_fields(user: TrainingAdmin):
    del user
    return [{"field_id": field.field_id, "expected_types": sorted(item.value for item in field.expected_types), "allowed_scope_types": sorted(field.allowed_scope_types), "domain": field.domain, "description": field.description, "repeatable": field.repeatable} for field in FIELD_REGISTRY.values()]


def _raise(error: Exception) -> None:
    if isinstance(error, TrainingNotFound):
        raise HTTPException(404, str(error)) from error
    if isinstance(error, AISuggestionUnavailable):
        raise HTTPException(503, "AI mapping suggestions are unavailable") from error
    if isinstance(error, (TrainingConflict, TrainingError)):
        raise HTTPException(409, str(error)) from error
    raise error


@router.get("/unresolved", response_model=list[UnresolvedResponse])
def unresolved_list(user: TrainingAdmin, db: Annotated[Session, Depends(get_db)], review_status: UnresolvedReviewStatus | None = Query(default=None)):
    return list_unresolved(db, user, review_status)


@router.get("/unresolved/{block_id}", response_model=UnresolvedResponse)
def unresolved_detail(block_id: UUID, user: TrainingAdmin, db: Annotated[Session, Depends(get_db)]):
    try:
        return get_unresolved(db, user, block_id)
    except Exception as error:
        _raise(error)


@router.patch("/unresolved/{block_id}", response_model=UnresolvedResponse)
def unresolved_update(block_id: UUID, request: ReviewUpdateRequest, user: TrainingAdmin, db: Annotated[Session, Depends(get_db)]):
    try:
        return update_review_status(db, user, block_id, request.review_status)
    except Exception as error:
        db.rollback(); _raise(error)


@router.post("/unresolved/{block_id}/suggest", response_model=MappingResponse, status_code=201)
def unresolved_suggest(block_id: UUID, user: TrainingAdmin, db: Annotated[Session, Depends(get_db)], provider: Annotated[AISuggestionProvider, Depends(get_ai_suggestion_provider)]):
    try:
        return suggest_mapping(db, user, block_id, provider)
    except Exception as error:
        db.rollback(); _raise(error)


@router.post("/mappings", response_model=MappingResponse, status_code=201)
def mapping_create(request: MappingCreateRequest, user: TrainingAdmin, db: Annotated[Session, Depends(get_db)]):
    try:
        return create_mapping(db, user, mapping_key=request.mapping_key, title=request.title, description=request.description, definition=request.definition, previous_mapping_version_id=request.previous_mapping_version_id, unresolved_block_id=request.unresolved_block_id)
    except Exception as error:
        db.rollback(); _raise(error)


@router.get("/mappings/{mapping_version_id}", response_model=MappingResponse)
def mapping_detail(mapping_version_id: UUID, user: TrainingAdmin, db: Annotated[Session, Depends(get_db)]):
    try:
        return get_mapping(db, user, mapping_version_id)
    except Exception as error:
        _raise(error)


@router.put("/mappings/{mapping_version_id}", response_model=MappingResponse)
def mapping_update(mapping_version_id: UUID, request: MappingUpdateRequest, user: TrainingAdmin, db: Annotated[Session, Depends(get_db)]):
    try:
        return update_mapping(db, user, mapping_version_id, title=request.title, description=request.description, definition=request.definition)
    except Exception as error:
        db.rollback(); _raise(error)


@router.post("/mappings/{mapping_version_id}/validate", response_model=ValidationRequestResponse, status_code=202)
def mapping_validate(mapping_version_id: UUID, user: TrainingAdmin, db: Annotated[Session, Depends(get_db)]):
    try:
        run, job = request_validation(db, user, mapping_version_id)
        return ValidationRequestResponse(validation_run_id=run.validation_run_id, job_id=job.job_id, status=run.status)
    except Exception as error:
        db.rollback(); _raise(error)


@router.post("/mappings/{mapping_version_id}/approve", response_model=MappingResponse)
def mapping_approve(mapping_version_id: UUID, user: TrainingAdmin, db: Annotated[Session, Depends(get_db)]):
    try:
        return approve_mapping(db, user, mapping_version_id)
    except Exception as error:
        db.rollback(); _raise(error)


@router.post("/mappings/{mapping_version_id}/publish", response_model=PublicationResponse)
def mapping_publish(mapping_version_id: UUID, user: TrainingAdmin, db: Annotated[Session, Depends(get_db)]):
    try:
        mapping, pack = publish_mapping(db, user, mapping_version_id)
        return PublicationResponse(mapping=MappingResponse.model_validate(mapping), knowledge_pack_version_id=pack.knowledge_pack_version_id, knowledge_pack_version=pack.version)
    except Exception as error:
        db.rollback(); _raise(error)


@router.post("/mappings/{mapping_version_id}/reject", response_model=MappingResponse)
def mapping_reject(mapping_version_id: UUID, user: TrainingAdmin, db: Annotated[Session, Depends(get_db)]):
    try:
        return reject_mapping(db, user, mapping_version_id)
    except Exception as error:
        db.rollback(); _raise(error)


@router.get("/mappings/{mapping_version_id}/impact", response_model=ImpactResponse)
def mapping_impact(mapping_version_id: UUID, user: TrainingAdmin, db: Annotated[Session, Depends(get_db)]):
    try:
        return impact_analysis(db, user, mapping_version_id)
    except Exception as error:
        _raise(error)


@router.get("/knowledge-packs", response_model=list[KnowledgePackResponse])
def knowledge_packs(user: TrainingAdmin, db: Annotated[Session, Depends(get_db)]):
    return list_packs(db, user)


@router.get("/knowledge-packs/{pack_id}/versions", response_model=list[KnowledgePackVersionResponse])
def knowledge_pack_history(pack_id: UUID, user: TrainingAdmin, db: Annotated[Session, Depends(get_db)]):
    try:
        return pack_versions(db, user, pack_id)
    except Exception as error:
        _raise(error)
