from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.errors import (
    AuditConflictError, AuditInfrastructureError, AuditNotFoundError,
    AuditValidationError,
)
from app.audit.schemas import (
    AssessmentPackResponse, AuditCreate, AuditResponse, BatchAuditCreate, BatchAuditItemResponse,
    BatchAuditResponse, JobSummary, ReevaluationEligibilityResponse,
    ReevaluationRequest,
)
from app.audit.service import (
    create_audit, create_batch_audits, get_audit, get_audit_job, list_audits,
    start_audit,
)
from app.assessment_packs.service import compatible_packs
from app.db.models import AuditAssessment, AssessmentPackVersion, ProfileResolutionDecision
from app.reevaluation.service import eligibility as reevaluation_eligibility, history as reevaluation_history, start as start_reevaluation
from app.auth.dependencies import get_current_user, require_roles
from app.db.models import Audit, User, UserRole
from app.db.session import get_db


router = APIRouter(prefix="/audits", tags=["audits"])


def _translate(error: Exception) -> HTTPException:
    if isinstance(error, AuditNotFoundError):
        return HTTPException(status.HTTP_404_NOT_FOUND, error.message)
    if isinstance(error, AuditConflictError):
        return HTTPException(status.HTTP_409_CONFLICT, {
            "code": error.code, "message": error.message,
        })
    if isinstance(error, AuditValidationError):
        return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, {
            "code": error.code, "message": error.message,
        })
    if isinstance(error, AuditInfrastructureError):
        return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, {
            "code": error.code, "message": error.message,
        })
    raise error


def _response(db: Session, audit: Audit, job=None) -> AuditResponse:
    associated_job = job if job is not None else get_audit_job(db, audit.audit_id)
    response = AuditResponse.model_validate(audit)
    if associated_job is not None:
        response.job = JobSummary.model_validate(associated_job)
    requested = (audit.version_refs or {}).get("assessment_pack_version_id")
    if requested:
        pinned = db.scalar(select(AuditAssessment).where(AuditAssessment.audit_id == audit.audit_id))
        if pinned is not None:
            pack = db.get(AssessmentPackVersion, pinned.assessment_pack_version_id)
            if pack is not None:
                response.assessment = {
                    "assessment_pack_version_id": str(pack.assessment_pack_version_id),
                    "family": pack.family, "name": pack.name, "version": pack.version,
                    "source_version_label": pack.source_version_label,
                    "content_digest": pack.content_digest,
                }
        else:
            response.assessment = {"assessment_pack_version_id": requested}
    return response


@router.post("", response_model=AuditResponse, status_code=status.HTTP_201_CREATED)
def create_audit_endpoint(
    request: AuditCreate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> AuditResponse:
    try:
        return _response(db, create_audit(db, user, request))
    except (
        AuditNotFoundError, AuditConflictError, AuditValidationError,
        AuditInfrastructureError,
    ) as error:
        raise _translate(error) from None


@router.get("/assessment-packs", response_model=list[AssessmentPackResponse])
def assessment_packs_endpoint(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    profile_version_id: str | None = None,
) -> list[AssessmentPackResponse]:
    rows = compatible_packs(db, user.organization_id, profile_version_id) if profile_version_id else list(
        db.scalars(select(AssessmentPackVersion).where(
            AssessmentPackVersion.status == "published",
            (AssessmentPackVersion.organization_id == user.organization_id)
            | (AssessmentPackVersion.organization_id.is_(None)),
        ).order_by(AssessmentPackVersion.family, AssessmentPackVersion.name, AssessmentPackVersion.version)))
    return [AssessmentPackResponse.model_validate(row) for row in rows]


@router.post("/batch", response_model=BatchAuditResponse)
def create_batch_audits_endpoint(
    request: BatchAuditCreate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> BatchAuditResponse:
    results = create_batch_audits(db, user, request)
    return BatchAuditResponse(
        accepted=sum(item["status"] == "accepted" for item in results),
        rejected=sum(item["status"] == "rejected" for item in results),
        results=[BatchAuditItemResponse.model_validate(item) for item in results],
    )


@router.get("", response_model=list[AuditResponse])
def list_audits_endpoint(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> list[AuditResponse]:
    return [_response(db, audit) for audit in list_audits(db, user)]


@router.get("/{audit_id}", response_model=AuditResponse)
def get_audit_endpoint(
    audit_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> AuditResponse:
    try:
        return _response(db, get_audit(db, user, audit_id))
    except AuditNotFoundError as error:
        raise _translate(error) from None


@router.get("/{audit_id}/profile-resolution", response_model=dict[str, object])
def profile_resolution_endpoint(
    audit_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, object]:
    audit = get_audit(db, user, audit_id)
    decision = db.scalar(select(ProfileResolutionDecision).where(
        ProfileResolutionDecision.audit_id == audit.audit_id,
        ProfileResolutionDecision.organization_id == user.organization_id,
    ).order_by(ProfileResolutionDecision.created_at.desc()))
    if decision is None:
        return dict(audit.profile_resolution or {})
    return {
        "resolution_status": decision.resolution_status,
        "selected_profile_id": decision.selected_profile_id,
        "selected_profile_version_id": decision.selected_profile_version_id,
        "applicability_status": decision.applicability_status,
        "identity_provenance": decision.identity_provenance,
        "evidence_summary": decision.evidence_summary,
    }


@router.post("/{audit_id}/run", response_model=AuditResponse)
def run_audit_endpoint(
    audit_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> AuditResponse:
    try:
        audit, job = start_audit(db, user, audit_id)
        return _response(db, audit, job)
    except (
        AuditNotFoundError, AuditConflictError, AuditValidationError,
        AuditInfrastructureError,
    ) as error:
        raise _translate(error) from None


@router.get("/{audit_id}/reevaluation-eligibility", response_model=ReevaluationEligibilityResponse)
def reevaluation_eligibility_endpoint(audit_id: UUID, user: Annotated[User, Depends(get_current_user)], db: Annotated[Session, Depends(get_db)]):
    try:
        result = reevaluation_eligibility(db, user, audit_id)
        return ReevaluationEligibilityResponse(
            eligible=result.eligible, reason=result.reason, source_audit_id=result.source.audit_id,
            source_revision_number=result.source.revision_number,
            candidates=[{"knowledge_pack_version_id": item.knowledge_pack_version_id, "knowledge_pack_id": item.knowledge_pack_id, "version": item.version, "published_at": item.published_at} for item in result.candidates],
        )
    except AuditNotFoundError as error:
        raise _translate(error) from None


@router.get("/{audit_id}/revisions", response_model=list[AuditResponse])
def audit_history_endpoint(audit_id: UUID, user: Annotated[User, Depends(get_current_user)], db: Annotated[Session, Depends(get_db)]):
    try:
        return [_response(db, item) for item in reevaluation_history(db, user, audit_id)]
    except AuditNotFoundError as error:
        raise _translate(error) from None


@router.post("/{audit_id}/re-evaluate", response_model=AuditResponse, status_code=status.HTTP_201_CREATED)
def reevaluate_audit_endpoint(audit_id: UUID, request: ReevaluationRequest, user: Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.MAPPING_ADMIN))], db: Annotated[Session, Depends(get_db)]):
    try:
        audit, job = start_reevaluation(db, user, audit_id, request.knowledge_pack_version_id)
        return _response(db, audit, job)
    except (AuditNotFoundError, AuditConflictError, AuditValidationError, AuditInfrastructureError) as error:
        raise _translate(error) from None
