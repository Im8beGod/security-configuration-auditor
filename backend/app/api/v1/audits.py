from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.audit.errors import (
    AuditConflictError, AuditInfrastructureError, AuditNotFoundError,
    AuditValidationError,
)
from app.audit.schemas import AuditCreate, AuditResponse, JobSummary
from app.audit.service import (
    create_audit, get_audit, get_audit_job, list_audits, start_audit,
)
from app.auth.dependencies import get_current_user
from app.db.models import Audit, User
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
