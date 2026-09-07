from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.db.models import User
from app.db.session import get_db
from app.findings.schemas import FindingEvidenceResponse, FindingPage, FindingResponse
from app.findings.service import FindingNotFoundError, FindingProvenanceError, get_finding, list_findings, resolve_evidence
from app.ingestion.storage import ArtifactStorage, get_artifact_storage

router = APIRouter(tags=["findings"])

def _error(error):
    if isinstance(error, FindingNotFoundError): return HTTPException(404, "Finding not found")
    if isinstance(error, FindingProvenanceError): return HTTPException(422, "Finding evidence is unavailable")
    raise error

@router.get("/audits/{audit_id}/findings", response_model=FindingPage)
def list_audit_findings(audit_id: UUID, user: Annotated[User, Depends(get_current_user)], db: Annotated[Session, Depends(get_db)], verdict: str|None=None, severity: str|None=None, security_domain: str|None=None, rule_id: str|None=None, framework: str|None=None, offset: Annotated[int, Query(ge=0)]=0, limit: Annotated[int, Query(ge=1,le=100)]=50):
    try:
        items,total=list_findings(db,user,audit_id,verdict=verdict,severity=severity,security_domain=security_domain,rule_id=rule_id,framework=framework,offset=offset,limit=limit)
        return FindingPage(items=[FindingResponse.model_validate(item) for item in items],total=total,offset=offset,limit=limit)
    except FindingNotFoundError as error: raise _error(error) from None

@router.get("/findings/{finding_id}", response_model=FindingResponse)
def finding_detail(finding_id: UUID, user: Annotated[User, Depends(get_current_user)], db: Annotated[Session, Depends(get_db)]):
    try: return get_finding(db,user,finding_id)
    except FindingNotFoundError as error: raise _error(error) from None

@router.get("/findings/{finding_id}/evidence", response_model=FindingEvidenceResponse)
def finding_evidence(finding_id: UUID, user: Annotated[User, Depends(get_current_user)], db: Annotated[Session, Depends(get_db)], storage: Annotated[ArtifactStorage, Depends(get_artifact_storage)]):
    try: return resolve_evidence(db,user,finding_id,storage)
    except (FindingNotFoundError,FindingProvenanceError) as error: raise _error(error) from None
