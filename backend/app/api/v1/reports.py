import hashlib
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from app.auth.dependencies import get_current_user
from app.db.models import ReportStatus, User
from app.db.session import get_db
from app.reporting.schemas import ReportResponse
from app.reporting.service import ReportNotFound, ReportingError, create_report, get_report
from app.reporting.storage import ReportNotFoundError, ReportStorage, get_report_storage

router = APIRouter(tags=["reports"])

@router.post("/audits/{audit_id}/reports", response_model=ReportResponse, status_code=202)
def request_report(audit_id: UUID, user: Annotated[User, Depends(get_current_user)], db: Annotated[Session, Depends(get_db)]):
    try: report, _job = create_report(db, user, audit_id); return report
    except ReportNotFound as error: raise HTTPException(404, "Audit not found") from error
    except ReportingError as error: raise HTTPException(409, "Audit is not ready for reporting") from error

@router.get("/reports/{report_id}", response_model=ReportResponse)
def report_status(report_id: UUID, user: Annotated[User, Depends(get_current_user)], db: Annotated[Session, Depends(get_db)]):
    try: return get_report(db, user, report_id)
    except ReportNotFound as error: raise HTTPException(404, "Report not found") from error

@router.get("/reports/{report_id}/download")
def report_download(report_id: UUID, user: Annotated[User, Depends(get_current_user)], db: Annotated[Session, Depends(get_db)], storage: Annotated[ReportStorage, Depends(get_report_storage)]):
    try: report = get_report(db, user, report_id)
    except ReportNotFound as error: raise HTTPException(404, "Report not found") from error
    if report.status != ReportStatus.READY or not report.storage_reference: raise HTTPException(409, "Report is not ready")
    try: content = storage.read(report.storage_reference)
    except ReportNotFoundError as error: raise HTTPException(404, "Report content not found") from error
    if len(content) != report.byte_size or hashlib.sha256(content).hexdigest() != report.sha256: raise HTTPException(409, "Report content failed integrity verification")
    return Response(content, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="audit-{report.audit_id}.pdf"', "ETag": report.sha256 or ""})
