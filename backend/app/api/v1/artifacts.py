from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.core.config import Settings, get_settings
from app.db.models import Artifact, User
from app.db.session import get_db
from app.ingestion.errors import IngestionError, IngestionInfrastructureError
from app.ingestion.metadata import normalize_filename
from app.ingestion.schemas import (
    ArtifactResponse,
    BulkUploadItem,
    BulkUploadResponse,
    UploadError,
)
from app.ingestion.service import ingest_artifact
from app.ingestion.storage import ArtifactStorage, get_artifact_storage


router = APIRouter(prefix="/artifacts", tags=["artifacts"])
UPLOAD_CHUNK_BYTES = 64 * 1024


@router.get("", response_model=list[ArtifactResponse])
def list_artifacts(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    unassigned: Annotated[bool, Query()] = False,
) -> list[Artifact]:
    statement = select(Artifact).where(
        Artifact.organization_id == user.organization_id
    )
    if unassigned:
        statement = statement.where(Artifact.snapshot_id.is_(None))
    return list(db.scalars(statement.order_by(
        Artifact.created_at.desc(), Artifact.artifact_id
    )))


async def _read_bounded(upload: UploadFile, maximum_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while chunk := await upload.read(UPLOAD_CHUNK_BYTES):
        total += len(chunk)
        if total > maximum_bytes:
            raise IngestionError(
                "file_too_large", f"Uploaded evidence exceeds the {maximum_bytes}-byte limit"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _http_error(error: IngestionError) -> HTTPException:
    if isinstance(error, IngestionInfrastructureError):
        return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, error.message)
    code = status.HTTP_413_CONTENT_TOO_LARGE if error.code == "file_too_large" else status.HTTP_422_UNPROCESSABLE_CONTENT
    return HTTPException(code, {"code": error.code, "message": error.message})


@router.post("/upload", response_model=ArtifactResponse, status_code=status.HTTP_201_CREATED)
async def upload_artifact(
    file: Annotated[UploadFile, File(...)],
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    storage: Annotated[ArtifactStorage, Depends(get_artifact_storage)],
) -> Artifact:
    try:
        data = await _read_bounded(file, settings.artifact_max_upload_bytes)
        return ingest_artifact(db, storage, user, data, file.filename, file.content_type)
    except IngestionError as error:
        raise _http_error(error) from None
    finally:
        await file.close()


@router.post("/bulk-upload", response_model=BulkUploadResponse)
async def bulk_upload_artifacts(
    files: Annotated[list[UploadFile], File(...)],
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    storage: Annotated[ArtifactStorage, Depends(get_artifact_storage)],
) -> BulkUploadResponse:
    if len(files) > settings.artifact_max_bulk_files:
        for upload in files:
            await upload.close()
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            {
                "code": "too_many_files",
                "message": f"Bulk upload accepts at most {settings.artifact_max_bulk_files} files",
            },
        )

    results: list[BulkUploadItem] = []
    for upload in files:
        filename = normalize_filename(upload.filename)
        try:
            data = await _read_bounded(upload, settings.artifact_max_upload_bytes)
            artifact = ingest_artifact(
                db, storage, user, data, upload.filename, upload.content_type
            )
            results.append(BulkUploadItem(
                filename=filename, status="success", artifact=ArtifactResponse.model_validate(artifact)
            ))
        except IngestionError as error:
            results.append(BulkUploadItem(
                filename=filename,
                status="failed",
                error=UploadError(code=error.code, message=error.message),
            ))
        finally:
            await upload.close()
    succeeded = sum(item.status == "success" for item in results)
    return BulkUploadResponse(
        total=len(results), succeeded=succeeded, failed=len(results) - succeeded, results=results
    )


@router.get("/{artifact_id}", response_model=ArtifactResponse)
def get_artifact(
    artifact_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Artifact:
    artifact = db.scalar(select(Artifact).where(
        Artifact.artifact_id == artifact_id,
        Artifact.organization_id == user.organization_id,
    ))
    if artifact is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Artifact not found")
    return artifact
