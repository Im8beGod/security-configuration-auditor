from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.assessment_packs.catalog import (
    CatalogImportError, MAX_EXTERNAL_CATALOG_BYTES, import_external_catalog,
)
from app.auth.dependencies import require_roles
from app.db.models import User, UserRole
from app.db.session import get_db


router = APIRouter(prefix="/assessment-packs", tags=["assessment-packs"])
CatalogAdmin = Annotated[User, Depends(require_roles(UserRole.ADMIN))]


@router.post("/import", status_code=201)
async def import_catalog(
    file: Annotated[UploadFile, File(...)],
    user: CatalogAdmin,
    db: Annotated[Session, Depends(get_db)],
):
    content = await file.read(MAX_EXTERNAL_CATALOG_BYTES + 1)
    try:
        pack, counts = import_external_catalog(
            db, user.organization_id, content, file.filename or "catalog.json",
        )
        db.commit()
        db.refresh(pack)
    except CatalogImportError as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Catalog version conflicts with published data") from exc
    return {
        "assessment_pack_version_id": str(pack.assessment_pack_version_id),
        "pack_key": pack.pack_key, "version": pack.version,
        "family": pack.family, "source_version": pack.source_version_label,
        "source_url": pack.source_metadata["official_source_url"],
        "source_digest": pack.content_digest,
        "control_count": sum(counts.values()), **counts,
        "automatic": 0,
    }
