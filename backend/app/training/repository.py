from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import MappingStatus, MappingValidationRun, MappingVersion, UnresolvedBlock


def unresolved_by_id(db: Session, block_id: UUID, organization_id: UUID) -> UnresolvedBlock | None:
    return db.scalar(select(UnresolvedBlock).where(UnresolvedBlock.unresolved_block_id == block_id, UnresolvedBlock.organization_id == organization_id))


def mapping_by_id(db: Session, mapping_version_id: UUID, organization_id: UUID, *, lock: bool = False) -> MappingVersion | None:
    statement = select(MappingVersion).where(MappingVersion.mapping_version_id == mapping_version_id, MappingVersion.organization_id == organization_id)
    return db.scalar(statement.with_for_update() if lock else statement)


def latest_validation(db: Session, mapping_version_id: UUID) -> MappingValidationRun | None:
    return db.scalar(select(MappingValidationRun).where(MappingValidationRun.mapping_version_id == mapping_version_id).order_by(MappingValidationRun.created_at.desc(), MappingValidationRun.validation_run_id.desc()).limit(1))


def published_mappings(db: Session, organization_id: UUID) -> list[MappingVersion]:
    return list(db.scalars(select(MappingVersion).where(MappingVersion.organization_id == organization_id, MappingVersion.status == MappingStatus.PUBLISHED).order_by(MappingVersion.mapping_key, MappingVersion.version)))
