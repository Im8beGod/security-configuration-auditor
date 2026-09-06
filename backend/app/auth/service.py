from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import dummy_password_hash, verify_password
from app.db.models import Organization, User


def authenticate_user(db: Session, email: str, password: str) -> User | None:
    row = db.execute(
        select(User, Organization.is_active)
        .join(Organization, User.organization_id == Organization.organization_id)
        .where(User.email == email.strip().lower())
        .execution_options(populate_existing=True)
    ).first()
    stored_hash = row[0].password_hash if row is not None else dummy_password_hash()
    valid_password = verify_password(password, stored_hash)
    if row is None or not valid_password or not row[0].is_active or not row[1]:
        return None
    return row[0]


def resolve_current_user(db: Session, user_id: UUID) -> User | None:
    """Reload identity and tenant state; JWT role claims are never used."""
    return db.scalar(
        select(User)
        .join(Organization, User.organization_id == Organization.organization_id)
        .where(
            User.user_id == user_id,
            User.is_active.is_(True),
            Organization.is_active.is_(True),
        )
        .execution_options(populate_existing=True)
    )
