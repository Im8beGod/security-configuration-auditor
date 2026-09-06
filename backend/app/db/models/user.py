from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum as SqlEnum,
    ForeignKey,
    String,
    Uuid,
    true,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base import Base
from app.db.models.common import utc_now

if TYPE_CHECKING:
    from app.db.models.organization import Organization


class UserRole(str, Enum):
    ANALYST = "analyst"
    MAPPING_ADMIN = "mapping_admin"
    ADMIN = "admin"


class User(Base):
    """Platform identity belonging to exactly one organization."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "email = lower(btrim(email)) AND char_length(email) > 0",
            name="ck_users_email",
        ),
        CheckConstraint(
            "char_length(password_hash) > 0",
            name="ck_users_password_hash",
        ),
    )

    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.organization_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        SqlEnum(
            UserRole,
            name="ck_users_role",
            native_enum=False,
            create_constraint=True,
            validate_strings=True,
            values_callable=lambda enum: [member.value for member in enum],
            length=32,
        ),
        nullable=False,
        default=UserRole.ANALYST,
        server_default=UserRole.ANALYST.value,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=true(),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    organization: Mapped[Organization] = relationship(back_populates="users")

    @validates("email")
    def normalize_email(self, _key: str, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("User email must not be empty")
        return normalized

    @validates("password_hash")
    def validate_password_hash(self, _key: str, value: str) -> str:
        if not value or value != value.strip():
            raise ValueError("Password hash must be non-empty and normalized")
        return value
