from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, String, Uuid, true
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base import Base
from app.db.models.common import utc_now

if TYPE_CHECKING:
    from app.db.models.user import User


SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class Organization(Base):
    """Tenant boundary for platform users."""

    __tablename__ = "organizations"
    __table_args__ = (
        CheckConstraint(
            "slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'",
            name="ck_organizations_slug",
        ),
    )

    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
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

    users: Mapped[list[User]] = relationship(back_populates="organization")

    @validates("name")
    def normalize_name(self, _key: str, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Organization name must not be empty")
        return normalized

    @validates("slug")
    def normalize_slug(self, _key: str, value: str) -> str:
        normalized = "-".join(value.strip().lower().split())
        if not normalized:
            raise ValueError("Organization slug must not be empty")
        if not SLUG_PATTERN.fullmatch(normalized):
            raise ValueError(
                "Organization slug must contain lowercase letters, numbers, "
                "and single hyphens"
            )
        return normalized
