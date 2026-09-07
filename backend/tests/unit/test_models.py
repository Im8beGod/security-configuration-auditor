from uuid import UUID

import pytest
from sqlalchemy import CheckConstraint, DateTime, UniqueConstraint, Uuid, inspect

from app.db.base import Base
from app.db.models import Organization, User, UserRole


def test_only_current_application_tables_are_registered() -> None:
    assert set(Base.metadata.tables) == {
        "artifacts", "audits", "devices", "effective_states", "jobs", "organizations", "security_facts",
        "snapshots", "users"
    }


def test_identity_primary_keys_use_uuid() -> None:
    organization_id = Organization.__table__.c.organization_id
    user_id = User.__table__.c.user_id

    assert organization_id.primary_key is True
    assert user_id.primary_key is True
    assert isinstance(organization_id.type, Uuid)
    assert isinstance(user_id.type, Uuid)
    assert organization_id.type.python_type is UUID
    assert user_id.type.python_type is UUID


def test_organization_slug_is_unique_and_required() -> None:
    table = Organization.__table__
    unique_columns = {
        tuple(constraint.columns.keys())
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    assert table.c.slug.nullable is False
    assert ("slug",) in unique_columns


def test_user_tenant_foreign_key_is_required_and_restrictive() -> None:
    organization_id = User.__table__.c.organization_id
    foreign_key = next(iter(organization_id.foreign_keys))

    assert organization_id.nullable is False
    assert organization_id.index is True
    assert foreign_key.target_fullname == "organizations.organization_id"
    assert foreign_key.ondelete == "RESTRICT"


def test_user_email_is_globally_unique_and_required() -> None:
    table = User.__table__
    unique_columns = {
        tuple(constraint.columns.keys())
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    assert table.c.email.nullable is False
    assert ("email",) in unique_columns


def test_role_values_and_database_constraint_are_frozen() -> None:
    role_column = User.__table__.c.role
    check_names = {
        constraint.name
        for constraint in User.__table__.constraints
        if isinstance(constraint, CheckConstraint)
    }

    assert [role.value for role in UserRole] == [
        "analyst",
        "mapping_admin",
        "admin",
    ]
    assert role_column.type.native is False
    assert role_column.type.enums == ["analyst", "mapping_admin", "admin"]
    assert "ck_users_role" in check_names
    assert role_column.nullable is False


def test_user_stores_only_a_required_password_hash() -> None:
    columns = User.__table__.c

    assert "password_hash" in columns
    assert columns.password_hash.nullable is False
    assert "password" not in columns


def test_required_fields_and_timezone_aware_timestamps() -> None:
    for table, required_columns in (
        (
            Organization.__table__,
            {"organization_id", "name", "slug", "is_active", "created_at", "updated_at"},
        ),
        (
            User.__table__,
            {
                "user_id",
                "organization_id",
                "email",
                "password_hash",
                "role",
                "is_active",
                "created_at",
                "updated_at",
            },
        ),
    ):
        assert all(table.c[name].nullable is False for name in required_columns)
        assert isinstance(table.c.created_at.type, DateTime)
        assert table.c.created_at.type.timezone is True
        assert table.c.updated_at.type.timezone is True


def test_relationships_use_back_populates_without_delete_cascade() -> None:
    organization_users = inspect(Organization).relationships.users
    user_organization = inspect(User).relationships.organization

    assert organization_users.back_populates == "organization"
    assert user_organization.back_populates == "users"
    assert "delete" not in organization_users.cascade
    assert "delete-orphan" not in organization_users.cascade


def test_model_validators_normalize_identity_values() -> None:
    organization = Organization(name="  Example Organization  ", slug=" Example Org ")
    user = User(
        organization=organization,
        email="  ANALYST@EXAMPLE.COM ",
        password_hash="$argon2id$test-only-placeholder",
    )

    assert organization.name == "Example Organization"
    assert organization.slug == "example-org"
    assert user.email == "analyst@example.com"

    with pytest.raises(ValueError, match="must not be empty"):
        Organization(name="Example", slug="   ")
