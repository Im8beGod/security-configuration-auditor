import json
import re

import pytest
from sqlalchemy import CheckConstraint, Column, JSON, MetaData, Table, Uuid, create_engine, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import Settings
from app.db.models import Job, Organization, User


@compiles(JSONB, "sqlite")
def compile_jsonb_for_sqlite(_type, _compiler, **_kwargs):
    return "JSON"


@pytest.fixture
def auth_settings():
    return Settings(
        postgres_password="test-only-db",
        jwt_secret="test-only-signing-key-at-least-32-characters",
        api_prefix="/api/v1",
        auth_cookie_name="test_auth",
        auth_cookie_secure=False,
        auth_cookie_samesite="lax",
        auth_cookie_path="/",
        jwt_algorithm="HS256",
        jwt_access_token_expire_minutes=30,
        _env_file=None,
    )


@pytest.fixture
def identity_factory():
    """SQLite identity-only test schema; production metadata is never mutated."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def sqlite_functions(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.create_function("btrim", 1, lambda value: value.strip())
        connection.create_function("char_length", 1, len)
        connection.create_function(
            "regexp", 2, lambda pattern, value: re.fullmatch(pattern, value) is not None
        )

    metadata = MetaData()
    organization = Organization.__table__.to_metadata(metadata)
    User.__table__.to_metadata(metadata)
    # PostgreSQL's ~ operator has a test-only SQLite equivalent.
    constraint = next(
        item for item in organization.constraints if item.name == "ck_organizations_slug"
    )
    organization.constraints.remove(constraint)
    organization.append_constraint(
        CheckConstraint(
            "slug REGEXP '^[a-z0-9]+(-[a-z0-9]+)*$'",
            name="ck_organizations_slug",
        )
    )
    metadata.create_all(engine)  # Isolated copies of the two identity tables only.
    try:
        yield sessionmaker(bind=engine, autoflush=False, autocommit=False)
    finally:
        engine.dispose()


@pytest.fixture
def job_factory():
    """SQLite job-only schema for lifecycle tests; production remains PostgreSQL."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def sqlite_json_type(connection, _record):
        def jsonb_typeof(value):
            parsed = json.loads(value) if isinstance(value, str) else value
            return "object" if isinstance(parsed, dict) else "other"

        connection.execute("PRAGMA foreign_keys=ON")
        connection.create_function("jsonb_typeof", 1, jsonb_typeof)

    metadata = MetaData()
    Table("audits", metadata, Column("audit_id", Uuid(as_uuid=True), primary_key=True))
    Table("devices", metadata, Column("device_id", Uuid(as_uuid=True), primary_key=True))
    jobs = Job.__table__.to_metadata(metadata)
    jobs.c.payload.type = JSON()
    jobs.c.payload.server_default = None
    metadata.create_all(engine)
    try:
        yield sessionmaker(
            bind=engine, autoflush=False, autocommit=False, expire_on_commit=False
        )
    finally:
        engine.dispose()
