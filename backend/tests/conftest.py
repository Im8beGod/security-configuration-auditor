import json
import re

import pytest
from sqlalchemy import CheckConstraint, Column, JSON, MetaData, Table, Uuid, create_engine, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import Settings
from app.db.models import Artifact, Audit, Device, Job, Organization, Snapshot, User


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


@pytest.fixture
def artifact_factory():
    """SQLite identity/artifact schema for fast API behavior tests."""
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    @event.listens_for(engine, "connect")
    def sqlite_functions(connection, _record):
        def jsonb_typeof(value):
            parsed = json.loads(value) if isinstance(value, str) else value
            if isinstance(parsed, list):
                return "array"
            if isinstance(parsed, dict):
                return "object"
            return "other"

        connection.execute("PRAGMA foreign_keys=ON")
        connection.create_function("btrim", 1, lambda value: value.strip())
        connection.create_function("char_length", 1, len)
        connection.create_function("jsonb_typeof", 1, jsonb_typeof)
        connection.create_function(
            "regexp", 2, lambda pattern, value: re.fullmatch(pattern, value) is not None
        )

    metadata = MetaData()
    organization = Organization.__table__.to_metadata(metadata)
    User.__table__.to_metadata(metadata)
    Table("snapshots", metadata, Column("snapshot_id", Uuid(as_uuid=True), primary_key=True))
    artifacts = Artifact.__table__.to_metadata(metadata)
    artifacts.c.validation_issues.type = JSON()
    artifacts.c.validation_issues.server_default = None
    artifacts.c.source_metadata.type = JSON()
    artifacts.c.source_metadata.server_default = None
    slug_constraint = next(
        item for item in organization.constraints if item.name == "ck_organizations_slug"
    )
    organization.constraints.remove(slug_constraint)
    organization.append_constraint(CheckConstraint(
        "slug REGEXP '^[a-z0-9]+(-[a-z0-9]+)*$'", name="ck_organizations_slug"
    ))
    sha_constraint = next(
        item for item in artifacts.constraints if item.name == "ck_artifacts_sha256"
    )
    artifacts.constraints.remove(sha_constraint)
    artifacts.append_constraint(CheckConstraint(
        "sha256 REGEXP '^[0-9a-f]{64}$'", name="ck_artifacts_sha256"
    ))
    metadata.create_all(engine)
    try:
        yield sessionmaker(bind=engine, autoflush=False, autocommit=False)
    finally:
        engine.dispose()


@pytest.fixture
def workflow_factory():
    """SQLite Device/Snapshot/Artifact schema for fast API workflow tests."""
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    @event.listens_for(engine, "connect")
    def sqlite_functions(connection, _record):
        def jsonb_typeof(value):
            parsed = json.loads(value) if isinstance(value, str) else value
            return "array" if isinstance(parsed, list) else "object" if isinstance(parsed, dict) else "other"

        connection.execute("PRAGMA foreign_keys=ON")
        connection.create_function("btrim", 1, lambda value: value.strip())
        connection.create_function("char_length", 1, len)
        connection.create_function("jsonb_typeof", 1, jsonb_typeof)
        connection.create_function(
            "regexp", 2, lambda pattern, value: re.fullmatch(pattern, value) is not None
        )

    metadata = MetaData()
    organization = Organization.__table__.to_metadata(metadata)
    User.__table__.to_metadata(metadata)
    Device.__table__.to_metadata(metadata)
    snapshots = Snapshot.__table__.to_metadata(metadata)
    artifacts = Artifact.__table__.to_metadata(metadata)
    audits = Audit.__table__.to_metadata(metadata)
    jobs = Job.__table__.to_metadata(metadata)
    for column_name in ("validation_issues", "source_metadata"):
        artifacts.c[column_name].type = JSON()
        artifacts.c[column_name].server_default = None
    for column_name in (
        "selected_frameworks", "version_refs", "profile_resolution",
        "verdict_counts", "severity_counts", "coverage",
    ):
        audits.c[column_name].type = JSON()
    jobs.c.payload.type = JSON()
    jobs.c.payload.server_default = None
    for table, constraint_name, expression in (
        (organization, "ck_organizations_slug", "slug REGEXP '^[a-z0-9]+(-[a-z0-9]+)*$'"),
        (snapshots, "ck_snapshots_snapshot_hash", "snapshot_hash REGEXP '^[0-9a-f]{64}$'"),
        (artifacts, "ck_artifacts_sha256", "sha256 REGEXP '^[0-9a-f]{64}$'"),
    ):
        constraint = next(item for item in table.constraints if item.name == constraint_name)
        table.constraints.remove(constraint)
        table.append_constraint(CheckConstraint(expression, name=constraint_name))
    metadata.create_all(engine)
    try:
        yield sessionmaker(bind=engine, autoflush=False, autocommit=False)
    finally:
        engine.dispose()
