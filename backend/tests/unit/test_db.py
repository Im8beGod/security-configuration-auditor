from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, make_url
from sqlalchemy.orm import Session

import app.db.models  # noqa: F401
import app.db.session as db_session
from app.core.config import Settings
from app.db import Base, check_database_connection
from app.db.engine import create_database_engine
from app.db.session import create_session_factory


@pytest.fixture
def database_settings() -> Settings:
    return Settings(
        postgres_host="postgres",
        postgres_port=5432,
        postgres_db="security_auditor",
        postgres_user="security_auditor",
        postgres_password="test_database_password",
        jwt_secret="test-jwt-secret-with-at-least-32-characters",
        _env_file=None,
    )


def test_base_has_current_identity_metadata() -> None:
    assert Base.metadata is not None
    assert set(Base.metadata.tables) == {
    "artifacts", "audits", "devices", "effective_states", "findings", "jobs", "organizations", "security_facts",
        "snapshots", "users"
    }


def test_database_engine_uses_settings_url(
    database_settings: Settings,
) -> None:
    engine = create_database_engine(database_settings)

    try:
        assert engine.url == make_url(database_settings.database_url)
        assert engine.url.drivername == "postgresql+psycopg"
        assert engine.dialect.name == "postgresql"
        assert engine.dialect.driver == "psycopg"
    finally:
        engine.dispose()


def test_session_factory_is_bound_and_creates_session() -> None:
    engine = create_engine("sqlite://")
    session_factory = create_session_factory(engine)

    try:
        assert session_factory.kw["bind"] is engine
        assert session_factory.kw["autocommit"] is False
        assert session_factory.kw["autoflush"] is False

        session = session_factory()
        assert isinstance(session, Session)
        session.close()
    finally:
        engine.dispose()


def test_get_db_yields_and_closes_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_engine("sqlite://")
    session_factory = create_session_factory(engine)
    session = session_factory()
    close = MagicMock(wraps=session.close)
    monkeypatch.setattr(session, "close", close)
    monkeypatch.setattr(db_session, "get_session_factory", lambda: lambda: session)

    dependency = db_session.get_db()
    yielded_session = next(dependency)

    assert isinstance(yielded_session, Session)
    dependency.close()
    close.assert_called_once_with()
    engine.dispose()


def test_connectivity_helper_executes_select_one() -> None:
    engine = create_engine("sqlite://")

    try:
        assert check_database_connection(engine) is True
    finally:
        engine.dispose()
