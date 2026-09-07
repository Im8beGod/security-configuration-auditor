"""Opt-in verification against an already-migrated development PostgreSQL DB."""

import os
from http.cookies import SimpleCookie
from secrets import token_urlsafe
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text, update
from sqlalchemy.orm import sessionmaker

from app.cli.bootstrap_admin import BootstrapConflict, bootstrap_admin
from app.core.config import get_settings
from app.core.security import verify_password
from app.db.base import Base
from app.db.engine import create_database_engine
from app.db.models import Organization, User, UserRole
from app.db.session import get_db
from app.main import create_app


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_AUTH_POSTGRES_TEST") != "1",
    reason="Set SIH_AUTH_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def application_counts(connection):
    return {
        name: connection.scalar(select(func.count()).select_from(table))
        for name, table in Base.metadata.tables.items()
    }


def test_postgres_bootstrap_and_cookie_authentication():
    settings = get_settings().model_copy(update={
        "api_prefix": "/api/v1", "auth_cookie_name": "postgres_auth_test",
        "auth_cookie_secure": False, "auth_cookie_path": "/",
        "auth_cookie_samesite": "lax",
    })
    engine = create_database_engine(settings)
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260908_0011"
            before = application_counts(connection)
            connection.rollback()
            transaction = connection.begin()
            try:
                # CLI transactions commit savepoints, never this outer transaction.
                # Everything created/changed by verification is rolled back even on failure.
                factory = sessionmaker(
                    bind=connection, join_transaction_mode="create_savepoint",
                    autoflush=False, autocommit=False,
                )
                suffix = uuid4().hex
                email, slug = f"auth-{suffix}@example.invalid", f"auth-{suffix}"
                password = token_urlsafe(32)
                org_id, user_id = bootstrap_admin(
                    factory, "Temporary Auth Verification", slug, email, password
                )
                with factory() as db:
                    user = db.get(User, user_id)
                    assert db.get(Organization, org_id) is not None
                    assert user.organization_id == org_id
                    assert user.role == UserRole.ADMIN
                    assert user.password_hash.startswith("$argon2id$")
                    assert verify_password(password, user.password_hash)
                created = application_counts(connection)
                assert created == {
                    name: count + (1 if name in {"organizations", "users"} else 0)
                    for name, count in before.items()
                }
                for duplicate_email, duplicate_slug in [
                    (email, f"other-{suffix}"), (f"other-{email}", slug)
                ]:
                    with pytest.raises(BootstrapConflict):
                        bootstrap_admin(
                            factory, "Must Not Persist", duplicate_slug,
                            duplicate_email, password,
                        )
                    assert application_counts(connection) == created

                application = create_app(settings)
                application.dependency_overrides[get_settings] = lambda: settings

                def session_dependency():
                    with factory() as db:
                        yield db

                application.dependency_overrides[get_db] = session_dependency
                with TestClient(application) as client:
                    credentials = {"email": email.upper(), "password": password}
                    response = client.post("/api/v1/auth/login", json=credentials)
                    assert response.status_code == 200
                    cookie = SimpleCookie(response.headers["set-cookie"])[settings.auth_cookie_name]
                    assert cookie["httponly"] and cookie["samesite"] == "lax"
                    assert cookie.value not in response.text
                    assert "password" not in response.text
                    response = client.get("/api/v1/auth/me")
                    assert response.status_code == 200
                    assert response.json()["role"] == "admin"
                    assert response.json()["user_id"] == str(user_id)
                    assert client.post("/api/v1/auth/login", json={
                        **credentials, "password": token_urlsafe(32)
                    }).status_code == 401
                    with factory.begin() as db:
                        db.execute(update(User).where(User.user_id == user_id).values(
                            role=UserRole.ANALYST
                        ))
                    assert client.get("/api/v1/auth/me").json()["role"] == "analyst"
                    with factory.begin() as db:
                        db.execute(update(User).where(User.user_id == user_id).values(
                            is_active=False
                        ))
                    assert client.get("/api/v1/auth/me").status_code == 401
                    assert client.post("/api/v1/auth/login", json=credentials).status_code == 401
                    with factory.begin() as db:
                        db.execute(update(User).where(User.user_id == user_id).values(
                            is_active=True
                        ))
                        db.execute(update(Organization).where(
                            Organization.organization_id == org_id
                        ).values(is_active=False))
                    assert client.get("/api/v1/auth/me").status_code == 401
                    assert client.post("/api/v1/auth/login", json=credentials).status_code == 401
                    assert client.post("/api/v1/auth/logout").status_code == 204
                    assert settings.auth_cookie_name not in client.cookies
            finally:
                transaction.rollback()
        with engine.connect() as connection:
            assert application_counts(connection) == before
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260908_0011"
    finally:
        engine.dispose()
