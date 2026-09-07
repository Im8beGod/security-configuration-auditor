from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from typing import Annotated

import jwt
import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import delete, update

from app.auth.dependencies import require_roles
from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.models import Organization, User, UserRole
from app.db.session import get_db
from app.main import create_app


@pytest.fixture
def auth_context(identity_factory, auth_settings):
    password = "test-only-admin-password"
    org_id, user_id = bootstrap_admin(
        identity_factory, "Auth Tests", "auth-tests", "admin@example.invalid", password
    )
    application = create_app(auth_settings)
    application.dependency_overrides[get_settings] = lambda: auth_settings

    def session_dependency():
        with identity_factory() as db:
            yield db

    application.dependency_overrides[get_db] = session_dependency

    # RBAC demonstration exists solely in this fixture's isolated application.
    for role in UserRole:
        def endpoint(
            user: Annotated[User, Depends(require_roles(role))],
        ):
            return {"role": user.role.value}

        application.add_api_route(
            f"/test-only/{role.value}", endpoint, methods=["GET"]
        )
    with TestClient(application) as client:
        yield client, identity_factory, auth_settings, org_id, user_id, password


def login(context, **overrides):
    client, _, _, _, _, password = context
    return client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.invalid", "password": password, **overrides},
    )


def test_login_cookie_safe_response_and_email_normalization(auth_context):
    response = login(auth_context, email=" ADMIN@EXAMPLE.INVALID ")
    assert response.status_code == 200
    assert set(response.json()) == {
        "user_id", "organization_id", "email", "role", "is_active"
    }
    cookie = SimpleCookie(response.headers["set-cookie"])["test_auth"]
    assert cookie["httponly"]
    assert cookie["samesite"] == "lax"
    assert not cookie["secure"]
    assert cookie["path"] == "/"
    assert cookie["max-age"] == "1800"
    assert cookie.value not in response.text
    assert "password" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_cookie_secure_and_logout_attributes(auth_context):
    client, _, settings, *_ = auth_context
    settings.auth_cookie_secure = True
    settings.auth_cookie_path = "/api"
    settings.auth_cookie_samesite = "strict"
    response = login(auth_context)
    cookie = SimpleCookie(response.headers["set-cookie"])["test_auth"]
    assert cookie["secure"] and cookie["httponly"]
    assert cookie["samesite"] == "strict" and cookie["path"] == "/api"
    logout = client.post("/api/v1/auth/logout")
    removed = SimpleCookie(logout.headers["set-cookie"])["test_auth"]
    assert removed["path"] == cookie["path"]
    assert removed["secure"] and removed["httponly"]
    assert removed["max-age"] == "0"


def test_invalid_credentials_are_indistinguishable(auth_context):
    wrong = login(auth_context, password="incorrect")
    missing = login(auth_context, email="absent@example.invalid")
    assert wrong.status_code == missing.status_code == 401
    assert wrong.json() == missing.json() == {"detail": "Invalid email or password"}


def test_authentication_reads_never_commit(auth_context, monkeypatch):
    def unexpected_commit(_session):
        raise AssertionError("Authentication must not commit")

    client, factory, *_ = auth_context
    monkeypatch.setattr(factory.class_, "commit", unexpected_commit)
    assert login(auth_context).status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 200


@pytest.mark.parametrize("entity", ["user", "organization", "malformed_hash"])
def test_login_rejects_inactive_identity_and_malformed_hash(auth_context, entity):
    _, factory, _, org_id, user_id, _ = auth_context
    with factory.begin() as db:
        if entity == "organization":
            db.execute(update(Organization).where(
                Organization.organization_id == org_id
            ).values(is_active=False))
        else:
            values = {"password_hash": "malformed"} if entity == "malformed_hash" else {
                "is_active": False
            }
            db.execute(update(User).where(User.user_id == user_id).values(**values))
    response = login(auth_context)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}


def test_oversized_password_and_invalid_inputs_never_echo_secrets(auth_context):
    password = "sensitive-test-input-" * 100
    response = login(auth_context, password=password)
    assert response.status_code == 422
    assert password not in response.text
    client = auth_context[0]
    response = client.post("/api/v1/auth/login", json={
        "email": None, "password": {"secret": password}
    })
    assert response.status_code == 422
    assert password not in response.text
    response = client.post(
        "/api/v1/auth/login",
        content='{"password":"sensitive-test-input-",invalid}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert "sensitive-test-input-" not in response.text


def test_me_and_rbac_reload_persisted_roles(auth_context):
    client, factory, _, _, user_id, _ = auth_context
    assert login(auth_context).status_code == 200
    for persisted_role in UserRole:
        with factory.begin() as db:
            db.execute(update(User).where(User.user_id == user_id).values(
                role=persisted_role
            ))
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 200
        assert response.json()["role"] == persisted_role.value
        assert "password_hash" not in response.text
        for allowed_role in UserRole:
            response = client.get(f"/test-only/{allowed_role.value}")
            expected = 200 if allowed_role == persisted_role else 403
            assert response.status_code == expected


def test_missing_cookie_is_401_for_me_and_rbac(auth_context):
    client = auth_context[0]
    assert client.get("/api/v1/auth/me").status_code == 401
    for role in UserRole:
        assert client.get(f"/test-only/{role.value}").status_code == 401


@pytest.mark.parametrize("case", ["malformed", "expired", "missing_user", "user", "organization"])
def test_me_rejects_invalid_identity(auth_context, case):
    client, factory, settings, org_id, user_id, _ = auth_context
    assert login(auth_context).status_code == 200
    token = None
    if case == "malformed":
        token = "malformed"
    elif case == "expired":
        now = datetime.now(timezone.utc)
        token = jwt.encode({
            "sub": str(user_id), "iat": now - timedelta(minutes=2),
            "exp": now - timedelta(minutes=1), "type": "access",
        }, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm)
    elif case == "missing_user":
        with factory.begin() as db:
            db.execute(delete(User).where(User.user_id == user_id))
    else:
        with factory.begin() as db:
            if case == "user":
                db.execute(update(User).where(User.user_id == user_id).values(is_active=False))
            else:
                db.execute(update(Organization).where(
                    Organization.organization_id == org_id
                ).values(is_active=False))
    if token:
        client.cookies.clear()
        client.cookies.set(settings.auth_cookie_name, token)
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


def test_jwt_role_claim_cannot_elevate_user(auth_context):
    client, factory, settings, _, user_id, _ = auth_context
    with factory.begin() as db:
        db.execute(update(User).where(User.user_id == user_id).values(role=UserRole.ANALYST))
    now = datetime.now(timezone.utc)
    token = jwt.encode({
        "sub": str(user_id), "iat": now, "exp": now + timedelta(minutes=1),
        "type": "access", "role": "admin",
    }, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm)
    client.cookies.set(settings.auth_cookie_name, token)
    assert client.get("/api/v1/auth/me").json()["role"] == "analyst"
    assert client.get("/test-only/admin").status_code == 403


def test_logout_is_idempotent_and_removes_cookie(auth_context):
    client = auth_context[0]
    assert login(auth_context).status_code == 200
    response = client.post("/api/v1/auth/logout")
    assert response.status_code == 204
    assert "test_auth" not in client.cookies
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.post("/api/v1/auth/logout").status_code == 204


def test_api_surface_and_configured_prefix(auth_settings):
    auth_settings.api_prefix = "/api/test"
    application = create_app(auth_settings)
    paths = application.openapi()["paths"]
    assert {path: set(operations) for path, operations in paths.items()} == {
        "/health": {"get"},
        "/api/test/auth/login": {"post"},
        "/api/test/auth/logout": {"post"},
            "/api/test/auth/me": {"get"},
            "/api/test/dashboard": {"get"},
        "/api/test/artifacts/upload": {"post"},
        "/api/test/artifacts": {"get"},
        "/api/test/artifacts/bulk-upload": {"post"},
        "/api/test/artifacts/{artifact_id}": {"get"},
        "/api/test/audits": {"get", "post"},
        "/api/test/audits/{audit_id}": {"get"},
            "/api/test/audits/{audit_id}/reevaluation-eligibility": {"get"},
            "/api/test/audits/{audit_id}/revisions": {"get"},
            "/api/test/audits/{audit_id}/re-evaluate": {"post"},
            "/api/test/audits/{audit_id}/run": {"post"},
            "/api/test/audits/{audit_id}/findings": {"get"},
            "/api/test/audits/{audit_id}/reports": {"post"},
            "/api/test/reports/{report_id}": {"get"},
            "/api/test/reports/{report_id}/download": {"get"},
            "/api/test/findings/{finding_id}": {"get"},
            "/api/test/findings/{finding_id}/evidence": {"get"},
            "/api/test/findings/{finding_id}/remediation": {"get"},
            "/api/test/findings/{finding_id}/remediation/preview": {"post"},
        "/api/test/devices": {"get", "post"},
        "/api/test/devices/{device_id}": {"get", "patch"},
        "/api/test/devices/{device_id}/snapshots": {"get", "post"},
        "/api/test/snapshots/{snapshot_id}": {"get", "patch"},
        "/api/test/snapshots/{snapshot_id}/artifacts/{artifact_id}": {
            "delete", "post"
        },
        "/api/test/snapshots/{snapshot_id}/finalize": {"post"},
        "/api/test/jobs/{job_id}": {"get"},
        "/api/test/training/unresolved": {"get"},
        "/api/test/training/unresolved/{block_id}": {"get", "patch"},
        "/api/test/training/unresolved/{block_id}/suggest": {"post"},
        "/api/test/training/mappings": {"post"},
        "/api/test/training/mappings/{mapping_version_id}": {"get", "put"},
        "/api/test/training/mappings/{mapping_version_id}/validate": {"post"},
        "/api/test/training/mappings/{mapping_version_id}/approve": {"post"},
        "/api/test/training/mappings/{mapping_version_id}/publish": {"post"},
        "/api/test/training/mappings/{mapping_version_id}/reject": {"post"},
        "/api/test/training/mappings/{mapping_version_id}/impact": {"get"},
        "/api/test/training/knowledge-packs": {"get"},
        "/api/test/training/knowledge-packs/{pack_id}/versions": {"get"},
        "/api/test/training/canonical-fields": {"get"},
    }
    with TestClient(application) as client:
        assert client.post("/api/test/auth/register").status_code == 404
        assert client.post("/api/test/auth/signup").status_code == 404
        preflight = client.options(
            "/api/test/auth/login",
            headers={
                "Origin": auth_settings.frontend_origin,
                "Access-Control-Request-Method": "POST",
            },
        )
        assert preflight.status_code == 200
        assert preflight.headers["access-control-allow-origin"] == (
            auth_settings.frontend_origin
        )
        assert preflight.headers["access-control-allow-credentials"] == "true"
        rejected = client.options(
            "/api/test/auth/login",
            headers={
                "Origin": "https://untrusted.example",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert "access-control-allow-origin" not in rejected.headers
