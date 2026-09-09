from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import ApplicationSettings, Settings, get_settings


def set_required_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POSTGRES_PASSWORD", "test_database_password")
    monkeypatch.setenv("JWT_SECRET", "test-jwt-secret-with-at-least-32-characters")


def test_settings_load_typed_environment_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_required_environment(monkeypatch)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("API_PREFIX", "/api/test")
    monkeypatch.setenv("FRONTEND_ORIGIN", "https://frontend.example.test/")
    monkeypatch.setenv("POSTGRES_HOST", "db.internal")
    monkeypatch.setenv("POSTGRES_PORT", "5544")
    monkeypatch.setenv("POSTGRES_DB", "audits")
    monkeypatch.setenv("POSTGRES_USER", "auditor")
    monkeypatch.setenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "45")
    monkeypatch.setenv("ARTIFACT_STORAGE_PATH", "/tmp/audit-artifacts")
    monkeypatch.setenv("REPORT_STORAGE_PATH", "/tmp/audit-reports")
    monkeypatch.setenv("WORKER_POLL_INTERVAL_SECONDS", "2.5")
    monkeypatch.setenv("WORKER_JOB_LEASE_SECONDS", "120")
    monkeypatch.setenv("WORKER_HEARTBEAT_INTERVAL_SECONDS", "30")
    monkeypatch.setenv("ARTIFACT_MAX_UPLOAD_BYTES", "12345")
    monkeypatch.setenv("ARTIFACT_MAX_BULK_FILES", "7")

    settings = Settings(_env_file=None)

    assert settings.app_env == "test"
    assert settings.api_prefix == "/api/test"
    assert settings.frontend_origin == "https://frontend.example.test"
    assert settings.postgres_port == 5544
    assert isinstance(settings.postgres_port, int)
    assert settings.jwt_access_token_expire_minutes == 45
    assert isinstance(settings.jwt_access_token_expire_minutes, int)
    assert settings.artifact_storage_path == Path("/tmp/audit-artifacts")
    assert settings.report_storage_path == Path("/tmp/audit-reports")
    assert settings.worker_poll_interval_seconds == 2.5
    assert settings.worker_job_lease_seconds == 120
    assert settings.worker_heartbeat_interval_seconds == 30
    assert settings.artifact_max_upload_bytes == 12345
    assert settings.artifact_max_bulk_files == 7
    assert isinstance(settings.worker_poll_interval_seconds, float)
    assert settings.database_url == (
        "postgresql+psycopg://auditor:test_database_password"
        "@db.internal:5544/audits"
    )


def test_api_prefix_defaults_to_version_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_required_environment(monkeypatch)
    monkeypatch.delenv("API_PREFIX", raising=False)

    settings = Settings(_env_file=None)

    assert settings.api_prefix == "/api/v1"


def test_api_prefix_rejects_invalid_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_required_environment(monkeypatch)
    monkeypatch.setenv("API_PREFIX", "api/v1")

    with pytest.raises(ValidationError, match="API prefix must start"):
        Settings(_env_file=None)


def test_frontend_origin_rejects_wildcards_and_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_required_environment(monkeypatch)
    for origin in ("*", "https://example.test/app", "https://user@example.test"):
        monkeypatch.setenv("FRONTEND_ORIGIN", origin)
        with pytest.raises(ValidationError, match="Frontend origin"):
            Settings(_env_file=None)


def test_missing_jwt_secret_has_clear_validation_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("POSTGRES_PASSWORD", "test_database_password")
    monkeypatch.delenv("JWT_SECRET", raising=False)

    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)

    assert any(
        error["loc"] == ("jwt_secret",) and error["type"] == "missing"
        for error in exc_info.value.errors()
    )


def test_get_settings_returns_cached_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_required_environment(monkeypatch)
    get_settings.cache_clear()

    try:
        assert get_settings() is get_settings()
    finally:
        get_settings.cache_clear()


def test_cookie_environment_is_typed(monkeypatch):
    set_required_environment(monkeypatch)
    monkeypatch.setenv("AUTH_COOKIE_NAME", "test_cookie")
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")
    monkeypatch.setenv("AUTH_COOKIE_SAMESITE", "strict")
    monkeypatch.setenv("AUTH_COOKIE_PATH", "/api")
    settings = Settings(_env_file=None)
    assert settings.auth_cookie_name == "test_cookie"
    assert settings.auth_cookie_secure is True
    assert settings.auth_cookie_samesite == "strict"
    assert settings.auth_cookie_path == "/api"


@pytest.mark.parametrize("field,value", [
    ("auth_cookie_name", "bad;cookie"),
    ("auth_cookie_path", "relative"),
    ("auth_cookie_samesite", "unsupported"),
    ("jwt_access_token_expire_minutes", 0),
    ("jwt_algorithm", "none"),
])
def test_invalid_auth_configuration_rejected(auth_settings, field, value):
    values = auth_settings.model_dump()
    values[field] = value
    with pytest.raises(ValidationError):
        Settings(**values)


def test_cross_site_cookie_requires_secure(auth_settings):
    values = auth_settings.model_dump()
    values.update(auth_cookie_samesite="none", auth_cookie_secure=False)
    with pytest.raises(ValidationError, match="requires AUTH_COOKIE_SECURE"):
        Settings(**values)
    values["auth_cookie_secure"] = True
    assert Settings(**values).auth_cookie_samesite == "none"


def test_application_settings_require_no_secrets(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.delenv("POSTGRES_PASSWORD", raising=False)
    monkeypatch.setenv("API_PREFIX", "/api/test")
    assert ApplicationSettings().api_prefix == "/api/test"


def test_worker_poll_interval_default_and_validation(auth_settings):
    assert auth_settings.worker_poll_interval_seconds == 1.0
    assert auth_settings.worker_job_lease_seconds == 60.0
    assert auth_settings.worker_heartbeat_interval_seconds == 15.0
    values = auth_settings.model_dump()
    values["worker_poll_interval_seconds"] = 0.05
    with pytest.raises(ValidationError):
        Settings(**values)
    values = auth_settings.model_dump()
    values.update(worker_job_lease_seconds=30, worker_heartbeat_interval_seconds=30)
    with pytest.raises(ValidationError, match="heartbeat interval"):
        Settings(**values)
