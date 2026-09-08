from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class ApplicationSettings(BaseSettings):
    """Non-secret routing configuration, also inherited by full Settings."""

    model_config = SettingsConfigDict(
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "SIH 26155 Network Security Compliance Auditor"
    app_env: str = "development"
    api_prefix: str = "/api/v1"
    frontend_origin: str = "http://localhost:5173"

    @field_validator("api_prefix")
    @classmethod
    def validate_api_prefix(cls, value: str) -> str:
        prefix = value.strip()
        if not prefix.startswith("/"):
            raise ValueError("API prefix must start with '/'")
        if prefix == "/" or prefix.endswith("/"):
            raise ValueError("API prefix must identify a non-root path without a trailing '/'")
        return prefix

    @field_validator("frontend_origin")
    @classmethod
    def validate_frontend_origin(cls, value: str) -> str:
        origin = value.strip().rstrip("/")
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Frontend origin must be an HTTP(S) origin without a path")
        return origin


class Settings(ApplicationSettings):
    """Validated runtime configuration; secrets remain required on use."""

    postgres_host: str = "postgres"
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_db: str = "security_auditor"
    postgres_user: str = "security_auditor"
    postgres_password: SecretStr

    jwt_secret: SecretStr = Field(min_length=32)
    jwt_algorithm: Literal["HS256"] = "HS256"
    jwt_access_token_expire_minutes: int = Field(default=30, gt=0)

    auth_cookie_name: str = Field(
        default="sih26155_access_token", pattern=r"^[A-Za-z0-9_-]+$"
    )
    auth_cookie_secure: bool = False
    auth_cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    auth_cookie_path: str = Field(default="/", pattern=r"^/[^\s;]*$")

    artifact_storage_path: Path = Path("/app/storage/artifacts")
    report_storage_path: Path = Path("/app/storage/reports")
    artifact_max_upload_bytes: int = Field(default=10 * 1024 * 1024, ge=1)
    artifact_max_bulk_files: int = Field(default=20, ge=1, le=100)
    worker_poll_interval_seconds: float = Field(
        default=1.0, ge=0.1, allow_inf_nan=False
    )
    ai_mapping_suggestions_enabled: bool = False
    ai_mapping_provider: Literal["ollama"] = "ollama"
    ai_ollama_base_url: str = "http://localhost:11434"
    ai_ollama_model: str = Field(default="qwen2.5-coder:7b-instruct-q4_K_M", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:/-]+$")
    ai_ollama_timeout_seconds: float = Field(default=120, ge=1, le=300)

    @field_validator("ai_ollama_model")
    @classmethod
    def validate_local_model(cls, value: str) -> str:
        if value.lower().endswith((":cloud", "-cloud")):
            raise ValueError("Cloud models are not permitted for local mapping assistance")
        return value

    @field_validator("ai_ollama_base_url")
    @classmethod
    def validate_local_ai_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1", "host.docker.internal", "ollama"} or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("Ollama must use a local HTTP origin without credentials or a path")
        return value.rstrip("/")

    @model_validator(mode="after")
    def validate_cookie_security(self) -> "Settings":
        if self.auth_cookie_samesite == "none" and not self.auth_cookie_secure:
            raise ValueError("SameSite=None requires AUTH_COOKIE_SECURE=true")
        return self

    @property
    def database_url(self) -> str:
        return URL.create(
            drivername="postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        ).render_as_string(hide_password=False)


@lru_cache
def get_application_settings() -> ApplicationSettings:
    """Load routing settings without requiring database or JWT secrets."""

    return ApplicationSettings()


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide validated application settings."""

    return Settings()
