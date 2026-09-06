from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.models import DeviceClass, DeviceIdentityStatus


class DeviceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str = Field(min_length=1, max_length=255)
    latest_hostname: str | None = Field(default=None, max_length=255)
    stable_serial_number: str | None = Field(default=None, max_length=255)
    asset_tag: str | None = Field(default=None, max_length=255)
    device_class: DeviceClass = DeviceClass.UNKNOWN
    identity_status: DeviceIdentityStatus = DeviceIdentityStatus.MANUALLY_CONFIRMED

    @field_validator("display_name")
    @classmethod
    def normalize_display_name(cls, value: str) -> str:
        if not (normalized := value.strip()):
            raise ValueError("Display name must not be blank")
        return normalized

    @field_validator("latest_hostname", "stable_serial_number", "asset_tag")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class DeviceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    latest_hostname: str | None = Field(default=None, max_length=255)
    stable_serial_number: str | None = Field(default=None, max_length=255)
    asset_tag: str | None = Field(default=None, max_length=255)
    device_class: DeviceClass | None = None
    identity_status: DeviceIdentityStatus | None = None
    is_active: bool | None = None

    @field_validator("display_name")
    @classmethod
    def normalize_updated_display_name(cls, value: str | None) -> str:
        if value is None or not (normalized := value.strip()):
            raise ValueError("Display name must not be blank")
        return normalized

    @field_validator("device_class", "identity_status", "is_active")
    @classmethod
    def reject_null_required_fields(cls, value):
        if value is None:
            raise ValueError("Field must not be null")
        return value

    _normalize_optional_text = field_validator(
        "latest_hostname", "stable_serial_number", "asset_tag"
    )(DeviceCreate.normalize_optional_text.__func__)


class DeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    device_id: UUID
    organization_id: UUID
    display_name: str
    latest_hostname: str | None
    stable_serial_number: str | None
    asset_tag: str | None
    device_class: DeviceClass
    identity_status: DeviceIdentityStatus
    first_seen_at: datetime
    last_seen_at: datetime
    is_active: bool
    created_at: datetime
    updated_at: datetime
    schema_version: str
