from datetime import datetime, timezone
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.models import SnapshotGroupingStatus, SnapshotSource, SnapshotStatus
from app.ingestion.schemas import ArtifactResponse


class SnapshotCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str | None = Field(default=None, max_length=255)
    captured_at: datetime | None = None
    source: SnapshotSource = SnapshotSource.UPLOAD
    grouping_status: SnapshotGroupingStatus = SnapshotGroupingStatus.MANUALLY_CONFIRMED

    @field_validator("label")
    @classmethod
    def normalize_label(cls, value: str | None) -> str | None:
        return value.strip() or None if value is not None else None

    @field_validator("captured_at")
    @classmethod
    def require_aware_capture_time(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("captured_at must include a timezone")
            return value.astimezone(timezone.utc)
        return None

    @field_validator("grouping_status")
    @classmethod
    def reject_unperformed_automatic_grouping(
        cls, value: SnapshotGroupingStatus
    ) -> SnapshotGroupingStatus:
        if value == SnapshotGroupingStatus.AUTOMATIC:
            raise ValueError("Automatic grouping is not available in Step 4B")
        return value


class SnapshotUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str | None = Field(default=None, max_length=255)
    captured_at: datetime | None = None
    grouping_status: SnapshotGroupingStatus | None = None

    _normalize_label = field_validator("label")(SnapshotCreate.normalize_label.__func__)
    _require_aware_capture_time = field_validator("captured_at")(
        SnapshotCreate.require_aware_capture_time.__func__
    )

    @field_validator("grouping_status")
    @classmethod
    def reject_null_grouping_status(cls, value: SnapshotGroupingStatus | None):
        if value is None:
            raise ValueError("grouping_status must not be null")
        if value == SnapshotGroupingStatus.AUTOMATIC:
            raise ValueError("Automatic grouping is not available in Step 4B")
        return value


class SnapshotResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    snapshot_id: UUID
    device_id: UUID
    organization_id: UUID
    label: str | None
    captured_at: datetime | None
    ingested_at: datetime
    status: SnapshotStatus
    grouping_status: SnapshotGroupingStatus
    snapshot_hash: str
    artifact_count: int
    source: SnapshotSource
    created_by: UUID | None
    created_at: datetime
    schema_version: str
    artifacts: list[ArtifactResponse]
