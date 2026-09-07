from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict
from app.db.models.report import ReportStatus

class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    report_id: UUID; organization_id: UUID; device_id: UUID; audit_id: UUID
    report_type: str; format: str; status: ReportStatus
    sha256: str | None; byte_size: int | None
    template_version: str; generator_version: str; audit_schema_version: str
    source_finding_ids: list[str]; generated_by: UUID | None
    created_at: datetime; generated_at: datetime | None
    failure_code: str | None; failure_message: str | None; schema_version: str
