from typing import Any
from uuid import UUID
from pydantic import BaseModel


class CoverageAggregate(BaseModel):
    numerator: int
    denominator: int
    percentage: float | None
    status: str


class DashboardDevice(BaseModel):
    device_id: UUID
    display_name: str
    latest_audit_id: UUID | None
    latest_audit_status: str | None
    latest_completed_audit_id: UUID | None


class RecentAudit(BaseModel):
    audit_id: UUID
    device_id: UUID
    device_name: str
    status: str
    created_at: Any
    completed_at: Any | None
    fail_count: int
    unknown_count: int
    critical_count: int
    high_count: int


class DashboardResponse(BaseModel):
    total_devices: int
    audited_devices: int
    unaudited_devices: int
    critical_risk_devices: int
    high_risk_devices: int
    devices_needing_review: int
    verdict_distribution: dict[str, int]
    severity_distribution: dict[str, int]
    audit_status_distribution: dict[str, int]
    vendor_distribution: dict[str, int]
    profile_distribution: dict[str, int]
    device_family_distribution: dict[str, int]
    coverage: dict[str, CoverageAggregate]
    devices: list[DashboardDevice]
    recent_audits: list[RecentAudit]
