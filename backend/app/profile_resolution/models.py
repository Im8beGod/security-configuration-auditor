from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any
from uuid import UUID

from app.db.models import ArtifactEvidenceType, DeviceClass


class SignalStrength(str, Enum):
    STRONGEST = "strongest"
    STRONG = "strong"
    MEDIUM = "medium"
    WEAK = "weak"


class ResolutionConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNRESOLVED = "unresolved"


class ResolutionStatus(str, Enum):
    RESOLVED = "resolved"
    PARTIALLY_RESOLVED = "partially_resolved"
    UNSUPPORTED = "unsupported"
    CONFLICT = "conflict"
    UNRESOLVED = "unresolved"
    AMBIGUOUS = "ambiguous"
    INCOMPATIBLE = "incompatible"
    VERSION_UNKNOWN = "version_unknown"


@dataclass(frozen=True)
class EvidenceSignal:
    artifact_id: UUID
    evidence_type: ArtifactEvidenceType
    line_number: int | None
    category: str
    signal_id: str
    strength: SignalStrength
    extracted_fields: tuple[str, ...] = ()
    source_label: str | None = None


@dataclass(frozen=True)
class ResolutionConflict:
    code: str
    artifact_ids: tuple[UUID, ...]


@dataclass(frozen=True)
class ProfileResolutionResult:
    vendor: str | None
    product_family: str | None
    os: str | None
    os_version: str | None
    model: str | None
    serial_number: str | None
    device_class: DeviceClass | None
    selected_profile_id: str | None
    selected_profile_version_id: str | None
    confidence: ResolutionConfidence
    resolution_status: ResolutionStatus
    supporting_signals: tuple[EvidenceSignal, ...]
    unresolved_reasons: tuple[str, ...]
    conflicts: tuple[ResolutionConflict, ...]

    @property
    def identity_provenance(self) -> dict[str, list[dict[str, Any]]]:
        provenance: dict[str, list[dict[str, Any]]] = {}
        for signal in self.supporting_signals:
            for field in signal.extracted_fields:
                provenance.setdefault(field, []).append({
                    "artifact_id": str(signal.artifact_id),
                    "source": signal.source_label,
                    "line": signal.line_number,
                    "basis": signal.signal_id,
                    "confidence": signal.strength.value,
                })
        return provenance

    def to_persisted(self) -> dict[str, Any]:
        """Return exactly the frozen Audit.profile_resolution contract."""
        return {
            "profile_id": self.selected_profile_id,
            "profile_version_id": self.selected_profile_version_id,
            "vendor": self.vendor,
            "product_family": self.product_family,
            "os": self.os,
            "os_version": self.os_version,
            "model": self.model,
            "serial_number": self.serial_number,
            "confidence": self.confidence.value,
            "resolution_status": self.resolution_status.value,
            "identity_provenance": self.identity_provenance,
            "conflicts": [
                {"code": item.code, "artifact_ids": [str(value) for value in item.artifact_ids]}
                for item in self.conflicts
            ],
        }
