from __future__ import annotations

import re
from dataclasses import dataclass
from uuid import UUID

from app.db.models import ArtifactEvidenceType, DeviceClass
from app.profile_resolution.evidence import EvidenceDocument, SnapshotEvidence
from app.profile_resolution.models import (
    EvidenceSignal,
    ProfileResolutionResult,
    ResolutionConfidence,
    ResolutionConflict,
    ResolutionStatus,
    SignalStrength,
)
from app.profile_resolution.registry import CISCO_IOS_XE_17, FORTIOS_7, compatible_manifests


MAX_LINE_CHARACTERS = 4096
MAX_LINES_PER_ARTIFACT = 10_000
MAX_SUPPORTING_SIGNALS = 200
VALUE_PATTERN = r"([A-Za-z0-9][A-Za-z0-9()._/-]{0,63})"

IOS_XE_VERSION_PATTERNS = (
    re.compile(
        rf"\bCisco IOS XE Software\b.{{0,200}}?\bVersion\s+{VALUE_PATTERN}",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\bCisco IOS Software\b.{{0,250}}?\b(?:IOS[-_ ]?XE|[A-Z0-9]+_IOSXE)\b"
        rf".{{0,250}}?\bVersion\s+{VALUE_PATTERN}",
        re.IGNORECASE,
    ),
)
IOS_XE_MARKER = re.compile(
    r"\b(?:Cisco IOS[- ]?XE Software|[A-Z0-9]+_IOSXE)\b", re.IGNORECASE
)
IOS_VERSION_PATTERN = re.compile(
    rf"\bCisco IOS Software\b.{{0,300}}?\bVersion\s+{VALUE_PATTERN}", re.IGNORECASE
)
MODEL_NUMBER_PATTERN = re.compile(
    rf"^\s*Model Number\s*:\s*{VALUE_PATTERN}", re.IGNORECASE
)
CISCO_PROCESSOR_PATTERN = re.compile(
    rf"^\s*cisco\s+{VALUE_PATTERN}\s+\(.{{0,160}}\)\s+processor\b", re.IGNORECASE
)
CHASSIS_NAME_PATTERN = re.compile(r'^\s*NAME\s*:\s*"[^"]*chassis[^"]*"', re.IGNORECASE)
PID_PATTERN = re.compile(rf"\bPID\s*:\s*{VALUE_PATTERN}", re.IGNORECASE)
SERIAL_PATTERNS = (
    re.compile(rf"\bSystem Serial Number\s*:\s*{VALUE_PATTERN}", re.IGNORECASE),
    re.compile(rf"\bProcessor board ID\s+{VALUE_PATTERN}", re.IGNORECASE),
)
SN_PATTERN = re.compile(rf"\bSN\s*:\s*{VALUE_PATTERN}", re.IGNORECASE)
JUNOS_PATTERN = re.compile(
    rf"\b(?:JUNOS Software Release|Junos:)\s*\[?{VALUE_PATTERN}", re.IGNORECASE
)
FORTIOS_PATTERN = re.compile(rf"\bFortiOS\s+v?{VALUE_PATTERN}", re.IGNORECASE)
ARISTA_EOS_PATTERN = re.compile(rf"\bArista\b.{{0,120}}\bEOS\b.{{0,80}}?{VALUE_PATTERN}", re.IGNORECASE)
FILENAME_HINT_PATTERN = re.compile(
    r"(?:^|[^a-z0-9])(?:cisco|ios[-_ ]?xe)(?:[^a-z0-9]|$)", re.IGNORECASE
)

CONFIG_SYNTAX_PATTERNS = {
    "hostname": re.compile(r"^hostname\s+\S+", re.IGNORECASE),
    "interface": re.compile(r"^interface\s+\S+", re.IGNORECASE),
    "line": re.compile(r"^line\s+(?:vty|con|console|aux)\b", re.IGNORECASE),
    "aaa": re.compile(r"^aaa\s+", re.IGNORECASE),
    "access_list": re.compile(r"^(?:ip|ipv6)\s+access-list\s+", re.IGNORECASE),
    "snmp": re.compile(r"^snmp-server\s+", re.IGNORECASE),
    "routing": re.compile(r"^router\s+(?:bgp|ospf|eigrp|isis)\b", re.IGNORECASE),
}


@dataclass(frozen=True)
class _Identity:
    vendor: str
    os: str
    version: str | None
    signal: EvidenceSignal


@dataclass(frozen=True)
class _Hardware:
    value: str
    signal: EvidenceSignal


def resolve_profile(evidence: SnapshotEvidence) -> ProfileResolutionResult:
    signals: list[EvidenceSignal] = []
    identities: list[_Identity] = []
    models: list[_Hardware] = []
    serials: list[_Hardware] = []
    cisco_syntax_signals: list[EvidenceSignal] = []

    for document in evidence.documents:
        document_cisco_context = False
        filename_signal = _signal(
            document, None, "filename_hint", "cisco_filename_hint", SignalStrength.WEAK
        )
        if FILENAME_HINT_PATTERN.search(document.original_filename):
            _append_signal(signals, filename_signal)

        syntax_categories: set[str] = set()
        chassis_context = 0
        for line_number, line in _data_lines(document):
            match_line = line[:MAX_LINE_CHARACTERS]
            explicit_strength = (
                SignalStrength.STRONG
                if document.evidence_type == ArtifactEvidenceType.CONFIGURATION
                else SignalStrength.STRONGEST
            )

            xe_match = _first_match(IOS_XE_VERSION_PATTERNS, match_line)
            if xe_match:
                version = xe_match.group(1)
                signal = _signal(
                    document, line_number, "os_identity", "cisco_ios_xe_version",
                    explicit_strength, ("vendor", "os", "os_version"),
                )
                identities.append(_Identity("Cisco", "IOS XE", version, signal))
                document_cisco_context = True
                _append_signal(signals, signal)
            elif IOS_XE_MARKER.search(match_line):
                signal = _signal(
                    document, line_number, "os_identity", "cisco_ios_xe_marker",
                    explicit_strength, ("vendor", "os"),
                )
                identities.append(_Identity("Cisco", "IOS XE", None, signal))
                document_cisco_context = True
                _append_signal(signals, signal)
            else:
                ios_match = IOS_VERSION_PATTERN.search(match_line)
                if ios_match:
                    signal = _signal(
                        document, line_number, "os_identity", "cisco_ios_version",
                        explicit_strength, ("vendor", "os", "os_version"),
                    )
                    identities.append(_Identity("Cisco", "IOS", ios_match.group(1), signal))
                    document_cisco_context = True
                    _append_signal(signals, signal)

            for pattern, vendor, os_name, signal_id in (
                (JUNOS_PATTERN, "Juniper", "Junos", "juniper_junos_version"),
                (FORTIOS_PATTERN, "Fortinet", "FortiOS", "fortinet_fortios_version"),
                (ARISTA_EOS_PATTERN, "Arista", "EOS", "arista_eos_version"),
            ):
                other_match = pattern.search(match_line)
                if other_match:
                    signal = _signal(
                        document, line_number, "os_identity", signal_id,
                        explicit_strength, ("vendor", "os", "os_version"),
                    )
                    identities.append(_Identity(vendor, os_name, other_match.group(1), signal))
                    _append_signal(signals, signal)

            if document.evidence_type in {
                ArtifactEvidenceType.VERSION_OUTPUT,
                ArtifactEvidenceType.INVENTORY_OUTPUT,
                ArtifactEvidenceType.OPERATIONAL_OUTPUT,
                ArtifactEvidenceType.UNKNOWN_EVIDENCE,
            }:
                model_match = MODEL_NUMBER_PATTERN.search(match_line)
                processor_match = CISCO_PROCESSOR_PATTERN.search(match_line)
                model_match = processor_match or model_match
                if model_match and (
                    processor_match is not None
                    or document_cisco_context
                    or _is_recognized_cisco_model(model_match.group(1))
                ):
                    signal = _signal(
                        document, line_number, "hardware_identity", "cisco_model",
                        SignalStrength.STRONG, ("model",),
                    )
                    models.append(_Hardware(model_match.group(1), signal))
                    document_cisco_context = True
                    _append_signal(signals, signal)

                if CHASSIS_NAME_PATTERN.search(match_line):
                    chassis_context = 2
                elif chassis_context:
                    pid_match = PID_PATTERN.search(match_line)
                    if pid_match and _is_recognized_cisco_model(pid_match.group(1)):
                        signal = _signal(
                            document, line_number, "hardware_identity", "cisco_chassis_pid",
                            SignalStrength.STRONG, ("model",),
                        )
                        models.append(_Hardware(pid_match.group(1), signal))
                        document_cisco_context = True
                        _append_signal(signals, signal)
                    sn_match = SN_PATTERN.search(match_line)
                    if sn_match and document_cisco_context:
                        signal = _signal(
                            document, line_number, "hardware_identity", "cisco_chassis_serial",
                            SignalStrength.STRONG, ("serial_number",),
                        )
                        serials.append(_Hardware(sn_match.group(1), signal))
                        _append_signal(signals, signal)
                    chassis_context -= 1

                for serial_pattern in SERIAL_PATTERNS:
                    serial_match = serial_pattern.search(match_line)
                    if serial_match and document_cisco_context:
                        signal = _signal(
                            document, line_number, "hardware_identity", "cisco_serial",
                            SignalStrength.STRONG, ("serial_number",),
                        )
                        serials.append(_Hardware(serial_match.group(1), signal))
                        _append_signal(signals, signal)
                        break

            stripped = match_line.strip()
            for category, pattern in CONFIG_SYNTAX_PATTERNS.items():
                if pattern.search(stripped):
                    syntax_categories.add(category)

        if len(syntax_categories) >= 3:
            signal = _signal(
                document, None, "cli_structure", "cisco_cli_structure",
                SignalStrength.MEDIUM, ("vendor",),
            )
            cisco_syntax_signals.append(signal)
            _append_signal(signals, signal)

    return _resolve_candidates(
        identities=identities,
        models=models,
        serials=serials,
        cisco_syntax_signals=cisco_syntax_signals,
        signals=tuple(signals),
        unavailable_count=len(evidence.issues),
    )


def _resolve_candidates(
    *,
    identities: list[_Identity],
    models: list[_Hardware],
    serials: list[_Hardware],
    cisco_syntax_signals: list[EvidenceSignal],
    signals: tuple[EvidenceSignal, ...],
    unavailable_count: int,
) -> ProfileResolutionResult:
    identity_keys = {(item.vendor, item.os) for item in identities}
    if len(identity_keys) > 1:
        artifact_ids = tuple(sorted(
            {item.signal.artifact_id for item in identities}, key=str
        ))
        return _result(
            signals=signals,
            confidence=ResolutionConfidence.UNRESOLVED,
            status=ResolutionStatus.CONFLICT,
            reasons=("Conflicting explicit platform evidence",),
            conflicts=(ResolutionConflict("platform_identity_conflict", artifact_ids),),
        )

    if identity_keys:
        vendor, os_name = next(iter(identity_keys))
        matching = [item for item in identities if (item.vendor, item.os) == (vendor, os_name)]
        versions = {item.version for item in matching if item.version is not None}
        if len(versions) > 1:
            artifact_ids = tuple(sorted(
                {item.signal.artifact_id for item in matching if item.version is not None}, key=str
            ))
            return _result(
                vendor=vendor,
                os_name=os_name,
                model=_first_value(models),
                serial_number=_first_value(serials),
                signals=signals,
                confidence=ResolutionConfidence.UNRESOLVED,
                status=ResolutionStatus.CONFLICT,
                reasons=("Conflicting explicit OS versions",),
                conflicts=(ResolutionConflict("os_version_conflict", artifact_ids),),
            )

        version = next(iter(versions), None)
        model = _first_value(models) if vendor == "Cisco" else None
        serial_number = _first_value(serials) if vendor == "Cisco" else None
        product_family, device_class = _classify_hardware(model)
        explicit_confidence = (
            ResolutionConfidence.HIGH
            if any(item.signal.strength == SignalStrength.STRONGEST for item in matching)
            else ResolutionConfidence.MEDIUM
        )

        if (vendor, os_name) == ("Cisco", "IOS XE"):
            if version is None:
                return _result(
                    vendor=vendor, product_family=product_family, os_name=os_name,
                    model=model, serial_number=serial_number, device_class=device_class,
                    signals=signals, confidence=ResolutionConfidence.MEDIUM,
                    status=ResolutionStatus.PARTIALLY_RESOLVED,
                    reasons=("IOS XE version is required for profile applicability",),
                )
            candidates = compatible_manifests(vendor, os_name, version)
            if len(candidates) > 1:
                return _result(vendor=vendor, product_family=product_family, os_name=os_name, os_version=version,
                               model=model, serial_number=serial_number, device_class=device_class, signals=signals,
                               confidence=ResolutionConfidence.UNRESOLVED, status=ResolutionStatus.AMBIGUOUS,
                               reasons=("Multiple compatible profile manifests were detected",))
            if candidates:
                selected = candidates[0]
                return _result(
                    vendor=vendor, product_family=product_family, os_name=os_name,
                    os_version=version, model=model, serial_number=serial_number,
                    device_class=device_class,
                    selected_profile_id=selected.profile_id,
                    selected_profile_version_id=selected.profile_version_id,
                    signals=signals, confidence=explicit_confidence,
                    status=ResolutionStatus.RESOLVED,
                )
            return _result(
                vendor=vendor, product_family=product_family, os_name=os_name,
                os_version=version, model=model, serial_number=serial_number,
                device_class=device_class, signals=signals,
                confidence=explicit_confidence,
                status=ResolutionStatus.UNSUPPORTED,
                reasons=("Detected IOS XE version is outside the supported 17.x profile",),
            )

        if (vendor, os_name) == ("Fortinet", "FortiOS"):
            if version is None:
                return _result(
                    vendor=vendor, product_family="FortiGate", os_name=os_name,
                    signals=signals, confidence=ResolutionConfidence.MEDIUM,
                    status=ResolutionStatus.PARTIALLY_RESOLVED,
                    reasons=("FortiOS version is required for profile applicability",),
                )
            candidates = compatible_manifests(vendor, os_name, version)
            if len(candidates) > 1:
                return _result(vendor=vendor, product_family="FortiGate", os_name=os_name, os_version=version,
                               signals=signals, confidence=ResolutionConfidence.UNRESOLVED,
                               status=ResolutionStatus.AMBIGUOUS,
                               reasons=("Multiple compatible profile manifests were detected",))
            if candidates:
                selected = candidates[0]
                return _result(
                    vendor=vendor, product_family="FortiGate", os_name=os_name,
                    os_version=version, device_class=DeviceClass.FIREWALL,
                    selected_profile_id=selected.profile_id,
                    selected_profile_version_id=selected.profile_version_id,
                    signals=signals, confidence=explicit_confidence,
                    status=ResolutionStatus.RESOLVED,
                )
            return _result(
                vendor=vendor, product_family="FortiGate", os_name=os_name,
                os_version=version, signals=signals,
                confidence=explicit_confidence, status=ResolutionStatus.UNSUPPORTED,
                reasons=("Detected FortiOS version is outside the supported 7.x profile",),
            )

        return _result(
            vendor=vendor, os_name=os_name, os_version=version,
            signals=signals, confidence=explicit_confidence,
            status=ResolutionStatus.UNSUPPORTED,
            reasons=("Detected platform has no supported deep profile",),
        )

    model = _first_value(models)
    serial_number = _first_value(serials)
    product_family, device_class = _classify_hardware(model)
    if model is not None:
        return _result(
            vendor="Cisco", product_family=product_family, model=model,
            serial_number=serial_number, device_class=device_class, signals=signals,
            confidence=ResolutionConfidence.MEDIUM,
            status=ResolutionStatus.PARTIALLY_RESOLVED,
            reasons=("Cisco hardware evidence does not establish IOS XE",),
        )
    if cisco_syntax_signals:
        return _result(
            vendor="Cisco", signals=signals, confidence=ResolutionConfidence.LOW,
            status=ResolutionStatus.PARTIALLY_RESOLVED,
            reasons=("Cisco-like CLI syntax does not distinguish IOS from IOS XE",),
        )

    reasons = ["No authoritative platform evidence was detected"]
    if unavailable_count:
        reasons.append("One or more artifacts could not be inspected")
    return _result(
        signals=signals, confidence=ResolutionConfidence.UNRESOLVED,
        status=ResolutionStatus.UNRESOLVED, reasons=tuple(reasons),
    )


def _result(
    *,
    vendor: str | None = None,
    product_family: str | None = None,
    os_name: str | None = None,
    os_version: str | None = None,
    model: str | None = None,
    serial_number: str | None = None,
    device_class: DeviceClass | None = None,
    selected_profile_id: str | None = None,
    selected_profile_version_id: str | None = None,
    signals: tuple[EvidenceSignal, ...],
    confidence: ResolutionConfidence,
    status: ResolutionStatus,
    reasons: tuple[str, ...] = (),
    conflicts: tuple[ResolutionConflict, ...] = (),
) -> ProfileResolutionResult:
    return ProfileResolutionResult(
        vendor=vendor,
        product_family=product_family,
        os=os_name,
        os_version=os_version,
        model=model,
        serial_number=serial_number,
        device_class=device_class,
        selected_profile_id=selected_profile_id,
        selected_profile_version_id=selected_profile_version_id,
        confidence=confidence,
        resolution_status=status,
        supporting_signals=signals,
        unresolved_reasons=reasons,
        conflicts=conflicts,
    )


def _data_lines(document: EvidenceDocument):
    banner_delimiter: str | None = None
    for line_number, raw_line in enumerate(
        document.text.splitlines()[:MAX_LINES_PER_ARTIFACT], start=1
    ):
        line = raw_line[:MAX_LINE_CHARACTERS]
        if document.evidence_type == ArtifactEvidenceType.CONFIGURATION:
            stripped = line.strip()
            if banner_delimiter is not None:
                if banner_delimiter in stripped:
                    banner_delimiter = None
                continue
            if not stripped or stripped.startswith(("!", "#", ";")):
                continue
            banner_match = re.match(r"^banner\s+\S+\s+(\S+)", stripped, re.IGNORECASE)
            if banner_match:
                delimiter = banner_match.group(1)
                if stripped.count(delimiter) < 2:
                    banner_delimiter = delimiter
                continue
        yield line_number, line


def _first_match(patterns: tuple[re.Pattern[str], ...], line: str):
    for pattern in patterns:
        match = pattern.search(line)
        if match:
            return match
    return None


def _signal(
    document: EvidenceDocument,
    line_number: int | None,
    category: str,
    signal_id: str,
    strength: SignalStrength,
    extracted_fields: tuple[str, ...] = (),
) -> EvidenceSignal:
    return EvidenceSignal(
        artifact_id=document.artifact_id,
        evidence_type=document.evidence_type,
        line_number=line_number,
        category=category,
        signal_id=signal_id,
        strength=strength,
        extracted_fields=extracted_fields,
        source_label=document.original_filename,
    )


def _append_signal(signals: list[EvidenceSignal], signal: EvidenceSignal) -> None:
    identity = (signal.artifact_id, signal.signal_id, signal.line_number)
    if len(signals) < MAX_SUPPORTING_SIGNALS and all(
        (item.artifact_id, item.signal_id, item.line_number) != identity for item in signals
    ):
        signals.append(signal)


def _first_value(values: list[_Hardware]) -> str | None:
    return values[0].value if values else None


def _classify_hardware(model: str | None) -> tuple[str | None, DeviceClass | None]:
    if model is None:
        return None, None
    normalized = model.upper()
    if normalized.startswith(("C9", "WS-C", "CAT")):
        return "Catalyst", DeviceClass.SWITCH
    if normalized.startswith("ISR"):
        return "ISR", DeviceClass.ROUTER
    if normalized.startswith("ASR"):
        return "ASR", DeviceClass.ROUTER
    return None, None


def _is_recognized_cisco_model(model: str) -> bool:
    product_family, _device_class = _classify_hardware(model)
    return product_family is not None
