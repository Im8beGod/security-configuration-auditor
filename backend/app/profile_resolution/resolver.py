from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
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
from app.profile_resolution.registry import CISCO_IOS_XE_17, FORTIOS_7, GENERIC_CLI, GENERIC_JSON, GENERIC_XML, PROFILE_REGISTRY, ProfileManifest, compatible_manifests


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
FORTIOS_STATUS_PATTERN = re.compile(
    rf"^\s*Version:\s*(FortiGate-[A-Za-z0-9._/-]+)\s+v?{VALUE_PATTERN}(?:,\s*build\s*(\d+))?",
    re.IGNORECASE,
)
FORTIOS_HOSTNAME_PATTERN = re.compile(rf"^\s*Hostname\s*:\s*{VALUE_PATTERN}", re.IGNORECASE)
FORTIOS_SERIAL_PATTERN = re.compile(rf"^\s*Serial-Number\s*:\s*{VALUE_PATTERN}", re.IGNORECASE)
ARISTA_PRODUCT_PATTERN = re.compile(
    r"^\s*Arista\s+(vEOS(?:-lab)?|EOS|DCS-[A-Za-z0-9._/-]+)\b", re.IGNORECASE
)
ARISTA_SERIAL_PATTERN = re.compile(rf"^\s*Serial number\s*:\s*{VALUE_PATTERN}", re.IGNORECASE)
ARISTA_SOFTWARE_VERSION_PATTERN = re.compile(
    rf"^\s*Software image version\s*:\s*{VALUE_PATTERN}", re.IGNORECASE
)
KNOWN_PLATFORM_CLAIM_PATTERN = re.compile(
    r"\b(?:Cisco|IOS[-_ ]?XE|Fortinet|FortiOS|Juniper|Junos|Arista\s+(?:EOS|vEOS|DCS-))\b",
    re.IGNORECASE,
)
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


def resolve_profile(evidence: SnapshotEvidence, *, runtime_manifests: Iterable[ProfileManifest] = ()) -> ProfileResolutionResult:
    signals: list[EvidenceSignal] = []
    identities: list[_Identity] = []
    models: list[_Hardware] = []
    serials: list[_Hardware] = []
    hostnames: list[_Hardware] = []
    fortios_builds: list[str] = []
    cisco_syntax_signals: list[EvidenceSignal] = []

    for document in evidence.documents:
        document_cisco_context = False
        document_arista_context = False
        document_fortios_context = False
        arista_versions: list[tuple[str, int]] = []
        fortios_identity: list[tuple[str, str, int, str]] = []
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
            ):
                other_match = pattern.search(match_line)
                if other_match:
                    signal = _signal(
                        document, line_number, "os_identity", signal_id,
                        explicit_strength, ("vendor", "os", "os_version"),
                    )
                    identities.append(_Identity(vendor, os_name, other_match.group(1), signal))
                    if vendor == "Fortinet":
                        document_fortios_context = True
                    _append_signal(signals, signal)

            fortios_status = FORTIOS_STATUS_PATTERN.search(match_line)
            if fortios_status:
                version = fortios_status.group(2)
                if fortios_status.group(3):
                    fortios_builds.append(fortios_status.group(3))
                document_fortios_context = True
                fortios_identity.append((fortios_status.group(1), version, line_number, match_line))

            if document.evidence_type == ArtifactEvidenceType.VERSION_OUTPUT:
                arista_product = ARISTA_PRODUCT_PATTERN.search(match_line)
                if arista_product:
                    document_arista_context = True
                    signal = _signal(
                        document, line_number, "os_identity", "arista_eos_marker",
                        SignalStrength.STRONGEST, ("vendor", "os"),
                    )
                    identities.append(_Identity("Arista", "EOS", None, signal))
                    _append_signal(signals, signal)
                    model_signal = _signal(
                        document, line_number, "hardware_identity", "arista_model",
                        SignalStrength.STRONG, ("model",),
                    )
                    models.append(_Hardware(arista_product.group(1), model_signal))
                    _append_signal(signals, model_signal)
                arista_serial = ARISTA_SERIAL_PATTERN.search(match_line)
                if arista_serial and document_arista_context:
                    serial_signal = _signal(
                        document, line_number, "hardware_identity", "arista_serial",
                        SignalStrength.STRONG, ("serial_number",),
                    )
                    serials.append(_Hardware(arista_serial.group(1), serial_signal))
                    _append_signal(signals, serial_signal)
                arista_version = ARISTA_SOFTWARE_VERSION_PATTERN.search(match_line)
                if arista_version:
                    arista_versions.append((arista_version.group(1), line_number))

            if document.evidence_type in {
                ArtifactEvidenceType.VERSION_OUTPUT,
                ArtifactEvidenceType.INVENTORY_OUTPUT,
                ArtifactEvidenceType.OPERATIONAL_OUTPUT,
                ArtifactEvidenceType.UNKNOWN_EVIDENCE,
            }:
                hostname_match = FORTIOS_HOSTNAME_PATTERN.search(match_line)
                serial_match = FORTIOS_SERIAL_PATTERN.search(match_line)
                if hostname_match:
                    fortios_identity.append(("hostname", hostname_match.group(1), line_number, "hostname"))
                if serial_match:
                    fortios_identity.append(("serial", serial_match.group(1), line_number, "serial"))
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
        if document_arista_context:
            for version, line_number in arista_versions:
                signal = _signal(
                    document, line_number, "os_identity", "arista_eos_version",
                    SignalStrength.STRONGEST, ("vendor", "os", "os_version"),
                )
                identities.append(_Identity("Arista", "EOS", version, signal))
                _append_signal(signals, signal)

        if document_fortios_context:
            for kind, value, line_number, _source in fortios_identity:
                if kind.startswith("FortiGate-"):
                    signal = _signal(document, line_number, "os_identity", "fortinet_fortios_status", SignalStrength.STRONGEST, ("vendor", "os", "os_version", "model"))
                    identities.append(_Identity("Fortinet", "FortiOS", value, signal))
                    models.append(_Hardware(kind, signal))
                    _append_signal(signals, signal)
                elif kind == "hostname":
                    signal = _signal(document, line_number, "hardware_identity", "fortinet_hostname", SignalStrength.STRONG, ("hostname",))
                    hostnames.append(_Hardware(value, signal)); _append_signal(signals, signal)
                elif kind == "serial":
                    signal = _signal(document, line_number, "hardware_identity", "fortinet_serial", SignalStrength.STRONG, ("serial_number",))
                    serials.append(_Hardware(value, signal)); _append_signal(signals, signal)

    runtime_manifests = tuple(runtime_manifests)
    _extract_manifest_xml_identity(evidence, identities, models, serials, hostnames, signals, runtime_manifests)

    result = _resolve_candidates(
        identities=identities,
        models=models,
        serials=serials,
        cisco_syntax_signals=cisco_syntax_signals,
        signals=tuple(signals),
        unavailable_count=len(evidence.issues),
        documents=evidence.documents,
        runtime_manifests=runtime_manifests,
    )
    hostname = _first_value(hostnames)
    metadata = {
        **result.metadata,
        **({"hostname": hostname} if hostname else {}),
        **({"os_build": fortios_builds[0]} if len(set(fortios_builds)) == 1 else {}),
    }
    return replace(result, metadata=metadata)


def _extract_manifest_xml_identity(
    evidence: SnapshotEvidence,
    identities: list[_Identity],
    models: list[_Hardware],
    serials: list[_Hardware],
    hostnames: list[_Hardware],
    signals: list[EvidenceSignal],
    runtime_manifests: tuple[ProfileManifest, ...] = (),
) -> None:
    # Keep XML parsing imports lazy because profile resolution is imported while
    # the database model package is still initializing.
    from app.parsing.models import ArtifactProvenance
    from app.parsing.service import parse_xml_text

    """Apply only manifest-declared bounded selectors to XML evidence."""
    xml_manifests = tuple(
        item for item in (*PROFILE_REGISTRY.values(), *runtime_manifests)
        if item.structural_reader_name == "xml_tree.v1" and item.xml_identity_selectors
    )
    if not xml_manifests:
        return
    for document in evidence.documents:
        if "<" not in document.text:
            continue
        source = ArtifactProvenance(
            artifact_id=document.artifact_id, organization_id=document.organization_id,
            snapshot_id=document.snapshot_id, source_label=document.original_filename,
            sha256=document.sha256, source_metadata=document.source_metadata,
        )
        try:
            ir = parse_xml_text(document.text, source=source, input_truncated=document.truncated)
        except (ValueError, TypeError):
            continue
        for manifest in xml_manifests:
            values = {
                selector.field: (selector, node, value)
                for selector in manifest.xml_identity_selectors
                for node in ir.nodes
                if (value := selector.matches(node.path, attributes=node.attributes, text=node.text)) is not None
            }
            version_data = values.get("os_version")
            if version_data is None and not any(item.vendor == manifest.vendor and item.os == manifest.os for item in identities):
                continue
            if version_data is not None:
                version_selector, version_node, version = version_data
                version_signal = _xml_signal(document, version_selector.field, version_selector, version_node, manifest)
                identities.append(_Identity(manifest.vendor, manifest.os, version, version_signal))
                _append_signal(signals, version_signal)
            for field, collection in (("hostname", values), ("model", values), ("serial_number", values)):
                item = collection.get(field)
                if item is None:
                    continue
                selector, node, value = item
                signal = _xml_signal(document, field, selector, node, manifest)
                _append_signal(signals, signal)
                if field == "model":
                    models.append(_Hardware(value, signal))
                elif field == "serial_number":
                    serials.append(_Hardware(value, signal))
                else:
                    hostnames.append(_Hardware(value, signal))


def _xml_signal(
    document: EvidenceDocument,
    field: str,
    selector,
    node,
    manifest: ProfileManifest,
) -> EvidenceSignal:
    return EvidenceSignal(
        artifact_id=document.artifact_id, evidence_type=document.evidence_type,
        line_number=None, category="xml_identity", signal_id=f"{manifest.profile_id}:{field}",
        strength=SignalStrength.STRONG, extracted_fields=(field,),
        source_label=document.original_filename, source_path=node.path,
    )


def _resolve_candidates(
    *,
    identities: list[_Identity],
    models: list[_Hardware],
    serials: list[_Hardware],
    cisco_syntax_signals: list[EvidenceSignal],
    signals: tuple[EvidenceSignal, ...],
    unavailable_count: int,
    documents: tuple[EvidenceDocument, ...],
    runtime_manifests: tuple[ProfileManifest, ...] = (),
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
        model = _first_value(models)
        serial_number = _first_value(serials)
        runtime = _resolve_runtime_manifest(documents, runtime_manifests, signals)
        if runtime is not None and runtime.vendor == vendor and runtime.os == os_name:
            return runtime
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
                    vendor=vendor, product_family="FortiGate", os_name=os_name, model=model, serial_number=serial_number,
                    signals=signals, confidence=ResolutionConfidence.MEDIUM,
                    status=ResolutionStatus.PARTIALLY_RESOLVED,
                    reasons=("FortiOS version is required for profile applicability",),
                )
            candidates = compatible_manifests(vendor, os_name, version)
            if len(candidates) > 1:
                return _result(vendor=vendor, product_family="FortiGate", os_name=os_name, os_version=version, model=model, serial_number=serial_number,
                               signals=signals, confidence=ResolutionConfidence.UNRESOLVED,
                               status=ResolutionStatus.AMBIGUOUS,
                               reasons=("Multiple compatible profile manifests were detected",))
            if candidates:
                selected = candidates[0]
                return _result(
                    vendor=vendor, product_family="FortiGate", os_name=os_name,
                    os_version=version, model=model, serial_number=serial_number, device_class=DeviceClass.FIREWALL,
                    selected_profile_id=selected.profile_id,
                    selected_profile_version_id=selected.profile_version_id,
                    signals=signals, confidence=explicit_confidence,
                    status=ResolutionStatus.RESOLVED,
                )
            return _result(
                vendor=vendor, product_family="FortiGate", os_name=os_name,
                os_version=version, model=model, serial_number=serial_number, signals=signals,
                confidence=explicit_confidence, status=ResolutionStatus.UNSUPPORTED,
                reasons=("Detected FortiOS version is outside the supported 7.x profile",),
            )

        if (vendor, os_name) == ("Arista", "EOS"):
            if version is None:
                return _result(
                    vendor=vendor, product_family="EOS", os_name=os_name,
                    model=model, serial_number=serial_number,
                    device_class=DeviceClass.SWITCH, signals=signals,
                    confidence=ResolutionConfidence.MEDIUM,
                    status=ResolutionStatus.PARTIALLY_RESOLVED,
                    reasons=("EOS version output is required for profile applicability",),
                )
            candidates = compatible_manifests(vendor, os_name, version)
            if len(candidates) > 1:
                return _result(
                    vendor=vendor, product_family="EOS", os_name=os_name,
                    os_version=version, device_class=DeviceClass.SWITCH,
                    model=model, serial_number=serial_number,
                    signals=signals, confidence=ResolutionConfidence.UNRESOLVED,
                    status=ResolutionStatus.AMBIGUOUS,
                    reasons=("Multiple compatible profile manifests were detected",),
                )
            if candidates:
                selected = candidates[0]
                return _result(
                    vendor=vendor, product_family="EOS", os_name=os_name,
                    os_version=version, device_class=DeviceClass.SWITCH,
                    model=model, serial_number=serial_number,
                    selected_profile_id=selected.profile_id,
                    selected_profile_version_id=selected.profile_version_id,
                    signals=signals, confidence=explicit_confidence,
                    status=ResolutionStatus.RESOLVED,
                )
            return _result(
                vendor=vendor, product_family="EOS", os_name=os_name,
                os_version=version, device_class=DeviceClass.SWITCH,
                model=model, serial_number=serial_number,
                signals=signals, confidence=explicit_confidence,
                status=ResolutionStatus.UNSUPPORTED,
                reasons=("Detected EOS version is outside the supported 4.x profile",),
            )

        if version is None:
            return _result(
                vendor=vendor, product_family=product_family, os_name=os_name,
                model=model, serial_number=serial_number, device_class=device_class,
                signals=signals, confidence=ResolutionConfidence.MEDIUM,
                status=ResolutionStatus.PARTIALLY_RESOLVED,
                reasons=("Profile applicability requires an explicit software version",),
            )
        candidates = compatible_manifests(vendor, os_name, version)
        if len(candidates) > 1:
            return _result(vendor=vendor, product_family=product_family, os_name=os_name, os_version=version,
                           model=model, serial_number=serial_number, device_class=device_class, signals=signals,
                           confidence=ResolutionConfidence.UNRESOLVED, status=ResolutionStatus.AMBIGUOUS,
                           reasons=("Multiple compatible profile manifests were detected",))
        if candidates:
            selected = candidates[0]
            return _result(vendor=vendor, product_family=product_family, os_name=os_name, os_version=version,
                           model=model, serial_number=serial_number, device_class=device_class,
                           selected_profile_id=selected.profile_id, selected_profile_version_id=selected.profile_version_id,
                           signals=signals, confidence=explicit_confidence, status=ResolutionStatus.RESOLVED)
        return _result(
            vendor=vendor, os_name=os_name, os_version=version,
            signals=signals, confidence=explicit_confidence,
            status=ResolutionStatus.UNSUPPORTED,
            reasons=("Detected platform has no supported deep profile",),
        )

    runtime = _resolve_runtime_manifest(documents, runtime_manifests, signals)
    if runtime is not None:
        return runtime

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

    configuration_documents = tuple(
        document for document in documents
        if document.text.strip() and document.evidence_type in {
            ArtifactEvidenceType.CONFIGURATION,
            ArtifactEvidenceType.STRUCTURED_EXPORT,
            ArtifactEvidenceType.UNKNOWN_EVIDENCE,
        }
    )
    structured_profiles = (
        (GENERIC_XML, lambda text: text.lstrip().startswith("<")),
        (GENERIC_JSON, lambda text: text.lstrip().startswith(("{", "["))),
    )
    for generic_profile, predicate in structured_profiles:
        if configuration_documents and all(predicate(document.text) for document in configuration_documents) and not signals:
            labels = _administrator_labels(configuration_documents)
            return _result(
                vendor=generic_profile.vendor,
                product_family=generic_profile.product_family,
                os_name=generic_profile.os,
                device_class=DeviceClass.UNKNOWN,
                selected_profile_id=generic_profile.profile_id,
                selected_profile_version_id=generic_profile.profile_version_id,
                signals=signals,
                confidence=ResolutionConfidence.LOW,
                status=ResolutionStatus.RESOLVED,
                reasons=("Generic bounded structured profile selected without inferred semantics",),
                metadata={"administrator_labels": labels} if labels else {},
            )
    generic_documents = tuple(
        document for document in configuration_documents
        if not document.text.lstrip().startswith("<")
        and not KNOWN_PLATFORM_CLAIM_PATTERN.search(document.text[:MAX_LINE_CHARACTERS])
    )
    if generic_documents and len(generic_documents) == len(configuration_documents) and not signals:
        labels = _administrator_labels(generic_documents)
        return _result(
            vendor=GENERIC_CLI.vendor,
            product_family=GENERIC_CLI.product_family,
            os_name=GENERIC_CLI.os,
            device_class=DeviceClass.UNKNOWN,
            selected_profile_id=GENERIC_CLI.profile_id,
            selected_profile_version_id=GENERIC_CLI.profile_version_id,
            signals=signals,
            confidence=ResolutionConfidence.LOW,
            status=ResolutionStatus.RESOLVED,
            reasons=("Generic CLI selected without inferred command semantics",),
            metadata={"administrator_labels": labels} if labels else {},
        )

    reasons = ["No authoritative platform evidence was detected"]
    if unavailable_count:
        reasons.append("One or more artifacts could not be inspected")
    return _result(
        signals=signals, confidence=ResolutionConfidence.UNRESOLVED,
        status=ResolutionStatus.UNRESOLVED, reasons=tuple(reasons),
    )


def _resolve_runtime_manifest(
    documents: tuple[EvidenceDocument, ...], manifests: tuple[ProfileManifest, ...], signals: tuple[EvidenceSignal, ...],
) -> ProfileResolutionResult | None:
    matches: list[tuple[ProfileManifest, str, EvidenceDocument]] = []
    for manifest in manifests:
        if not manifest.detection_tokens:
            continue
        pattern = re.compile(r"\bversion\s*[:=]?\s*v?(\d+(?:\.\d+)+(?:[A-Za-z0-9.-]+)?)", re.IGNORECASE)
        for document in documents:
            if document.evidence_type not in manifest.accepted_evidence_types:
                continue
            if not all(token.casefold() in document.text.casefold() for token in manifest.detection_tokens):
                continue
            found = pattern.search(document.text[:MAX_LINE_CHARACTERS * MAX_LINES_PER_ARTIFACT])
            if found and manifest.version_constraint.accepts(found.group(1)):
                matches.append((manifest, found.group(1), document))
    if not matches:
        return None
    identities = {(item.profile_version_id, version) for item, version, _document in matches}
    if len(identities) != 1:
        return _result(signals=signals, confidence=ResolutionConfidence.UNRESOLVED,
                       status=ResolutionStatus.AMBIGUOUS,
                       reasons=("Multiple compatible runtime profile manifests were detected",))
    manifest, version, document = matches[0]
    signal = EvidenceSignal(artifact_id=document.artifact_id, evidence_type=document.evidence_type,
                            line_number=None, category="runtime_manifest_identity",
                            signal_id=f"{manifest.profile_id}:detection", strength=SignalStrength.STRONG,
                            extracted_fields=("vendor", "os", "os_version"), source_label=document.original_filename)
    return _result(vendor=manifest.vendor, product_family=manifest.product_family, os_name=manifest.os,
                   os_version=version, device_class=next(iter(manifest.device_classes)),
                   selected_profile_id=manifest.profile_id, selected_profile_version_id=manifest.profile_version_id,
                   signals=(*signals, signal), confidence=ResolutionConfidence.HIGH,
                   status=ResolutionStatus.RESOLVED, reasons=("Published runtime profile matched bounded evidence",))


def _administrator_labels(documents: tuple[EvidenceDocument, ...]) -> dict[str, str]:
    labels: dict[str, str] = {}
    for key in ("vendor_label", "os_label"):
        values = {
            str(document.source_metadata[key]).strip()
            for document in documents
            if document.source_metadata.get(key)
        }
        if len(values) == 1:
            labels[key.removesuffix("_label")] = next(iter(values))
    return labels


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
    metadata: dict[str, object] | None = None,
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
        metadata=dict(metadata or {}),
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
