import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from app.db.models import ArtifactEvidenceType, DeviceClass


@dataclass(frozen=True)
class VersionConstraint:
    supported_major_versions: frozenset[int] = frozenset()
    minimum_version: tuple[int, ...] | None = None
    maximum_version: tuple[int, ...] | None = None
    excluded_versions: frozenset[str] = frozenset()

    def accepts(self, version: str) -> bool:
        parsed = self.parse(version)
        if parsed is None:
            return False
        normalized = ".".join(str(item) for item in parsed)
        if normalized in self.excluded_versions or version in self.excluded_versions:
            return False
        if self.supported_major_versions and parsed[0] not in self.supported_major_versions:
            return False
        lower = self.minimum_version and parsed[:len(self.minimum_version)] < self.minimum_version
        upper = self.maximum_version and parsed[:len(self.maximum_version)] > self.maximum_version
        return not (lower or upper)

    @staticmethod
    def parse(version: str | None) -> tuple[int, ...] | None:
        if not version or not re.fullmatch(r"\d+(?:\.\d+)*[A-Za-z0-9-]*", version):
            return None
        numbers = re.match(r"(\d+(?:\.\d+)*)", version)
        return tuple(int(item) for item in numbers.group(1).split(".")) if numbers else None


@dataclass(frozen=True)
class ProfileManifest:
    profile_id: str
    profile_version_id: str
    profile_version: str
    vendor: str
    product_family: str
    os: str
    version_constraint: VersionConstraint
    device_classes: frozenset[DeviceClass]
    accepted_evidence_types: frozenset[ArtifactEvidenceType]
    structural_reader_name: str | None
    knowledge_pack_name: str | None
    capabilities: frozenset[str]
    coverage_manifest: Mapping[str, object]
    manifest_schema_version: str = "1.0.0"
    exclusions: frozenset[str] = frozenset()
    detection_tokens: tuple[str, ...] = ()

    def applicability(self, version: str | None) -> str:
        if version is None:
            return "version_unknown"
        return "compatible" if self.version_constraint.accepts(version) and version not in self.exclusions else "incompatible"


def compatible_manifests(vendor: str, os_name: str, version: str | None) -> tuple[ProfileManifest, ...]:
    candidates = tuple(item for item in PROFILE_REGISTRY.values()
                       if item.vendor == vendor and item.os == os_name and item.applicability(version) == "compatible")
    return tuple(sorted(candidates, key=lambda item: (item.profile_id, item.profile_version)))


CISCO_IOS_XE_17 = ProfileManifest(
    profile_id="cisco.ios_xe.17",
    profile_version_id="cisco.ios_xe.17@1.0.0",
    profile_version="1.0.0",
    vendor="Cisco",
    product_family="IOS XE",
    os="IOS XE",
    version_constraint=VersionConstraint(frozenset({17})),
    device_classes=frozenset({DeviceClass.ROUTER, DeviceClass.SWITCH}),
    accepted_evidence_types=frozenset(ArtifactEvidenceType),
    structural_reader_name="indentation_cli.v1",
    knowledge_pack_name="cisco_iosxe_17@1.1.0",
    capabilities=frozenset({
        "profile_detection", "structural_parsing", "semantic_interpretation",
        "effective_state_resolution",
        "deterministic_compliance",
    }),
    coverage_manifest=MappingProxyType({
        "profile_detection": True,
        "structural_parsing": True,
        "semantic_interpretation": True,
        "effective_state_resolution": True,
        "deterministic_compliance": True,
        "supported_version_family": "IOS XE 17.x",
        "structural_reader": "indentation_cli.v1",
        "canonical_fields": (
            "management.remote.telnet.enabled",
            "management.remote.ssh.enabled",
            "management.remote.ssh.version",
            "management.session.idle_timeout",
            "logging.remote.destination",
            "time.ntp.server",
        ),
        "command_forms": (
            "transport input telnet|ssh|telnet ssh|ssh telnet|none",
            "exec-timeout <minutes> [seconds]",
            "ip ssh version 1|2",
            "logging host <ip-or-hostname>",
            "ntp server <ip-or-hostname>",
        ),
        "limitations": (
            "incomplete Cisco grammar",
            "no documented defaults, inheritance, references, or bindings",
            "no inheritance, override, or conflict resolution",
            "internal Cisco IOS XE technical baseline only (eight bounded rules)",
            "selected NIST SP 800-53 Rev. 5 mappings only; no CIS, STIG, ISO mappings, remediation, or reporting",
        ),
    }),
)

FORTIOS_7 = ProfileManifest(
    profile_id="fortinet.fortios.7",
    profile_version_id="fortinet.fortios.7@1.0.0",
    profile_version="1.0.0",
    vendor="Fortinet",
    product_family="FortiGate",
    os="FortiOS",
    version_constraint=VersionConstraint(frozenset({7})),
    device_classes=frozenset({DeviceClass.FIREWALL}),
    accepted_evidence_types=frozenset(ArtifactEvidenceType),
    structural_reader_name="fortios_cli.v1",
    knowledge_pack_name="fortios_7@1.1.0",
    capabilities=frozenset({
        "profile_detection", "structural_parsing", "semantic_interpretation",
        "effective_state_resolution", "deterministic_compliance",
    }),
    coverage_manifest=MappingProxyType({
        "profile_detection": True,
        "structural_parsing": True,
        "semantic_interpretation": True,
        "effective_state_resolution": True,
        "deterministic_compliance": True,
        "supported_version_family": "FortiOS 7.x",
        "structural_reader": "fortios_cli.v1",
        "canonical_fields": (
            "management.remote.telnet.enabled",
            "management.remote.ssh.enabled",
            "management.session.idle_timeout",
            "logging.remote.destination",
            "time.ntp.server",
        ),
    }),
)

PROFILE_REGISTRY: Mapping[str, ProfileManifest] = MappingProxyType(
    {
        CISCO_IOS_XE_17.profile_version_id: CISCO_IOS_XE_17,
        FORTIOS_7.profile_version_id: FORTIOS_7,
    }
)
