import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from app.db.models import ArtifactEvidenceType, DeviceClass


@dataclass(frozen=True)
class VersionConstraint:
    supported_major_versions: frozenset[int]

    def accepts(self, version: str) -> bool:
        match = re.match(r"^(\d+)(?:\.|$)", version)
        return bool(match and int(match.group(1)) in self.supported_major_versions)


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
            "no CIS, STIG, NIST, ISO mappings, remediation, or reporting",
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
    knowledge_pack_name="fortios_7@1.0.0",
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
