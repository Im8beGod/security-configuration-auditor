import re
from dataclasses import dataclass
from types import MappingProxyType
from collections.abc import Iterator, Mapping
from typing import Literal

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
        if not version or not re.fullmatch(r"\d+(?:\.\d+)*[A-Za-z0-9.-]*", version):
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
    xml_identity_selectors: tuple["XmlIdentitySelector", ...] = ()
    structural_evidence_types: frozenset[ArtifactEvidenceType] = frozenset({ArtifactEvidenceType.CONFIGURATION})

    def applicability(self, version: str | None) -> str:
        if version is None:
            return "version_unknown"
        return "compatible" if self.version_constraint.accepts(version) and version not in self.exclusions else "incompatible"


class ProfileManifestRegistry(Mapping[str, ProfileManifest]):
    """Immutable exact-version registry for built-in device profiles."""

    SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0.0"})

    def __init__(self, manifests: tuple[ProfileManifest, ...]) -> None:
        by_version: dict[str, ProfileManifest] = {}
        logical_versions: dict[tuple[str, str], ProfileManifest] = {}
        for manifest in manifests:
            self._validate(manifest)
            existing = by_version.get(manifest.profile_version_id)
            logical = logical_versions.get((manifest.profile_id, manifest.profile_version))
            if (existing is not None and existing != manifest) or (
                logical is not None and logical != manifest
            ):
                raise ValueError("Profile manifest version content conflicts")
            by_version[manifest.profile_version_id] = manifest
            logical_versions[(manifest.profile_id, manifest.profile_version)] = manifest
        self._by_version = MappingProxyType(by_version)

    def __getitem__(self, profile_version_id: str) -> ProfileManifest:
        return self._by_version[profile_version_id]

    def __iter__(self) -> Iterator[str]:
        return iter(self._by_version)

    def __len__(self) -> int:
        return len(self._by_version)

    @classmethod
    def _validate(cls, manifest: ProfileManifest) -> None:
        if manifest.manifest_schema_version not in cls.SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError("Unsupported profile-manifest schema version")
        if (
            not manifest.profile_id.strip()
            or not manifest.profile_version.strip()
            or manifest.profile_version_id
            != f"{manifest.profile_id}@{manifest.profile_version}"
        ):
            raise ValueError("Profile manifest identity is malformed")
        if not manifest.vendor.strip() or not manifest.os.strip() or not manifest.device_classes:
            raise ValueError("Profile manifest is malformed")
        if manifest.structural_reader_name is None or manifest.knowledge_pack_name is None:
            raise ValueError("Profile manifest bindings are incomplete")


@dataclass(frozen=True)
class XmlIdentitySelector:
    """Bounded manifest-declared identity lookup over xml_tree.v1 paths."""

    field: Literal["os_version", "hostname", "model", "serial_number"]
    path: tuple[str, ...]
    namespace_uris: tuple[str | None, ...] = ()
    source: Literal["text", "attribute"] = "text"
    attribute: str | None = None

    def matches(self, node_path: tuple[str, ...], *, attributes: tuple[tuple[str, str], ...], text: str | None) -> str | None:
        if len(node_path) != len(self.path):
            return None
        if self.namespace_uris and len(self.namespace_uris) != len(self.path):
            return None
        for actual, expected, expected_namespace in zip(node_path, self.path, self.namespace_uris or (None,) * len(self.path)):
            namespace, local = _xml_name(actual.rsplit("[", 1)[0])
            if local != expected or (expected_namespace is not None and namespace != expected_namespace):
                return None
        if self.source == "attribute":
            return dict(attributes).get(self.attribute or "")
        return text


def _xml_name(tag: str) -> tuple[str | None, str]:
    if tag.startswith("{") and "}" in tag:
        namespace, local = tag[1:].split("}", 1)
        return namespace, local
    return None, tag


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
    knowledge_pack_name="cisco_iosxe_17@1.2.0",
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
            "management.remote.source.restriction.configured",
            "logging.enabled",
            "logging.remote.destination",
            "time.ntp.server",
            "time.ntp.configured",
            "time.ntp.authentication.enabled",
            "time.ntp.authentication.key_id",
            "time.ntp.authentication.trusted_key_id",
        ),
        "command_forms": (
            "transport input telnet|ssh|telnet ssh|ssh telnet|none",
            "exec-timeout <minutes> [seconds]",
            "ip ssh version 1|2",
            "logging host <ip-or-hostname>",
            "ntp server <ip-or-hostname>",
            "access-class <name> in (within line vty)",
            "logging on",
            "ntp authenticate|authentication-key <id>|trusted-key <id>",
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
    knowledge_pack_name="fortios_7@1.3.0",
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
            "management.remote.https.enabled",
            "management.remote.tls.minimum_version",
            "management.remote.source.restriction.configured",
            "management.remote.source.permitted_network",
            "logging.enabled",
            "logging.remote.destination",
            "time.ntp.server",
            "time.ntp.configured",
        ),
    }),
)

JUNIPER_JUNOS_18 = ProfileManifest(
    profile_id="juniper.junos.18",
    profile_version_id="juniper.junos.18@1.0.0",
    profile_version="1.0.0",
    vendor="Juniper",
    product_family="Junos",
    os="Junos",
    version_constraint=VersionConstraint(minimum_version=(18, 4), maximum_version=(18, 4)),
    device_classes=frozenset({DeviceClass.ROUTER, DeviceClass.SWITCH, DeviceClass.FIREWALL}),
    accepted_evidence_types=frozenset(ArtifactEvidenceType),
    structural_reader_name="xml_tree.v1",
    knowledge_pack_name="juniper_junos_18@1.2.0",
    capabilities=frozenset({"profile_detection", "structural_parsing", "semantic_interpretation", "effective_state_resolution", "deterministic_compliance"}),
    coverage_manifest=MappingProxyType({
        "supported_version_family": "Junos 18.4 XML configuration",
        "structural_reader": "xml_tree.v1",
        "canonical_fields": ("management.remote.ssh.enabled", "management.session.idle_timeout", "logging.remote.destination", "time.ntp.server", "time.ntp.configured"),
        "limitations": ("reviewed 18.4R1-S2.4 scope only", "no model or serial inference from XML configuration", "unsupported structures remain UNKNOWN"),
    }),
    xml_identity_selectors=(
        XmlIdentitySelector("os_version", ("rpc-reply", "configuration", "version")),
        XmlIdentitySelector("hostname", ("rpc-reply", "configuration", "system", "host-name")),
    ),
    structural_evidence_types=frozenset({ArtifactEvidenceType.STRUCTURED_EXPORT}),
)

ARISTA_EOS_4 = ProfileManifest(
    profile_id="arista.eos.4",
    profile_version_id="arista.eos.4@1.0.0",
    profile_version="1.0.0",
    vendor="Arista",
    product_family="EOS",
    os="EOS",
    version_constraint=VersionConstraint(frozenset({4})),
    device_classes=frozenset({DeviceClass.SWITCH, DeviceClass.ROUTER}),
    accepted_evidence_types=frozenset(ArtifactEvidenceType),
    structural_reader_name="indentation_cli.v1",
    knowledge_pack_name="arista_eos_4@1.0.0",
    capabilities=frozenset({
        "profile_detection", "structural_parsing", "semantic_interpretation",
        "effective_state_resolution", "deterministic_compliance",
    }),
    coverage_manifest=MappingProxyType({
        "supported_version_family": "Arista EOS 4.x",
        "structural_reader": "indentation_cli.v1",
        "canonical_fields": (
            "management.remote.ssh.enabled",
            "management.remote.telnet.enabled",
            "management.session.idle_timeout",
            "logging.remote.destination",
            "time.ntp.server",
            "management.remote.source.restriction.configured",
        ),
        "command_forms": (
            "management ssh|telnet > shutdown|no shutdown",
            "management ssh > idle-timeout <minutes>",
            "management ssh > ip access-group <name> [vrf <name>] in",
            "logging host <ip-or-hostname>",
            "ntp server <ip-or-hostname>",
        ),
        "limitations": (
            "EOS version must come from explicit version output",
            "service defaults and unsupported command variants remain UNKNOWN",
        ),
    }),
)

GENERIC_CLI = ProfileManifest(
    profile_id="generic.cli",
    profile_version_id="generic.cli@1.0.0",
    profile_version="1.0.0",
    vendor="Generic",
    product_family="Generic CLI",
    os="CLI",
    version_constraint=VersionConstraint(frozenset({1})),
    device_classes=frozenset({DeviceClass.UNKNOWN, DeviceClass.OTHER}),
    accepted_evidence_types=frozenset(ArtifactEvidenceType),
    structural_reader_name="indentation_cli.v1",
    knowledge_pack_name="generic_cli@1.0.0",
    capabilities=frozenset({
        "structural_parsing", "semantic_interpretation",
        "effective_state_resolution", "deterministic_compliance",
        "administrator_training",
    }),
    coverage_manifest=MappingProxyType({
        "structural_reader": "indentation_cli.v1",
        "canonical_fields": (),
        "limitations": (
            "No command semantics are assumed until an administrator publishes a mapping",
            "Unsupported or unmatched syntax remains UNKNOWN",
        ),
    }),
    structural_evidence_types=frozenset({
        ArtifactEvidenceType.CONFIGURATION,
        ArtifactEvidenceType.UNKNOWN_EVIDENCE,
    }),
)

GENERIC_XML = ProfileManifest(
    profile_id="generic.xml",
    profile_version_id="generic.xml@1.0.0",
    profile_version="1.0.0",
    vendor="Generic",
    product_family="Generic XML",
    os="XML",
    version_constraint=VersionConstraint(frozenset({1})),
    device_classes=frozenset({DeviceClass.UNKNOWN, DeviceClass.OTHER}),
    accepted_evidence_types=frozenset({ArtifactEvidenceType.STRUCTURED_EXPORT}),
    structural_reader_name="xml_tree.v1",
    knowledge_pack_name="generic_xml@1.0.0",
    capabilities=frozenset({
        "structural_parsing", "semantic_interpretation",
        "effective_state_resolution", "deterministic_compliance",
        "administrator_training",
    }),
    coverage_manifest=MappingProxyType({
        "structural_reader": "xml_tree.v1",
        "canonical_fields": (),
        "limitations": (
            "Only exact bounded element paths, namespaces, text, attributes, and presence are supported",
            "No XPath, schema inference, defaults, references, or arbitrary expressions are supported",
            "Unsupported or unmatched leaves remain UNKNOWN",
        ),
    }),
    structural_evidence_types=frozenset({ArtifactEvidenceType.STRUCTURED_EXPORT}),
)

GENERIC_JSON = ProfileManifest(
    profile_id="generic.json",
    profile_version_id="generic.json@1.0.0",
    profile_version="1.0.0",
    vendor="Generic",
    product_family="Generic JSON",
    os="JSON",
    version_constraint=VersionConstraint(frozenset({1})),
    device_classes=frozenset({DeviceClass.UNKNOWN, DeviceClass.OTHER}),
    accepted_evidence_types=frozenset({ArtifactEvidenceType.STRUCTURED_EXPORT}),
    structural_reader_name="json_tree.v1",
    knowledge_pack_name="generic_json@1.0.0",
    capabilities=GENERIC_XML.capabilities,
    coverage_manifest=MappingProxyType({
        "structural_reader": "json_tree.v1",
        "canonical_fields": (),
        "limitations": (
            "Only exact bounded object-key and array-index paths are supported",
            "No JSONPath filters, schema inference, defaults, references, or arbitrary expressions are supported",
            "Unsupported or unmatched leaves remain UNKNOWN",
        ),
    }),
    structural_evidence_types=frozenset({ArtifactEvidenceType.STRUCTURED_EXPORT}),
)

PROFILE_REGISTRY = ProfileManifestRegistry(
    (
        CISCO_IOS_XE_17, FORTIOS_7, JUNIPER_JUNOS_18, ARISTA_EOS_4,
        GENERIC_CLI, GENERIC_XML, GENERIC_JSON,
    )
)
