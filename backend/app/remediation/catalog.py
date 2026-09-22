from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from uuid import UUID

from app.db.models import RemediationProcedureStatus


CISCO_PROFILE = "cisco.ios_xe.17@1.0.0"
FORTIOS_PROFILE = "fortinet.fortios.7@1.0.0"
JUNOS_PROFILE = "juniper.junos.18@1.0.0"
ARISTA_PROFILE = "arista.eos.4@1.0.0"


@dataclass(frozen=True)
class ReviewedProcedure:
    procedure_id: UUID
    procedure_key: str
    version: int
    rule_id: str
    title: str
    security_objective: str
    description: str
    status: RemediationProcedureStatus
    profile_applicability: dict
    prerequisites: list[dict]
    safety_warnings: list[str]
    required_parameters: list[dict]
    configuration_context: list[str]
    ordered_steps: list[dict]
    verification_steps: list[dict]
    rollback_steps: list[dict]
    validation_results: list[dict]
    source_references: list[dict]
    reviewed_at: str
    validated_at: str
    schema_version: str = "1.0.0"


class RemediationProcedureRegistry:
    """Immutable exact-version registry for reviewed built-in procedures."""

    def __init__(self, procedures: tuple[ReviewedProcedure, ...]) -> None:
        by_id: dict[UUID, ReviewedProcedure] = {}
        logical_versions: dict[tuple[str, int], ReviewedProcedure] = {}
        by_rule: dict[str, list[ReviewedProcedure]] = {}
        for procedure in procedures:
            if (
                procedure.schema_version != "1.0.0"
                or procedure.procedure_id.int == 0
                or not procedure.procedure_key.strip()
                or procedure.version < 1
                or not procedure.rule_id.strip()
                or not procedure.profile_applicability.get("profile_version_ids")
            ):
                raise ValueError("Remediation procedure registry entry is invalid")
            existing = by_id.get(procedure.procedure_id)
            logical = logical_versions.get((procedure.procedure_key, procedure.version))
            if (existing is not None and existing != procedure) or (
                logical is not None and logical != procedure
            ):
                raise ValueError("Remediation procedure version content conflicts")
            by_id[procedure.procedure_id] = procedure
            logical_versions[(procedure.procedure_key, procedure.version)] = procedure
            by_rule.setdefault(procedure.rule_id, []).append(procedure)
        self.by_id = MappingProxyType(by_id)
        self.by_rule = MappingProxyType({
            rule_id: tuple(items) for rule_id, items in by_rule.items()
        })

    def for_rule(
        self, rule_id: str, profile_version_id: str | None = None
    ) -> ReviewedProcedure | None:
        candidates = self.by_rule.get(rule_id, ())
        if profile_version_id is not None:
            candidates = tuple(
                item for item in candidates
                if profile_version_id
                in item.profile_applicability.get("profile_version_ids", [])
            )
        return candidates[0] if len(candidates) == 1 else None


_COMMON_WARNING = "Advisory preview only; the backend never connects to or changes a device."
_PROFILE = {"profile_version_ids": [CISCO_PROFILE]}


REVIEWED_CISCO_PROCEDURES = (
    ReviewedProcedure(
        procedure_id=UUID("b4f5e2b5-1c7d-5b4f-8e4d-7b1b5f4f1501"),
        procedure_key="cisco.iosxe.17.ssh-version-2", version=1,
        rule_id="management.ssh.version_2", title="Configure Cisco IOS XE SSH protocol version 2",
        security_objective="Require SSH protocol version 2 for remote administration.",
        description="Preview the bounded global configuration change for the SSH protocol version finding.",
        status=RemediationProcedureStatus.PUBLISHED, profile_applicability=_PROFILE,
        prerequisites=[{"text": "Review the device change window and preserve the current configuration."}],
        safety_warnings=[_COMMON_WARNING], required_parameters=[], configuration_context=["global configuration mode"],
        ordered_steps=[{"text": "configure terminal"}, {"text": "ip ssh version 2"}, {"text": "end"}],
        verification_steps=[{"text": "show ip ssh | include version"}],
        rollback_steps=[{"text": "Rollback requires restoring the previously approved SSH version; no automatic rollback command is emitted."}],
        validation_results=[{"review": "passed", "scope": "Cisco IOS XE 17.x", "commands": ["ip ssh version 2"]}],
        source_references=[{"title": "Cisco IOS XE 17.x Secure Shell Version 2 Support", "url": "https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-secure-shell-v2-0.html"}],
        reviewed_at="2026-09-08", validated_at="2026-09-08",
    ),
    ReviewedProcedure(
        procedure_id=UUID("b4f5e2b5-1c7d-5b4f-8e4d-7b1b5f4f1502"),
        procedure_key="cisco.iosxe.17.remote-logging-host", version=1,
        rule_id="logging.remote.destination.configured", title="Configure a Cisco IOS XE remote logging host",
        security_objective="Send system messages to the reviewed remote logging destination.",
        description="Preview the bounded global configuration change for the remote logging destination finding.",
        status=RemediationProcedureStatus.PUBLISHED, profile_applicability=_PROFILE,
        prerequisites=[{"text": "Confirm the destination is approved and reachable by the device."}],
        safety_warnings=[_COMMON_WARNING], required_parameters=[{"name": "destination", "label": "Logging host", "type": "hostname", "required": True}],
        configuration_context=["global configuration mode"],
        ordered_steps=[{"text": "configure terminal"}, {"text": "logging host {destination}"}, {"text": "end"}],
        verification_steps=[{"text": "show running-config | include logging host"}],
        rollback_steps=[{"text": "configure terminal"}, {"text": "no logging host {destination}"}, {"text": "end"}],
        validation_results=[{"review": "passed", "scope": "Cisco IOS XE 17.x", "commands": ["logging host <destination>"]}],
        source_references=[{"title": "Cisco IOS XE 17.x Logging Commands", "url": "https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/syst-mgmt/b-system-management/m_esm-syslog.html"}],
        reviewed_at="2026-09-08", validated_at="2026-09-08",
    ),
    ReviewedProcedure(
        procedure_id=UUID("b4f5e2b5-1c7d-5b4f-8e4d-7b1b5f4f1503"),
        procedure_key="cisco.iosxe.17.ntp-server", version=1,
        rule_id="time.ntp.server.configured", title="Configure a Cisco IOS XE NTP server",
        security_objective="Synchronize the device clock with the reviewed NTP server.",
        description="Preview the bounded global configuration change for the NTP server finding.",
        status=RemediationProcedureStatus.PUBLISHED, profile_applicability=_PROFILE,
        prerequisites=[{"text": "Confirm the server is approved and reachable by the device."}],
        safety_warnings=[_COMMON_WARNING], required_parameters=[{"name": "server", "label": "NTP server", "type": "hostname", "required": True}],
        configuration_context=["global configuration mode"],
        ordered_steps=[{"text": "configure terminal"}, {"text": "ntp server {server}"}, {"text": "end"}],
        verification_steps=[{"text": "show ntp status"}, {"text": "show running-config | include ntp server"}],
        rollback_steps=[{"text": "configure terminal"}, {"text": "no ntp server {server}"}, {"text": "end"}],
        validation_results=[{"review": "passed", "scope": "Cisco IOS XE 17.x", "commands": ["ntp server <server>"]}],
        source_references=[{"title": "Cisco IOS XE 17.x Network Time Protocol", "url": "https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/syst-mgmt/b-system-management/m_bsm-time-calendar-set.html"}],
        reviewed_at="2026-09-08", validated_at="2026-09-08",
    ),
)

REVIEWED_MULTI_VENDOR_PROCEDURES = (
    ReviewedProcedure(
        procedure_id=UUID("20000000-0000-0000-0000-000000000001"),
        procedure_key="cisco.ssh-only-vty", version=1,
        rule_id="management.telnet.disabled", title="Configure Cisco IOS XE SSH-only VTY management",
        security_objective="Disable clear-text Telnet management access.",
        description="Preview the reviewed VTY transport restriction without connecting to the device.",
        status=RemediationProcedureStatus.PUBLISHED,
        profile_applicability={"profile_version_ids": [CISCO_PROFILE]},
        prerequisites=[{"text": "Confirm SSH access and maintain an alternate administrative session."}],
        safety_warnings=[_COMMON_WARNING, "Apply through approved change control to avoid management lockout."],
        required_parameters=[{"name": "vty_range", "label": "VTY range", "type": "enum", "values": ["0 4", "5 15", "0 15"], "required": True}],
        configuration_context=["global configuration mode", "line VTY configuration mode"],
        ordered_steps=[{"text": "configure terminal"}, {"text": "line vty {vty_range}"}, {"text": "transport input ssh"}, {"text": "end"}],
        verification_steps=[{"text": "show running-config | section line vty"}],
        rollback_steps=[{"text": "Restore the captured prior transport input setting through approved change control."}],
        validation_results=[{"review": "passed", "scope": "Cisco IOS XE 17.x", "commands": ["line vty <range>", "transport input ssh"]}],
        source_references=[{"title": "Cisco IOS XE 17 Line Commands", "url": "https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/command/cisco-sd-wan-qualified-command-reference-guide/line-commands.html"}],
        reviewed_at="2026-09-20", validated_at="2026-09-20",
    ),
    ReviewedProcedure(
        procedure_id=UUID("20000000-0000-0000-0000-000000000003"),
        procedure_key="fortios.secure-interface-access", version=1,
        rule_id="management.telnet.disabled", title="Configure FortiOS secure management interface access",
        security_objective="Remove Telnet from the approved management protocol set.",
        description="Preview a complete reviewed allowaccess replacement for one interface.",
        status=RemediationProcedureStatus.PUBLISHED,
        profile_applicability={"profile_version_ids": [FORTIOS_PROFILE]},
        prerequisites=[{"text": "Capture the complete current allowaccess set and confirm SSH or HTTPS access."}],
        safety_warnings=[_COMMON_WARNING, "The command replaces the interface protocol set; omitted protocols are removed."],
        required_parameters=[
            {"name": "interface", "label": "Interface", "type": "hostname", "required": True},
            {"name": "protocols", "label": "Approved protocols", "type": "enum", "values": ["https ssh", "https ping ssh", "ping ssh"], "required": True},
        ],
        configuration_context=["config system interface"],
        ordered_steps=[{"text": "config system interface"}, {"text": "edit {interface}"}, {"text": "set allowaccess {protocols}"}, {"text": "next"}, {"text": "end"}],
        verification_steps=[{"text": "show system interface {interface}"}],
        rollback_steps=[{"text": "Restore the captured prior allowaccess protocol set for {interface}."}],
        validation_results=[{"review": "passed", "scope": "FortiOS 7.x", "commands": ["set allowaccess <approved protocols>"]}],
        source_references=[{"title": "FortiOS 7 CLI Reference", "url": "https://docs.fortinet.com/document/fortigate/7.0.0/cli-reference"}],
        reviewed_at="2026-09-20", validated_at="2026-09-20",
    ),
    ReviewedProcedure(
        procedure_id=UUID("20000000-0000-0000-0000-000000000005"),
        procedure_key="junos.ssh-only-service", version=1,
        rule_id="management.telnet.disabled", title="Configure Junos SSH-only management service",
        security_objective="Disable clear-text Telnet management access while retaining SSH.",
        description="Preview reviewed Junos set/delete commands for system services.",
        status=RemediationProcedureStatus.PUBLISHED,
        profile_applicability={"profile_version_ids": [JUNOS_PROFILE]},
        prerequisites=[{"text": "Confirm SSH access and maintain console or alternate administrative access."}],
        safety_warnings=[_COMMON_WARNING, "Commit only after reviewing inherited groups and candidate configuration."],
        required_parameters=[], configuration_context=["Junos configuration mode"],
        ordered_steps=[{"text": "set system services ssh"}, {"text": "delete system services telnet"}],
        verification_steps=[{"text": "show configuration system services | compare"}],
        rollback_steps=[{"text": "rollback 1"}],
        validation_results=[{"review": "passed", "scope": "Junos 18.x", "commands": ["set system services ssh", "delete system services telnet"]}],
        source_references=[{"title": "Junos System Services", "url": "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/services-edit-system.html"}],
        reviewed_at="2026-09-20", validated_at="2026-09-20",
    ),
)

REVIEWED_ARISTA_PROCEDURES = (
    ReviewedProcedure(
        procedure_id=UUID("a4500000-0000-5000-8000-000000000001"),
        procedure_key="arista.eos.4.disable-telnet", version=1,
        rule_id="management.telnet.disabled", title="Disable Arista EOS Telnet management",
        security_objective="Disable clear-text Telnet management access.",
        description="Preview the bounded EOS Telnet shutdown procedure.",
        status=RemediationProcedureStatus.PUBLISHED,
        profile_applicability={"profile_version_ids": [ARISTA_PROFILE]},
        prerequisites=[{"text": "Confirm SSH access and maintain an alternate administrative session."}],
        safety_warnings=[_COMMON_WARNING], required_parameters=[],
        configuration_context=["global configuration mode", "Telnet management configuration mode"],
        ordered_steps=[{"text": "configure terminal"}, {"text": "management telnet"}, {"text": "shutdown"}, {"text": "end"}],
        verification_steps=[{"text": "show running-config section management telnet"}],
        rollback_steps=[{"text": "Rollback requires reviewed use of no shutdown in management telnet mode."}],
        validation_results=[{"review": "passed", "scope": "Arista EOS 4.x", "commands": ["management telnet", "shutdown"]}],
        source_references=[{"title": "Arista EOS Session Management Commands", "url": "https://www.arista.com/en/um-eos/eos-session-management-commands"}],
        reviewed_at="2026-09-20", validated_at="2026-09-20",
    ),
    ReviewedProcedure(
        procedure_id=UUID("a4500000-0000-5000-8000-000000000002"),
        procedure_key="arista.eos.4.remote-logging-host", version=1,
        rule_id="logging.remote.destination.configured", title="Configure an Arista EOS remote logging host",
        security_objective="Send EOS system messages to an approved remote logging destination.",
        description="Preview the bounded EOS remote logging destination procedure.",
        status=RemediationProcedureStatus.PUBLISHED,
        profile_applicability={"profile_version_ids": [ARISTA_PROFILE]},
        prerequisites=[{"text": "Confirm the destination is approved and reachable by the switch."}],
        safety_warnings=[_COMMON_WARNING],
        required_parameters=[{"name": "destination", "label": "Logging host", "type": "hostname", "required": True}],
        configuration_context=["global configuration mode"],
        ordered_steps=[{"text": "configure terminal"}, {"text": "logging host {destination}"}, {"text": "end"}],
        verification_steps=[{"text": "show running-config | include logging host"}],
        rollback_steps=[{"text": "configure terminal"}, {"text": "no logging host {destination}"}, {"text": "end"}],
        validation_results=[{"review": "passed", "scope": "Arista EOS 4.x", "commands": ["logging host <destination>"]}],
        source_references=[{"title": "Arista EOS Switch Administration Commands", "url": "https://www.arista.com/en/um-eos/eos-switch-administration-commands"}],
        reviewed_at="2026-09-20", validated_at="2026-09-20",
    ),
    ReviewedProcedure(
        procedure_id=UUID("a4500000-0000-5000-8000-000000000003"),
        procedure_key="arista.eos.4.enable-ssh", version=1,
        rule_id="management.ssh.enabled", title="Enable Arista EOS SSH management",
        security_objective="Enable encrypted SSH management access.",
        description="Preview the bounded EOS SSH service enablement procedure.",
        status=RemediationProcedureStatus.PUBLISHED,
        profile_applicability={"profile_version_ids": [ARISTA_PROFILE]},
        prerequisites=[{"text": "Confirm SSH credentials and maintain an alternate administrative session."}],
        safety_warnings=[_COMMON_WARNING], required_parameters=[],
        configuration_context=["global configuration mode", "SSH management configuration mode"],
        ordered_steps=[{"text": "configure terminal"}, {"text": "management ssh"}, {"text": "no shutdown"}, {"text": "end"}],
        verification_steps=[{"text": "show running-config section management ssh"}],
        rollback_steps=[{"text": "Restore the captured prior management ssh shutdown state through change control."}],
        validation_results=[{"review": "passed", "scope": "Arista EOS 4.x", "commands": ["management ssh", "no shutdown"]}],
        source_references=[{"title": "Arista EOS Session Management Commands", "url": "https://www.arista.com/en/um-eos/eos-session-management-commands"}],
        reviewed_at="2026-09-21", validated_at="2026-09-21",
    ),
    ReviewedProcedure(
        procedure_id=UUID("a4500000-0000-5000-8000-000000000004"),
        procedure_key="arista.eos.4.ssh-idle-timeout", version=1,
        rule_id="management.idle_timeout.maximum", title="Configure Arista EOS SSH idle timeout",
        security_objective="Terminate inactive administrative SSH sessions within the approved interval.",
        description="Preview the bounded EOS SSH idle-timeout procedure.",
        status=RemediationProcedureStatus.PUBLISHED,
        profile_applicability={"profile_version_ids": [ARISTA_PROFILE]},
        prerequisites=[{"text": "Confirm the organization-approved timeout and maintain an alternate administrative session."}],
        safety_warnings=[_COMMON_WARNING],
        required_parameters=[{"name": "minutes", "label": "Idle timeout minutes", "type": "integer", "minimum": 1, "maximum": 60, "required": True}],
        configuration_context=["global configuration mode", "SSH management configuration mode"],
        ordered_steps=[{"text": "configure terminal"}, {"text": "management ssh"}, {"text": "idle-timeout {minutes}"}, {"text": "end"}],
        verification_steps=[{"text": "show running-config section management ssh"}],
        rollback_steps=[{"text": "Restore the captured prior SSH idle-timeout through approved change control."}],
        validation_results=[{"review": "passed", "scope": "Arista EOS 4.x", "commands": ["management ssh", "idle-timeout <minutes>"]}],
        source_references=[{"title": "Arista EOS Session Management Commands", "url": "https://www.arista.com/en/um-eos/eos-session-management-commands"}],
        reviewed_at="2026-09-21", validated_at="2026-09-21",
    ),
    ReviewedProcedure(
        procedure_id=UUID("a4500000-0000-5000-8000-000000000005"),
        procedure_key="arista.eos.4.ntp-server", version=1,
        rule_id="time.ntp.server.configured", title="Configure an Arista EOS NTP server",
        security_objective="Synchronize the EOS device clock with an approved NTP server.",
        description="Preview the bounded EOS NTP-server configuration procedure.",
        status=RemediationProcedureStatus.PUBLISHED,
        profile_applicability={"profile_version_ids": [ARISTA_PROFILE]},
        prerequisites=[{"text": "Confirm the server is approved and reachable by the switch."}],
        safety_warnings=[_COMMON_WARNING],
        required_parameters=[{"name": "server", "label": "NTP server", "type": "hostname", "required": True}],
        configuration_context=["global configuration mode"],
        ordered_steps=[{"text": "configure terminal"}, {"text": "ntp server {server}"}, {"text": "end"}],
        verification_steps=[{"text": "show running-config | include ntp server"}, {"text": "show ntp status"}],
        rollback_steps=[{"text": "configure terminal"}, {"text": "no ntp server {server}"}, {"text": "end"}],
        validation_results=[{"review": "passed", "scope": "Arista EOS 4.x", "commands": ["ntp server <server>"]}],
        source_references=[{"title": "Arista EOS Network Time Protocol Commands", "url": "https://www.arista.com/en/um-eos/eos-network-time-protocol-commands"}],
        reviewed_at="2026-09-22", validated_at="2026-09-22",
    ),
    ReviewedProcedure(
        procedure_id=UUID("a4500000-0000-5000-8000-000000000006"),
        procedure_key="arista.eos.4.ntp-configuration", version=1,
        rule_id="time.ntp.configured", title="Configure Arista EOS NTP",
        security_objective="Establish an NTP configuration for reliable device time.",
        description="Preview the bounded EOS NTP configuration procedure.",
        status=RemediationProcedureStatus.PUBLISHED,
        profile_applicability={"profile_version_ids": [ARISTA_PROFILE]},
        prerequisites=[{"text": "Confirm the server is approved and reachable by the switch."}],
        safety_warnings=[_COMMON_WARNING],
        required_parameters=[{"name": "server", "label": "NTP server", "type": "hostname", "required": True}],
        configuration_context=["global configuration mode"],
        ordered_steps=[{"text": "configure terminal"}, {"text": "ntp server {server}"}, {"text": "end"}],
        verification_steps=[{"text": "show running-config | include ntp server"}, {"text": "show ntp status"}],
        rollback_steps=[{"text": "configure terminal"}, {"text": "no ntp server {server}"}, {"text": "end"}],
        validation_results=[{"review": "passed", "scope": "Arista EOS 4.x", "commands": ["ntp server <server>"]}],
        source_references=[{"title": "Arista EOS Network Time Protocol Commands", "url": "https://www.arista.com/en/um-eos/eos-network-time-protocol-commands"}],
        reviewed_at="2026-09-22", validated_at="2026-09-22",
    ),
)

REVIEWED_STAGE7_PROCEDURES = (
    ReviewedProcedure(
        procedure_id=UUID("20000000-0000-0000-0000-000000000007"),
        procedure_key="cisco.enable-ssh-vty", version=1,
        rule_id="management.ssh.enabled", title="Enable Cisco IOS XE SSH VTY management",
        security_objective="Enable SSH management on the selected VTY range.",
        description="Preview the reviewed SSH-only VTY transport setting.",
        status=RemediationProcedureStatus.PUBLISHED,
        profile_applicability={"profile_version_ids": [CISCO_PROFILE]},
        prerequisites=[{"text": "Confirm SSH credentials and retain alternate administrative access."}],
        safety_warnings=[_COMMON_WARNING, "The command replaces the VTY transport set."],
        required_parameters=[{"name": "vty_range", "label": "VTY range", "type": "enum", "values": ["0 4", "5 15", "0 15"], "required": True}],
        configuration_context=["global configuration mode", "line VTY configuration mode"],
        ordered_steps=[{"text": "configure terminal"}, {"text": "line vty {vty_range}"}, {"text": "transport input ssh"}, {"text": "end"}],
        verification_steps=[{"text": "show running-config | section line vty"}],
        rollback_steps=[{"text": "Restore the captured prior transport input setting through approved change control."}],
        validation_results=[{"review": "passed", "scope": "Cisco IOS XE 17.x", "commands": ["line vty <range>", "transport input ssh"]}],
        source_references=[{"title": "Cisco IOS XE 17 Line Commands", "url": "https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/command/cisco-sd-wan-qualified-command-reference-guide/line-commands.html"}],
        reviewed_at="2026-09-22", validated_at="2026-09-22",
    ),
    ReviewedProcedure(
        procedure_id=UUID("20000000-0000-0000-0000-000000000008"),
        procedure_key="cisco.disable-http-server", version=1,
        rule_id="management.http.disabled", title="Disable Cisco IOS XE HTTP management server",
        security_objective="Disable the explicitly observed clear-text HTTP management server.",
        description="Preview the bounded global HTTP server disablement command.",
        status=RemediationProcedureStatus.PUBLISHED,
        profile_applicability={"profile_version_ids": [CISCO_PROFILE]},
        prerequisites=[{"text": "Confirm approved HTTPS or out-of-band administrative access."}],
        safety_warnings=[_COMMON_WARNING], required_parameters=[],
        configuration_context=["global configuration mode"],
        ordered_steps=[{"text": "configure terminal"}, {"text": "no ip http server"}, {"text": "end"}],
        verification_steps=[{"text": "show running-config | include ip http server"}],
        rollback_steps=[{"text": "Restore the captured HTTP server state only through approved change control."}],
        validation_results=[{"review": "passed", "scope": "Cisco IOS XE 17.x", "commands": ["no ip http server"]}],
        source_references=[{"title": "Cisco IOS XE HTTP Server Commands", "url": "https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/web/b-web-management.html"}],
        reviewed_at="2026-09-22", validated_at="2026-09-22",
    ),
    ReviewedProcedure(
        procedure_id=UUID("20000000-0000-0000-0000-000000000009"),
        procedure_key="fortios.enable-ssh-access", version=1,
        rule_id="management.ssh.enabled", title="Enable FortiOS SSH management access",
        security_objective="Include SSH in the reviewed interface management protocol set.",
        description="Preview a complete reviewed allowaccess replacement for one interface.",
        status=RemediationProcedureStatus.PUBLISHED,
        profile_applicability={"profile_version_ids": [FORTIOS_PROFILE]},
        prerequisites=[{"text": "Capture the complete current allowaccess set and retain alternate access."}],
        safety_warnings=[_COMMON_WARNING, "The command replaces the interface protocol set; omitted protocols are removed."],
        required_parameters=[
            {"name": "interface", "label": "Interface", "type": "hostname", "required": True},
            {"name": "protocols", "label": "Approved protocols", "type": "enum", "values": ["https ssh", "https ping ssh", "ping ssh"], "required": True},
        ],
        configuration_context=["config system interface"],
        ordered_steps=[{"text": "config system interface"}, {"text": "edit {interface}"}, {"text": "set allowaccess {protocols}"}, {"text": "next"}, {"text": "end"}],
        verification_steps=[{"text": "show system interface {interface}"}],
        rollback_steps=[{"text": "Restore the captured prior allowaccess protocol set for {interface}."}],
        validation_results=[{"review": "passed", "scope": "FortiOS 7.x", "commands": ["set allowaccess <approved protocols>"]}],
        source_references=[{"title": "FortiOS 7 CLI Reference", "url": "https://docs.fortinet.com/document/fortigate/7.0.0/cli-reference"}],
        reviewed_at="2026-09-22", validated_at="2026-09-22",
    ),
    ReviewedProcedure(
        procedure_id=UUID("20000000-0000-0000-0000-000000000010"),
        procedure_key="junos.enable-ssh-service", version=1,
        rule_id="management.ssh.enabled", title="Enable Junos SSH management service",
        security_objective="Enable the explicitly observed Junos SSH management service.",
        description="Preview the bounded Junos system-services SSH command.",
        status=RemediationProcedureStatus.PUBLISHED,
        profile_applicability={"profile_version_ids": [JUNOS_PROFILE]},
        prerequisites=[{"text": "Confirm SSH credentials and retain console or alternate administrative access."}],
        safety_warnings=[_COMMON_WARNING], required_parameters=[],
        configuration_context=["Junos configuration mode"],
        ordered_steps=[{"text": "set system services ssh"}],
        verification_steps=[{"text": "show configuration system services | compare"}],
        rollback_steps=[{"text": "delete system services ssh"}],
        validation_results=[{"review": "passed", "scope": "Junos 18.x", "commands": ["set system services ssh"]}],
        source_references=[{"title": "Junos System Services", "url": "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/services-edit-system.html"}],
        reviewed_at="2026-09-22", validated_at="2026-09-22",
    ),
)

REMEDIATION_PROCEDURE_REGISTRY = RemediationProcedureRegistry(
    REVIEWED_CISCO_PROCEDURES + REVIEWED_MULTI_VENDOR_PROCEDURES + REVIEWED_ARISTA_PROCEDURES + REVIEWED_STAGE7_PROCEDURES
)
REVIEWED_CISCO_PROCEDURES_BY_RULE = MappingProxyType({
    item.rule_id: item for item in REVIEWED_CISCO_PROCEDURES + REVIEWED_MULTI_VENDOR_PROCEDURES + REVIEWED_STAGE7_PROCEDURES
    if CISCO_PROFILE in item.profile_applicability.get("profile_version_ids", [])
})
