from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from app.db.models import RemediationProcedureStatus


CISCO_PROFILE = "cisco.ios_xe.17@1.0.0"


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

REVIEWED_CISCO_PROCEDURES_BY_RULE = {item.rule_id: item for item in REVIEWED_CISCO_PROCEDURES}
