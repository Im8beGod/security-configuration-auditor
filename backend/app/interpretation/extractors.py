from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
import re

from app.parsing import ConfigNode
from app.security_model import TypedValue, TypedValueType


INTEGER_PATTERN = re.compile(r"^[0-9]+$")
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$"
)


@dataclass(frozen=True)
class ExtractionOutcome:
    value: TypedValue | None
    diagnostic_code: str | None = None


def extract_transport_telnet(node: ConfigNode) -> ExtractionOutcome:
    return _extract_transport_protocol(node, "telnet")


def extract_transport_ssh(node: ConfigNode) -> ExtractionOutcome:
    return _extract_transport_protocol(node, "ssh")


def extract_timeout_minutes_seconds(node: ConfigNode) -> ExtractionOutcome:
    if len(node.arguments) not in {1, 2} or any(
        not INTEGER_PATTERN.fullmatch(item) for item in node.arguments
    ):
        return ExtractionOutcome(None, "invalid_exec_timeout")
    minutes = int(node.arguments[0])
    seconds = int(node.arguments[1]) if len(node.arguments) == 2 else 0
    if minutes > 35_791 or seconds > 59:
        return ExtractionOutcome(None, "invalid_exec_timeout")
    original = " ".join(node.arguments)
    return ExtractionOutcome(TypedValue(
        type=TypedValueType.DURATION,
        value=(minutes * 60) + seconds,
        unit="seconds",
        original_value=original,
        original_unit="minutes_seconds",
    ))


def extract_ssh_version(node: ConfigNode) -> ExtractionOutcome:
    if (
        len(node.arguments) != 3
        or tuple(item.lower() for item in node.arguments[:2]) != ("ssh", "version")
        or node.arguments[2] not in {"1", "2"}
    ):
        return ExtractionOutcome(None, "invalid_ssh_version")
    return ExtractionOutcome(TypedValue(
        type=TypedValueType.INTEGER,
        value=int(node.arguments[2]),
        original_value=node.arguments[2],
    ))


def extract_logging_destination(node: ConfigNode) -> ExtractionOutcome:
    return _extract_endpoint(node, prefix="host", diagnostic="invalid_logging_destination")


def extract_ntp_server(node: ConfigNode) -> ExtractionOutcome:
    return _extract_endpoint(node, prefix="server", diagnostic="invalid_ntp_server")


def extract_ntp_configured(node: ConfigNode) -> ExtractionOutcome:
    outcome = extract_ntp_server(node)
    if outcome.value is None:
        return outcome
    return extract_presence_enabled(node)


def extract_fortios_server(node: ConfigNode) -> ExtractionOutcome:
    return _extract_endpoint(node, prefix="server", diagnostic="invalid_fortios_server")


def extract_fortios_port_enabled(node: ConfigNode) -> ExtractionOutcome:
    if len(node.arguments) != 2 or node.arguments[0].lower() not in {
        "admin-ssh-port", "admin-telnet-port"
    } or not INTEGER_PATTERN.fullmatch(node.arguments[1]):
        return ExtractionOutcome(None, "invalid_fortios_port")
    return ExtractionOutcome(TypedValue(
        type=TypedValueType.BOOLEAN,
        value=int(node.arguments[1]) > 0,
        original_value=" ".join(node.arguments),
    ))


def extract_fortios_allowaccess_ssh(node: ConfigNode) -> ExtractionOutcome:
    return _extract_fortios_allowaccess(node, "ssh")


def extract_fortios_allowaccess_telnet(node: ConfigNode) -> ExtractionOutcome:
    return _extract_fortios_allowaccess(node, "telnet")


def extract_fortios_allowaccess_https(node: ConfigNode) -> ExtractionOutcome:
    return _extract_fortios_allowaccess(node, "https")


def extract_fortios_timeout(node: ConfigNode) -> ExtractionOutcome:
    if len(node.arguments) != 2 or node.arguments[0].lower() != "admintimeout" or not INTEGER_PATTERN.fullmatch(node.arguments[1]):
        return ExtractionOutcome(None, "invalid_fortios_timeout")
    minutes = int(node.arguments[1])
    if minutes > 35_791:
        return ExtractionOutcome(None, "invalid_fortios_timeout")
    return ExtractionOutcome(TypedValue(
        type=TypedValueType.DURATION, value=minutes * 60, unit="seconds",
        original_value=node.arguments[1], original_unit="minutes",
    ))


def extract_presence_enabled(node: ConfigNode) -> ExtractionOutcome:
    return ExtractionOutcome(TypedValue(
        type=TypedValueType.BOOLEAN, value=True,
        original_value=" ".join(node.arguments),
    ))


def extract_cisco_access_class(node: ConfigNode) -> ExtractionOutcome:
    if len(node.arguments) != 2 or node.arguments[1].lower() != "in":
        return ExtractionOutcome(None, "invalid_access_class")
    if not HOSTNAME_PATTERN.fullmatch(node.arguments[0]):
        return ExtractionOutcome(None, "invalid_access_class")
    return extract_presence_enabled(node)


def extract_ntp_key_id(node: ConfigNode) -> ExtractionOutcome:
    if len(node.arguments) < 2 or node.arguments[0].lower() not in {"authentication-key", "trusted-key"}:
        return ExtractionOutcome(None, "invalid_ntp_key_id")
    if not INTEGER_PATTERN.fullmatch(node.arguments[1]):
        return ExtractionOutcome(None, "invalid_ntp_key_id")
    return ExtractionOutcome(TypedValue(
        type=TypedValueType.INTEGER, value=int(node.arguments[1]),
        original_value=node.arguments[1],
    ))


def extract_fortios_trusthost_network(node: ConfigNode) -> ExtractionOutcome:
    if not node.arguments or not node.arguments[0].lower().startswith("trusthost"):
        return ExtractionOutcome(None)
    if len(node.arguments) != 3 or not re.fullmatch(r"trusthost(?:[1-9]|10)", node.arguments[0].lower()):
        return ExtractionOutcome(None, "invalid_fortios_trusthost")
    try:
        network = ip_network(f"{node.arguments[1]}/{node.arguments[2]}", strict=False)
    except ValueError:
        return ExtractionOutcome(None, "invalid_fortios_trusthost")
    return ExtractionOutcome(TypedValue(
        type=TypedValueType.IP_NETWORK, value=str(network),
        original_value=" ".join(node.arguments[1:]), original_unit="address_mask",
    ))


def extract_fortios_trusthost_restriction(node: ConfigNode) -> ExtractionOutcome:
    outcome = extract_fortios_trusthost_network(node)
    if outcome.value is None:
        return outcome
    return extract_presence_enabled(node)


def extract_fortios_tls_minimum(node: ConfigNode) -> ExtractionOutcome:
    if len(node.arguments) < 2 or node.arguments[0].lower() != "admin-https-ssl-versions":
        return ExtractionOutcome(None, "invalid_fortios_tls_versions")
    ranks = {"tlsv1-0": 10, "tlsv1-1": 11, "tlsv1-2": 12, "tlsv1-3": 13}
    versions = tuple(item.lower() for item in node.arguments[1:])
    if not versions or any(item not in ranks for item in versions):
        return ExtractionOutcome(None, "invalid_fortios_tls_versions")
    minimum = min(versions, key=lambda item: ranks[item])
    return ExtractionOutcome(TypedValue(
        type=TypedValueType.ENUM, value=minimum,
        original_value=" ".join(node.arguments),
    ))


def _extract_transport_protocol(node: ConfigNode, protocol: str) -> ExtractionOutcome:
    if len(node.arguments) < 2 or node.arguments[0].lower() != "input":
        return ExtractionOutcome(None, "invalid_transport_input")
    protocols = tuple(item.lower() for item in node.arguments[1:])
    if protocols == ("none",):
        value = False
    elif protocols in {
        ("telnet",),
        ("ssh",),
        ("telnet", "ssh"),
        ("ssh", "telnet"),
    }:
        # `transport input` is an explicit allow-list.  A supported protocol
        # omitted from that list is deterministic negative evidence, unlike a
        # protocol absent from a partial configuration excerpt.
        value = protocol in protocols
    else:
        return ExtractionOutcome(None, "unsupported_transport_input")
    return ExtractionOutcome(TypedValue(
        type=TypedValueType.BOOLEAN,
        value=value,
        original_value=" ".join(node.arguments),
    ))


def _extract_fortios_allowaccess(node: ConfigNode, protocol: str) -> ExtractionOutcome:
    valid_tokens = {
        "http", "https", "ping", "snmp", "ssh", "telnet", "fgfm", "ftm",
    }
    if len(node.arguments) < 2 or node.arguments[0].lower() != "allowaccess":
        return ExtractionOutcome(None, "invalid_fortios_allowaccess")
    tokens = tuple(item.lower() for item in node.arguments[1:])
    if any(token not in valid_tokens and token != "none" for token in tokens):
        return ExtractionOutcome(None, "invalid_fortios_allowaccess")
    if tokens == ("none",):
        value = False
    else:
        value = protocol in tokens
    return ExtractionOutcome(TypedValue(
        type=TypedValueType.BOOLEAN,
        value=value,
        original_value=" ".join(node.arguments),
    ))


def _extract_endpoint(
    node: ConfigNode, *, prefix: str, diagnostic: str
) -> ExtractionOutcome:
    if len(node.arguments) != 2 or node.arguments[0].lower() != prefix:
        return ExtractionOutcome(None, diagnostic)
    original = node.arguments[1].strip('"')
    try:
        canonical = str(ip_address(original))
    except ValueError:
        if not HOSTNAME_PATTERN.fullmatch(original):
            return ExtractionOutcome(None, diagnostic)
        return ExtractionOutcome(TypedValue(
            type=TypedValueType.STRING,
            value=original.lower(),
            original_value=original,
        ))
    return ExtractionOutcome(TypedValue(
        type=TypedValueType.IP_ADDRESS,
        value=canonical,
        original_value=original,
    ))


EXTRACTORS = {
    "transport_telnet": extract_transport_telnet,
    "transport_ssh": extract_transport_ssh,
    "duration_minutes_seconds": extract_timeout_minutes_seconds,
    "ssh_version": extract_ssh_version,
    "logging_destination": extract_logging_destination,
    "ntp_server": extract_ntp_server,
    "ntp_configured": extract_ntp_configured,
    "fortios_server": extract_fortios_server,
    "fortios_port_enabled": extract_fortios_port_enabled,
    "fortios_allowaccess_ssh": extract_fortios_allowaccess_ssh,
    "fortios_allowaccess_telnet": extract_fortios_allowaccess_telnet,
    "fortios_allowaccess_https": extract_fortios_allowaccess_https,
    "fortios_timeout": extract_fortios_timeout,
    "presence_enabled": extract_presence_enabled,
    "cisco_access_class": extract_cisco_access_class,
    "ntp_key_id": extract_ntp_key_id,
    "fortios_trusthost_network": extract_fortios_trusthost_network,
    "fortios_trusthost_restriction": extract_fortios_trusthost_restriction,
    "fortios_tls_minimum": extract_fortios_tls_minimum,
}
