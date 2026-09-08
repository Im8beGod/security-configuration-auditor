from uuid import UUID

from app.interpretation.knowledge_pack import DeclarativeMapping, NegationBehavior, NodeMatcher
from app.security_model import TypedValueType


def _mapping(mapping_id, version_id, field_id, matcher, extractor, types, *, scope="device", negation=NegationBehavior.UNSUPPORTED, reset=None):
    return DeclarativeMapping(
        UUID(mapping_id), UUID(version_id), field_id, matcher, extractor, scope,
        frozenset(types), negation_behavior=negation,
        reset_mapping_version_id=UUID(reset) if reset else None,
    )


B4_MAPPINGS = (
    _mapping(
        "a1b2c3d4-5101-5aaa-8aaa-000000000013", "a1b2c3d4-6101-5aaa-8aaa-000000000013",
        "management.remote.telnet.enabled",
        NodeMatcher("set", ("allowaccess",), "edit", (), "config", ("system", "interface")),
        "fortios_allowaccess_telnet", {TypedValueType.BOOLEAN}, reset="a1b2c3d4-6201-5aaa-8aaa-000000000013",
    ),
    _mapping(
        "a1b2c3d4-5201-5aaa-8aaa-000000000013", "a1b2c3d4-6201-5aaa-8aaa-000000000013",
        "management.remote.telnet.enabled",
        NodeMatcher("unset", ("allowaccess",), "edit", (), "config", ("system", "interface")),
        "fortios_allowaccess_telnet", {TypedValueType.BOOLEAN}, negation=NegationBehavior.RESET_TO_DEFAULT, reset="a1b2c3d4-6201-5aaa-8aaa-000000000013",
    ),
    _mapping(
        "a1b2c3d4-5102-5aaa-8aaa-000000000013", "a1b2c3d4-6102-5aaa-8aaa-000000000013",
        "management.remote.ssh.enabled",
        NodeMatcher("set", ("allowaccess",), "edit", (), "config", ("system", "interface")),
        "fortios_allowaccess_ssh", {TypedValueType.BOOLEAN}, reset="a1b2c3d4-6202-5aaa-8aaa-000000000013",
    ),
    _mapping(
        "a1b2c3d4-5202-5aaa-8aaa-000000000013", "a1b2c3d4-6202-5aaa-8aaa-000000000013",
        "management.remote.ssh.enabled",
        NodeMatcher("unset", ("allowaccess",), "edit", (), "config", ("system", "interface")),
        "fortios_allowaccess_ssh", {TypedValueType.BOOLEAN}, negation=NegationBehavior.RESET_TO_DEFAULT, reset="a1b2c3d4-6202-5aaa-8aaa-000000000013",
    ),
    _mapping(
        "a1b2c3d4-5103-5aaa-8aaa-000000000013", "a1b2c3d4-6103-5aaa-8aaa-000000000013",
        "management.session.idle_timeout",
        NodeMatcher("set", ("admintimeout",), "config", ("system", "global")),
        "fortios_timeout", {TypedValueType.DURATION},
    ),
    _mapping(
        "a1b2c3d4-5203-5aaa-8aaa-000000000013", "a1b2c3d4-6203-5aaa-8aaa-000000000013",
        "management.session.idle_timeout",
        NodeMatcher("unset", ("admintimeout",), "config", ("system", "global")),
        "fortios_timeout", {TypedValueType.DURATION}, negation=NegationBehavior.RESET_TO_DEFAULT,
    ),
    _mapping(
        "a1b2c3d4-5104-5aaa-8aaa-000000000013", "a1b2c3d4-6104-5aaa-8aaa-000000000013",
        "logging.remote.destination",
        NodeMatcher("set", ("server",), "config", ("log", "syslogd", "setting")),
        "fortios_server", {TypedValueType.IP_ADDRESS, TypedValueType.STRING},
    ),
    _mapping(
        "a1b2c3d4-5105-5aaa-8aaa-000000000013", "a1b2c3d4-6105-5aaa-8aaa-000000000013",
        "time.ntp.server",
        NodeMatcher("set", ("server",), "edit", (), "config", ("ntpserver",)),
        "ntp_server", {TypedValueType.IP_ADDRESS, TypedValueType.STRING},
    ),
)


MAPPINGS = tuple(
    item for item in B4_MAPPINGS
    if item.field_id not in {"management.remote.telnet.enabled", "management.remote.ssh.enabled"}
) + (
    _mapping(
        "a1b2c3d4-5301-5aaa-8aaa-000000000013", "a1b2c3d4-6301-5aaa-8aaa-000000000013",
        "management.remote.telnet.enabled",
        NodeMatcher("set", ("allowaccess",), "edit", (), "config", ("system", "interface")),
        "fortios_allowaccess_telnet", {TypedValueType.BOOLEAN}, scope="interface", reset="a1b2c3d4-6401-5aaa-8aaa-000000000013",
    ),
    _mapping(
        "a1b2c3d4-5302-5aaa-8aaa-000000000013", "a1b2c3d4-6302-5aaa-8aaa-000000000013",
        "management.remote.ssh.enabled",
        NodeMatcher("set", ("allowaccess",), "edit", (), "config", ("system", "interface")),
        "fortios_allowaccess_ssh", {TypedValueType.BOOLEAN}, scope="interface", reset="a1b2c3d4-6402-5aaa-8aaa-000000000013",
    ),
    _mapping(
        "a1b2c3d4-5401-5aaa-8aaa-000000000013", "a1b2c3d4-6401-5aaa-8aaa-000000000013",
        "management.remote.telnet.enabled",
        NodeMatcher("unset", ("allowaccess",), "edit", (), "config", ("system", "interface")),
        "fortios_allowaccess_telnet", {TypedValueType.BOOLEAN}, scope="interface",
        negation=NegationBehavior.RESET_TO_DEFAULT, reset="a1b2c3d4-6501-5aaa-8aaa-000000000013",
    ),
    _mapping(
        "a1b2c3d4-5402-5aaa-8aaa-000000000013", "a1b2c3d4-6402-5aaa-8aaa-000000000013",
        "management.remote.ssh.enabled",
        NodeMatcher("unset", ("allowaccess",), "edit", (), "config", ("system", "interface")),
        "fortios_allowaccess_ssh", {TypedValueType.BOOLEAN}, scope="interface",
        negation=NegationBehavior.RESET_TO_DEFAULT, reset="a1b2c3d4-6502-5aaa-8aaa-000000000013",
    ),
    _mapping(
        "a1b2c3d4-5303-5aaa-8aaa-000000000013", "a1b2c3d4-6303-5aaa-8aaa-000000000013",
        "management.remote.https.enabled",
        NodeMatcher("set", ("allowaccess",), "edit", (), "config", ("system", "interface")),
        "fortios_allowaccess_https", {TypedValueType.BOOLEAN}, scope="interface", reset="a1b2c3d4-6403-5aaa-8aaa-000000000013",
    ),
    _mapping(
        "a1b2c3d4-5403-5aaa-8aaa-000000000013", "a1b2c3d4-6403-5aaa-8aaa-000000000013",
        "management.remote.https.enabled",
        NodeMatcher("unset", ("allowaccess",), "edit", (), "config", ("system", "interface")),
        "fortios_allowaccess_https", {TypedValueType.BOOLEAN}, scope="interface",
        negation=NegationBehavior.RESET_TO_DEFAULT, reset="a1b2c3d4-6503-5aaa-8aaa-000000000013",
    ),
    _mapping(
        "a1b2c3d4-5304-5aaa-8aaa-000000000013", "a1b2c3d4-6304-5aaa-8aaa-000000000013",
        "management.remote.tls.minimum_version",
        NodeMatcher("set", ("admin-https-ssl-versions",), "config", ("system", "global")),
        "fortios_tls_minimum", {TypedValueType.ENUM},
    ),
    _mapping(
        "a1b2c3d4-5305-5aaa-8aaa-000000000013", "a1b2c3d4-6305-5aaa-8aaa-000000000013",
        "management.remote.source.restriction.configured",
        NodeMatcher("set", (), "edit", (), "config", ("system", "admin")),
        "fortios_trusthost_restriction", {TypedValueType.BOOLEAN}, scope="administrator",
    ),
    _mapping(
        "a1b2c3d4-5306-5aaa-8aaa-000000000013", "a1b2c3d4-6306-5aaa-8aaa-000000000013",
        "management.remote.source.permitted_network",
        NodeMatcher("set", (), "edit", (), "config", ("system", "admin")),
        "fortios_trusthost_network", {TypedValueType.IP_NETWORK}, scope="administrator",
    ),
    _mapping(
        "a1b2c3d4-5307-5aaa-8aaa-000000000013", "a1b2c3d4-6307-5aaa-8aaa-000000000013",
        "logging.enabled",
        NodeMatcher("set", ("status", "enable"), "config", ("log", "setting")),
        "presence_enabled", {TypedValueType.BOOLEAN},
    ),
    _mapping(
        "a1b2c3d4-5308-5aaa-8aaa-000000000013", "a1b2c3d4-6308-5aaa-8aaa-000000000013",
        "time.ntp.configured",
        NodeMatcher("set", ("server",), "edit", (), "config", ("ntpserver",)),
        "ntp_configured", {TypedValueType.BOOLEAN},
    ),
)
