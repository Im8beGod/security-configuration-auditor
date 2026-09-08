from uuid import UUID

from app.interpretation.knowledge_pack import DeclarativeMapping, NegationBehavior, NodeMatcher
from app.security_model import TypedValueType


def _mapping(mapping_id, version_id, field_id, matcher, extractor, types, *, negation=NegationBehavior.UNSUPPORTED, reset=None):
    return DeclarativeMapping(
        UUID(mapping_id), UUID(version_id), field_id, matcher, extractor, "device",
        frozenset(types), negation_behavior=negation,
        reset_mapping_version_id=UUID(reset) if reset else None,
    )


MAPPINGS = (
    _mapping(
        "a1b2c3d4-3101-5aaa-8aaa-000000000013", "a1b2c3d4-4101-5aaa-8aaa-000000000013",
        "management.remote.telnet.enabled",
        NodeMatcher("set", ("admin-telnet-port",), "config", ("system", "global")),
        "fortios_port_enabled", {TypedValueType.BOOLEAN},
    ),
    _mapping(
        "a1b2c3d4-3201-5aaa-8aaa-000000000013", "a1b2c3d4-4201-5aaa-8aaa-000000000013",
        "management.remote.telnet.enabled",
        NodeMatcher("unset", ("admin-telnet-port",), "config", ("system", "global")),
        "fortios_port_enabled", {TypedValueType.BOOLEAN}, negation=NegationBehavior.RESET_TO_DEFAULT,
    ),
    _mapping(
        "a1b2c3d4-3102-5aaa-8aaa-000000000013", "a1b2c3d4-4102-5aaa-8aaa-000000000013",
        "management.remote.ssh.enabled",
        NodeMatcher("set", ("admin-ssh-port",), "config", ("system", "global")),
        "fortios_port_enabled", {TypedValueType.BOOLEAN},
    ),
    _mapping(
        "a1b2c3d4-3202-5aaa-8aaa-000000000013", "a1b2c3d4-4202-5aaa-8aaa-000000000013",
        "management.remote.ssh.enabled",
        NodeMatcher("unset", ("admin-ssh-port",), "config", ("system", "global")),
        "fortios_port_enabled", {TypedValueType.BOOLEAN}, negation=NegationBehavior.RESET_TO_DEFAULT,
    ),
    _mapping(
        "a1b2c3d4-3103-5aaa-8aaa-000000000013", "a1b2c3d4-4103-5aaa-8aaa-000000000013",
        "management.session.idle_timeout",
        NodeMatcher("set", ("admintimeout",), "config", ("system", "global")),
        "fortios_timeout", {TypedValueType.DURATION},
    ),
    _mapping(
        "a1b2c3d4-3203-5aaa-8aaa-000000000013", "a1b2c3d4-4203-5aaa-8aaa-000000000013",
        "management.session.idle_timeout",
        NodeMatcher("unset", ("admintimeout",), "config", ("system", "global")),
        "fortios_timeout", {TypedValueType.DURATION}, negation=NegationBehavior.RESET_TO_DEFAULT,
    ),
    _mapping(
        "a1b2c3d4-3104-5aaa-8aaa-000000000013", "a1b2c3d4-4104-5aaa-8aaa-000000000013",
        "logging.remote.destination",
        NodeMatcher("set", ("server",), "config", ("log", "syslogd", "setting")),
        "fortios_server", {TypedValueType.IP_ADDRESS, TypedValueType.STRING},
    ),
    _mapping(
        "a1b2c3d4-3105-5aaa-8aaa-000000000013", "a1b2c3d4-4105-5aaa-8aaa-000000000013",
        "time.ntp.server",
        NodeMatcher("set", ("server",), "edit", (), "config", ("ntpserver",)),
        "ntp_server", {TypedValueType.IP_ADDRESS, TypedValueType.STRING},
    ),
)
