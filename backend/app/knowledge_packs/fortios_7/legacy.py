"""Immutable FortiOS 7 knowledge-pack version 1.0.0."""

from uuid import UUID

from app.interpretation.knowledge_pack import (
    DeclarativeMapping,
    KnowledgePack,
    NegationBehavior,
    NodeMatcher,
)
from app.security_model import TypedValueType


LEGACY_MAPPINGS = (
    DeclarativeMapping(
        UUID("a1b2c3d4-3101-5aaa-8aaa-000000000013"),
        UUID("a1b2c3d4-4101-5aaa-8aaa-000000000013"),
        "management.remote.telnet.enabled",
        NodeMatcher("set", ("admin-telnet-port",), "config", ("system", "global")),
        "fortios_port_enabled",
        "device",
        frozenset({TypedValueType.BOOLEAN}),
    ),
    DeclarativeMapping(
        UUID("a1b2c3d4-3201-5aaa-8aaa-000000000013"),
        UUID("a1b2c3d4-4201-5aaa-8aaa-000000000013"),
        "management.remote.telnet.enabled",
        NodeMatcher("unset", ("admin-telnet-port",), "config", ("system", "global")),
        "fortios_port_enabled",
        "device",
        frozenset({TypedValueType.BOOLEAN}),
        negation_behavior=NegationBehavior.RESET_TO_DEFAULT,
    ),
    DeclarativeMapping(
        UUID("a1b2c3d4-3102-5aaa-8aaa-000000000013"),
        UUID("a1b2c3d4-4102-5aaa-8aaa-000000000013"),
        "management.remote.ssh.enabled",
        NodeMatcher("set", ("admin-ssh-port",), "config", ("system", "global")),
        "fortios_port_enabled",
        "device",
        frozenset({TypedValueType.BOOLEAN}),
    ),
    DeclarativeMapping(
        UUID("a1b2c3d4-3202-5aaa-8aaa-000000000013"),
        UUID("a1b2c3d4-4202-5aaa-8aaa-000000000013"),
        "management.remote.ssh.enabled",
        NodeMatcher("unset", ("admin-ssh-port",), "config", ("system", "global")),
        "fortios_port_enabled",
        "device",
        frozenset({TypedValueType.BOOLEAN}),
        negation_behavior=NegationBehavior.RESET_TO_DEFAULT,
    ),
    DeclarativeMapping(
        UUID("a1b2c3d4-3103-5aaa-8aaa-000000000013"),
        UUID("a1b2c3d4-4103-5aaa-8aaa-000000000013"),
        "management.session.idle_timeout",
        NodeMatcher("set", ("admintimeout",), "config", ("system", "global")),
        "fortios_timeout",
        "device",
        frozenset({TypedValueType.DURATION}),
    ),
    DeclarativeMapping(
        UUID("a1b2c3d4-3203-5aaa-8aaa-000000000013"),
        UUID("a1b2c3d4-4203-5aaa-8aaa-000000000013"),
        "management.session.idle_timeout",
        NodeMatcher("unset", ("admintimeout",), "config", ("system", "global")),
        "fortios_timeout",
        "device",
        frozenset({TypedValueType.DURATION}),
        negation_behavior=NegationBehavior.RESET_TO_DEFAULT,
    ),
    DeclarativeMapping(
        UUID("a1b2c3d4-3104-5aaa-8aaa-000000000013"),
        UUID("a1b2c3d4-4104-5aaa-8aaa-000000000013"),
        "logging.remote.destination",
        NodeMatcher("set", ("server",), "config", ("log", "syslogd", "setting")),
        "fortios_server",
        "device",
        frozenset({TypedValueType.IP_ADDRESS, TypedValueType.STRING}),
    ),
    DeclarativeMapping(
        UUID("a1b2c3d4-3105-5aaa-8aaa-000000000013"),
        UUID("a1b2c3d4-4105-5aaa-8aaa-000000000013"),
        "time.ntp.server",
        NodeMatcher("set", ("server",), "edit", (), "config", ("ntpserver",)),
        "ntp_server",
        "device",
        frozenset({TypedValueType.IP_ADDRESS, TypedValueType.STRING}),
    ),
)


FORTIOS_7_KNOWLEDGE_PACK_V1 = KnowledgePack(
    knowledge_pack_id=UUID("a1b2c3d4-1111-5aaa-8aaa-000000000013"),
    knowledge_pack_version_id=UUID("a1b2c3d4-2222-5aaa-8aaa-000000000013"),
    name="fortios_7",
    version="1.0.0",
    schema_version="1.0.0",
    profile_id="fortinet.fortios.7",
    profile_version_id="fortinet.fortios.7@1.0.0",
    mappings=LEGACY_MAPPINGS,
)
