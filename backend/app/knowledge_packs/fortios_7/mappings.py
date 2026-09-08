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
