from uuid import UUID

from app.interpretation.knowledge_pack import DeclarativeMapping, NegationBehavior, NodeMatcher
from app.security_model import TypedValueType


def _mapping(number, field, matcher, extractor, types, *, scope="device", negation=NegationBehavior.UNSUPPORTED, reset=None, removal=None):
    return DeclarativeMapping(
        UUID(f"a4100000-0000-5000-8000-{number:012d}"),
        UUID(f"a4200000-0000-5000-8000-{number:012d}"),
        field, matcher, extractor, scope, frozenset(types),
        negation_behavior=negation,
        reset_mapping_version_id=UUID(f"a4300000-0000-5000-8000-{number:012d}") if reset else None,
        removal_mapping_version_id=UUID(f"a4400000-0000-5000-8000-{number:012d}") if removal else None,
    )


MAPPINGS = (
    _mapping(1, "management.remote.ssh.enabled", NodeMatcher("shutdown", (), "management", ("ssh",)), "presence_disabled", {TypedValueType.BOOLEAN}, negation=NegationBehavior.INVERT_BOOLEAN),
    _mapping(2, "management.remote.telnet.enabled", NodeMatcher("shutdown", (), "management", ("telnet",)), "presence_disabled", {TypedValueType.BOOLEAN}, negation=NegationBehavior.INVERT_BOOLEAN),
    _mapping(3, "management.session.idle_timeout", NodeMatcher("idle-timeout", (), "management", ("ssh",)), "duration_minutes", {TypedValueType.DURATION}, negation=NegationBehavior.RESET_TO_DEFAULT, reset=True),
    _mapping(4, "logging.remote.destination", NodeMatcher("logging", ("host",)), "logging_destination", {TypedValueType.IP_ADDRESS, TypedValueType.STRING}, negation=NegationBehavior.REMOVE_VALUE, removal=True),
    _mapping(5, "time.ntp.server", NodeMatcher("ntp", ("server",)), "ntp_server", {TypedValueType.IP_ADDRESS, TypedValueType.STRING}, negation=NegationBehavior.REMOVE_VALUE, removal=True),
    _mapping(6, "management.remote.source.restriction.configured", NodeMatcher("ip", ("access-group",), "management", ("ssh",)), "arista_service_acl", {TypedValueType.BOOLEAN}, scope="arista_management_service"),
)


PHASE7_MAPPINGS = MAPPINGS + (
    _mapping(7, "time.ntp.configured", NodeMatcher("ntp", ("server",)), "ntp_configured", {TypedValueType.BOOLEAN}),
)
