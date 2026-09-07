"""Immutable Cisco IOS XE 17 knowledge-pack version 1.0.0."""

from uuid import UUID

from app.interpretation.knowledge_pack import DeclarativeMapping, KnowledgePack, NodeMatcher
from app.security_model import TypedValueType


LEGACY_MAPPINGS = (
    DeclarativeMapping(UUID("c2a81d5b-9591-5ecd-beee-46beb57acced"), UUID("4e5634f2-c0f2-529e-912f-e42139aed61e"), "management.remote.telnet.enabled", NodeMatcher("transport", ("input",), "line", ("vty",)), "transport_telnet", "vty_range", frozenset({TypedValueType.BOOLEAN})),
    DeclarativeMapping(UUID("bc2cc368-40eb-53ed-896e-5efd779359d3"), UUID("82f62960-c06e-5ee1-a1ce-ccd574ead730"), "management.remote.ssh.enabled", NodeMatcher("transport", ("input",), "line", ("vty",)), "transport_ssh", "vty_range", frozenset({TypedValueType.BOOLEAN})),
    DeclarativeMapping(UUID("79a68ade-607d-5148-98cf-5e9f5e92943a"), UUID("a153b5c4-786d-5940-9fc7-2906ea7d42c7"), "management.session.idle_timeout", NodeMatcher("exec-timeout", (), "line", ("vty",)), "duration_minutes_seconds", "vty_range", frozenset({TypedValueType.DURATION})),
    DeclarativeMapping(UUID("98f4ebb2-a48e-51f0-8611-430e6987e212"), UUID("4b13928b-98eb-5dc2-a739-d978d5c8bd95"), "management.remote.ssh.version", NodeMatcher("ip", ("ssh", "version")), "ssh_version", "device", frozenset({TypedValueType.INTEGER})),
    DeclarativeMapping(UUID("3363d69a-c3e8-53a8-844a-9146e7eee8e3"), UUID("f112df12-f860-5fad-b013-7b89701d2fcf"), "logging.remote.destination", NodeMatcher("logging", ("host",)), "logging_destination", "device", frozenset({TypedValueType.IP_ADDRESS, TypedValueType.STRING})),
    DeclarativeMapping(UUID("3f7d8702-ed3f-5c11-ab86-34d057d95678"), UUID("31eadc31-751e-5451-bdd7-2532a26c9710"), "time.ntp.server", NodeMatcher("ntp", ("server",)), "ntp_server", "device", frozenset({TypedValueType.IP_ADDRESS, TypedValueType.STRING})),
)

CISCO_IOS_XE_17_KNOWLEDGE_PACK_V1 = KnowledgePack(
    knowledge_pack_id=UUID("33ededa8-0c17-55e0-b104-302fc55de5b8"),
    knowledge_pack_version_id=UUID("17e3e913-17df-53bf-b8c1-5cae4bfa133e"),
    name="cisco_iosxe_17", version="1.0.0", schema_version="1.0.0",
    profile_id="cisco.ios_xe.17", profile_version_id="cisco.ios_xe.17@1.0.0",
    mappings=LEGACY_MAPPINGS,
)
