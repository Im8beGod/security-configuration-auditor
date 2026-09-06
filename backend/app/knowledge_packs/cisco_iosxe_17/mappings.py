from uuid import UUID

from app.interpretation.knowledge_pack import DeclarativeMapping, NodeMatcher
from app.security_model import TypedValueType


MAPPINGS = (
    DeclarativeMapping(
        mapping_id=UUID("c2a81d5b-9591-5ecd-beee-46beb57acced"),
        mapping_version_id=UUID("4e5634f2-c0f2-529e-912f-e42139aed61e"),
        field_id="management.remote.telnet.enabled",
        matcher=NodeMatcher(
            command="transport", arguments_prefix=("input",),
            parent_command="line", parent_arguments_prefix=("vty",),
        ),
        extractor="transport_telnet",
        scope_resolver="vty_range",
        declared_value_types=frozenset({TypedValueType.BOOLEAN}),
    ),
    DeclarativeMapping(
        mapping_id=UUID("bc2cc368-40eb-53ed-896e-5efd779359d3"),
        mapping_version_id=UUID("82f62960-c06e-5ee1-a1ce-ccd574ead730"),
        field_id="management.remote.ssh.enabled",
        matcher=NodeMatcher(
            command="transport", arguments_prefix=("input",),
            parent_command="line", parent_arguments_prefix=("vty",),
        ),
        extractor="transport_ssh",
        scope_resolver="vty_range",
        declared_value_types=frozenset({TypedValueType.BOOLEAN}),
    ),
    DeclarativeMapping(
        mapping_id=UUID("79a68ade-607d-5148-98cf-5e9f5e92943a"),
        mapping_version_id=UUID("a153b5c4-786d-5940-9fc7-2906ea7d42c7"),
        field_id="management.session.idle_timeout",
        matcher=NodeMatcher(
            command="exec-timeout",
            parent_command="line", parent_arguments_prefix=("vty",),
        ),
        extractor="duration_minutes_seconds",
        scope_resolver="vty_range",
        declared_value_types=frozenset({TypedValueType.DURATION}),
    ),
    DeclarativeMapping(
        mapping_id=UUID("98f4ebb2-a48e-51f0-8611-430e6987e212"),
        mapping_version_id=UUID("4b13928b-98eb-5dc2-a739-d978d5c8bd95"),
        field_id="management.remote.ssh.version",
        matcher=NodeMatcher(command="ip", arguments_prefix=("ssh", "version")),
        extractor="ssh_version",
        scope_resolver="device",
        declared_value_types=frozenset({TypedValueType.INTEGER}),
    ),
    DeclarativeMapping(
        mapping_id=UUID("3363d69a-c3e8-53a8-844a-9146e7eee8e3"),
        mapping_version_id=UUID("f112df12-f860-5fad-b013-7b89701d2fcf"),
        field_id="logging.remote.destination",
        matcher=NodeMatcher(command="logging", arguments_prefix=("host",)),
        extractor="logging_destination",
        scope_resolver="device",
        declared_value_types=frozenset({TypedValueType.IP_ADDRESS, TypedValueType.STRING}),
    ),
    DeclarativeMapping(
        mapping_id=UUID("3f7d8702-ed3f-5c11-ab86-34d057d95678"),
        mapping_version_id=UUID("31eadc31-751e-5451-bdd7-2532a26c9710"),
        field_id="time.ntp.server",
        matcher=NodeMatcher(command="ntp", arguments_prefix=("server",)),
        extractor="ntp_server",
        scope_resolver="device",
        declared_value_types=frozenset({TypedValueType.IP_ADDRESS, TypedValueType.STRING}),
    ),
)
