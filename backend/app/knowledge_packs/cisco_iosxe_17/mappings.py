from uuid import UUID

from app.interpretation.knowledge_pack import (
    DeclarativeMapping,
    NegationBehavior,
    NodeMatcher,
)
from app.security_model import TypedValueType


B4_MAPPINGS = (
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
        negation_behavior=NegationBehavior.RESET_TO_DEFAULT,
        reset_mapping_version_id=UUID("e42c0eb2-1d5d-584a-b463-8ee80574a35c"),
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
        negation_behavior=NegationBehavior.RESET_TO_DEFAULT,
        reset_mapping_version_id=UUID("65f4fbb9-f9e8-5273-a182-8a99f95d72a1"),
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
        negation_behavior=NegationBehavior.RESET_TO_DEFAULT,
        reset_mapping_version_id=UUID("fa460558-d8fc-58a8-af78-caaa6272e861"),
    ),
    DeclarativeMapping(
        mapping_id=UUID("98f4ebb2-a48e-51f0-8611-430e6987e212"),
        mapping_version_id=UUID("4b13928b-98eb-5dc2-a739-d978d5c8bd95"),
        field_id="management.remote.ssh.version",
        matcher=NodeMatcher(command="ip", arguments_prefix=("ssh", "version")),
        extractor="ssh_version",
        scope_resolver="device",
        declared_value_types=frozenset({TypedValueType.INTEGER}),
        negation_behavior=NegationBehavior.RESET_TO_DEFAULT,
        reset_mapping_version_id=UUID("8fd9e941-6ece-5f2a-9d31-f1592dfd34bd"),
    ),
    DeclarativeMapping(
        mapping_id=UUID("3363d69a-c3e8-53a8-844a-9146e7eee8e3"),
        mapping_version_id=UUID("f112df12-f860-5fad-b013-7b89701d2fcf"),
        field_id="logging.remote.destination",
        matcher=NodeMatcher(command="logging", arguments_prefix=("host",)),
        extractor="logging_destination",
        scope_resolver="device",
        declared_value_types=frozenset({TypedValueType.IP_ADDRESS, TypedValueType.STRING}),
        negation_behavior=NegationBehavior.REMOVE_VALUE,
        removal_mapping_version_id=UUID("3fe025cc-e9bb-5860-a424-9273a7391c3a"),
    ),
    DeclarativeMapping(
        mapping_id=UUID("3f7d8702-ed3f-5c11-ab86-34d057d95678"),
        mapping_version_id=UUID("31eadc31-751e-5451-bdd7-2532a26c9710"),
        field_id="time.ntp.server",
        matcher=NodeMatcher(command="ntp", arguments_prefix=("server",)),
        extractor="ntp_server",
        scope_resolver="device",
        declared_value_types=frozenset({TypedValueType.IP_ADDRESS, TypedValueType.STRING}),
        negation_behavior=NegationBehavior.REMOVE_VALUE,
        removal_mapping_version_id=UUID("cc7f73d2-e27e-5a57-896c-b4d322fc2c14"),
    ),
)


MAPPINGS = B4_MAPPINGS + (
    DeclarativeMapping(
        mapping_id=UUID("876787ca-1d7f-5a4c-9f1a-01f934b4b501"),
        mapping_version_id=UUID("4c84d96e-99b0-53c9-b7f3-8e3f9e5bf501"),
        field_id="management.remote.source.restriction.configured",
        matcher=NodeMatcher(
            command="access-class", arguments_prefix=(),
            parent_command="line", parent_arguments_prefix=("vty",),
        ),
        extractor="cisco_access_class", scope_resolver="vty_range",
        declared_value_types=frozenset({TypedValueType.BOOLEAN}),
    ),
    DeclarativeMapping(
        mapping_id=UUID("876787ca-1d7f-5a4c-9f1a-01f934b4b502"),
        mapping_version_id=UUID("4c84d96e-99b0-53c9-b7f3-8e3f9e5bf502"),
        field_id="logging.enabled",
        matcher=NodeMatcher(command="logging", arguments_prefix=("on",)),
        extractor="presence_enabled", scope_resolver="device",
        declared_value_types=frozenset({TypedValueType.BOOLEAN}),
    ),
    DeclarativeMapping(
        mapping_id=UUID("876787ca-1d7f-5a4c-9f1a-01f934b4b503"),
        mapping_version_id=UUID("4c84d96e-99b0-53c9-b7f3-8e3f9e5bf503"),
        field_id="time.ntp.authentication.enabled",
        matcher=NodeMatcher(command="ntp", arguments_prefix=("authenticate",)),
        extractor="presence_enabled", scope_resolver="device",
        declared_value_types=frozenset({TypedValueType.BOOLEAN}),
    ),
    DeclarativeMapping(
        mapping_id=UUID("876787ca-1d7f-5a4c-9f1a-01f934b4b504"),
        mapping_version_id=UUID("4c84d96e-99b0-53c9-b7f3-8e3f9e5bf504"),
        field_id="time.ntp.authentication.key_id",
        matcher=NodeMatcher(command="ntp", arguments_prefix=("authentication-key",)),
        extractor="ntp_key_id", scope_resolver="device",
        declared_value_types=frozenset({TypedValueType.INTEGER}),
        negation_behavior=NegationBehavior.REMOVE_VALUE,
        removal_mapping_version_id=UUID("9d541282-0e9a-5180-a80b-3c2041c7b504"),
    ),
    DeclarativeMapping(
        mapping_id=UUID("876787ca-1d7f-5a4c-9f1a-01f934b4b505"),
        mapping_version_id=UUID("4c84d96e-99b0-53c9-b7f3-8e3f9e5bf505"),
        field_id="time.ntp.authentication.trusted_key_id",
        matcher=NodeMatcher(command="ntp", arguments_prefix=("trusted-key",)),
        extractor="ntp_key_id", scope_resolver="device",
        declared_value_types=frozenset({TypedValueType.INTEGER}),
        negation_behavior=NegationBehavior.REMOVE_VALUE,
        removal_mapping_version_id=UUID("9d541282-0e9a-5180-a80b-3c2041c7b505"),
    ),
    DeclarativeMapping(
        mapping_id=UUID("876787ca-1d7f-5a4c-9f1a-01f934b4b506"),
        mapping_version_id=UUID("4c84d96e-99b0-53c9-b7f3-8e3f9e5bf506"),
        field_id="time.ntp.configured",
        matcher=NodeMatcher(command="ntp", arguments_prefix=("server",)),
        extractor="ntp_configured", scope_resolver="device",
        declared_value_types=frozenset({TypedValueType.BOOLEAN}),
    ),
)
