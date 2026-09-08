from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from app.security_model.models import ScopeRef, TypedValue, TypedValueType


class FieldRegistryValidationError(ValueError):
    pass


@dataclass(frozen=True)
class CanonicalField:
    field_id: str
    expected_types: frozenset[TypedValueType]
    allowed_scope_types: frozenset[str]
    domain: str
    description: str
    repeatable: bool


_FIELDS = (
    CanonicalField(
        "management.remote.telnet.enabled",
        frozenset({TypedValueType.BOOLEAN}),
        frozenset({"vty_range", "interface", "device"}),
        "management",
        "Whether Telnet is explicitly allowed by a VTY transport statement.",
        False,
    ),
    CanonicalField(
        "management.remote.ssh.enabled",
        frozenset({TypedValueType.BOOLEAN}),
        frozenset({"vty_range", "interface", "device"}),
        "management",
        "Whether SSH is explicitly allowed by a VTY transport statement.",
        False,
    ),
    CanonicalField(
        "management.remote.ssh.version",
        frozenset({TypedValueType.INTEGER}),
        frozenset({"device"}),
        "management",
        "Explicitly configured SSH protocol version.",
        False,
    ),
    CanonicalField(
        "management.remote.https.enabled",
        frozenset({TypedValueType.BOOLEAN}),
        frozenset({"interface"}),
        "management",
        "Whether HTTPS administrative access is explicitly allowed on an interface.",
        False,
    ),
    CanonicalField(
        "management.remote.tls.minimum_version",
        frozenset({TypedValueType.ENUM}),
        frozenset({"device"}),
        "management",
        "Explicit minimum TLS version accepted for administrative HTTPS access.",
        False,
    ),
    CanonicalField(
        "management.remote.source.restriction.configured",
        frozenset({TypedValueType.BOOLEAN}),
        frozenset({"vty_range", "administrator"}),
        "management",
        "Whether an explicit management-source restriction is configured in its native scope.",
        False,
    ),
    CanonicalField(
        "management.remote.source.permitted_network",
        frozenset({TypedValueType.IP_NETWORK}),
        frozenset({"administrator"}),
        "management",
        "An explicitly configured administrative source network, retained in administrator scope.",
        True,
    ),
    CanonicalField(
        "management.session.idle_timeout",
        frozenset({TypedValueType.DURATION}),
        frozenset({"vty_range", "device"}),
        "management",
        "Explicit VTY idle timeout in canonical seconds.",
        False,
    ),
    CanonicalField(
        "logging.remote.destination",
        frozenset({TypedValueType.IP_ADDRESS, TypedValueType.STRING}),
        frozenset({"device"}),
        "logging",
        "Explicit remote logging destination.",
        True,
    ),
    CanonicalField(
        "logging.enabled",
        frozenset({TypedValueType.BOOLEAN}),
        frozenset({"device"}),
        "logging",
        "Whether logging is explicitly enabled by configuration evidence.",
        False,
    ),
    CanonicalField(
        "time.ntp.server",
        frozenset({TypedValueType.IP_ADDRESS, TypedValueType.STRING}),
        frozenset({"device"}),
        "time",
        "Explicit NTP server destination.",
        True,
    ),
    CanonicalField(
        "time.ntp.configured",
        frozenset({TypedValueType.BOOLEAN}),
        frozenset({"device"}),
        "time",
        "Whether NTP server configuration is explicitly present; absence remains unknown.",
        False,
    ),
    CanonicalField(
        "time.ntp.authentication.enabled",
        frozenset({TypedValueType.BOOLEAN}),
        frozenset({"device"}),
        "time",
        "Whether NTP authentication is explicitly enabled.",
        False,
    ),
    CanonicalField(
        "time.ntp.authentication.key_id",
        frozenset({TypedValueType.INTEGER}),
        frozenset({"device"}),
        "time",
        "Explicit NTP authentication key identifier; secret material is never extracted.",
        True,
    ),
    CanonicalField(
        "time.ntp.authentication.trusted_key_id",
        frozenset({TypedValueType.INTEGER}),
        frozenset({"device"}),
        "time",
        "Explicit NTP trusted-key identifier.",
        True,
    ),
)

FIELD_REGISTRY: Mapping[str, CanonicalField] = MappingProxyType({
    field.field_id: field for field in _FIELDS
})


def get_field(field_id: str) -> CanonicalField:
    field = FIELD_REGISTRY.get(field_id)
    if field is None:
        raise FieldRegistryValidationError("Unknown canonical field")
    return field


def validate_field_value_scope(
    field_id: str, value: TypedValue, scope: ScopeRef
) -> CanonicalField:
    field = get_field(field_id)
    if value.type not in field.expected_types:
        raise FieldRegistryValidationError("TypedValue type is incompatible with field")
    if scope.type not in field.allowed_scope_types:
        raise FieldRegistryValidationError("Scope type is incompatible with field")
    _validate_typed_value(value)
    if not scope.key or not isinstance(scope.attributes, Mapping):
        raise FieldRegistryValidationError("ScopeRef is malformed")
    return field


def _validate_typed_value(value: TypedValue) -> None:
    candidate = value.value
    valid = {
        TypedValueType.BOOLEAN: lambda: isinstance(candidate, bool),
        TypedValueType.INTEGER: lambda: isinstance(candidate, int) and not isinstance(candidate, bool),
        TypedValueType.NUMBER: lambda: isinstance(candidate, (int, float)) and not isinstance(candidate, bool),
        TypedValueType.STRING: lambda: isinstance(candidate, str),
        TypedValueType.ENUM: lambda: isinstance(candidate, str),
        TypedValueType.IP_ADDRESS: lambda: isinstance(candidate, str),
        TypedValueType.IP_NETWORK: lambda: isinstance(candidate, str),
        TypedValueType.DURATION: lambda: isinstance(candidate, (int, float)) and not isinstance(candidate, bool),
        TypedValueType.LIST: lambda: isinstance(candidate, list),
        TypedValueType.OBJECT: lambda: isinstance(candidate, dict),
        TypedValueType.NULL: lambda: candidate is None,
    }[value.type]()
    if not valid:
        raise FieldRegistryValidationError("TypedValue value is incompatible with its type")
