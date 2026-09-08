from uuid import UUID

from app.interpretation.knowledge_pack import DeclarativeMapping, NegationBehavior, NodeMatcher
from app.security_model import TypedValueType

PROFILE = "juniper.junos.18@1.0.0"


def _definition(field: str, path: list[str], source: str, output: str, capture: str | None = None, attribute: str | None = None) -> dict:
    return {
        "profile_applicability": {"profile_ids": ["juniper.junos.18"], "profile_version_ids": [PROFILE]},
        "structural_match": {"operation": "xml_path", "command": "xml", "xml_path": {"path": [{"local_name": item, "occurrence": "any" if item == "server" else "exact"} for item in path], "source": source, "capture": capture, "attribute": attribute, "value_type": output, "start_mode": "document_root"}},
        "target_field_id": field,
        "value_extraction": {"operation": "boolean_from_presence" if source == "presence" else "capture", "capture": capture, "output_type": output},
        "unit_conversion": {"operation": "none"}, "scope_resolution": {"strategy": "device"},
        "negation_behavior": {"operation": "unsupported"}, "removal_behavior": {"operation": "unsupported"}, "default_behavior": {"operation": "unknown"}, "examples": [],
    }


MAPPINGS = (
    DeclarativeMapping(UUID("b3010000-0000-5000-8000-000000000001"), UUID("b3020000-0000-5000-8000-000000000001"), "management.remote.ssh.enabled", NodeMatcher(command="xml"), "training_dsl", "device", frozenset({TypedValueType.BOOLEAN}), training_definition=_definition("management.remote.ssh.enabled", ["configuration", "system", "services", "ssh"], "presence", "boolean")),
    DeclarativeMapping(UUID("b3010000-0000-5000-8000-000000000002"), UUID("b3020000-0000-5000-8000-000000000002"), "logging.remote.destination", NodeMatcher(command="xml"), "training_dsl", "device", frozenset({TypedValueType.STRING}), training_definition=_definition("logging.remote.destination", ["configuration", "system", "syslog", "host", "name"], "text", "string", "destination")),
    DeclarativeMapping(UUID("b3010000-0000-5000-8000-000000000003"), UUID("b3020000-0000-5000-8000-000000000003"), "time.ntp.server", NodeMatcher(command="xml"), "training_dsl", "device", frozenset({TypedValueType.STRING}), training_definition=_definition("time.ntp.server", ["configuration", "system", "ntp", "server", "name"], "text", "string", "server")),
)
