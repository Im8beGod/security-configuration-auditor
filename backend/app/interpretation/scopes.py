from __future__ import annotations

from dataclasses import dataclass
import re

from app.parsing import ConfigNode, StructuralIR
from app.security_model import ScopeRef


VTY_NUMBER_PATTERN = re.compile(r"^[0-9]+$")


@dataclass(frozen=True)
class ScopeOutcome:
    scope: ScopeRef | None
    context_node: ConfigNode | None = None
    diagnostic_code: str | None = None


def resolve_device_scope(_node: ConfigNode, _ir: StructuralIR) -> ScopeOutcome:
    return ScopeOutcome(ScopeRef(type="device", key="device", attributes={}))


def resolve_vty_range(node: ConfigNode, ir: StructuralIR) -> ScopeOutcome:
    if node.parent_id is None:
        return ScopeOutcome(None, diagnostic_code="missing_vty_context")
    try:
        parent = ir.node(node.parent_id)
    except KeyError:
        return ScopeOutcome(None, diagnostic_code="missing_vty_context")
    arguments = parent.arguments
    if (
        parent.command != "line"
        or len(arguments) not in {2, 3}
        or arguments[0].lower() != "vty"
        or any(not VTY_NUMBER_PATTERN.fullmatch(item) for item in arguments[1:])
    ):
        return ScopeOutcome(None, context_node=parent, diagnostic_code="unsupported_vty_scope")
    start = int(arguments[1])
    end = int(arguments[2]) if len(arguments) == 3 else start
    if start > end or end > 999:
        return ScopeOutcome(None, context_node=parent, diagnostic_code="unsupported_vty_scope")
    return ScopeOutcome(
        ScopeRef(
            type="vty_range",
            key=f"vty:{start}-{end}",
            attributes={"start": start, "end": end},
        ),
        context_node=parent,
    )


SCOPE_RESOLVERS = {
    "device": resolve_device_scope,
    "vty_range": resolve_vty_range,
}

SCOPE_RESOLVER_TYPES = {
    "device": "device",
    "vty_range": "vty_range",
}
