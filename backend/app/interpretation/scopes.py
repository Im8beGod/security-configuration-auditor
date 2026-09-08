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


def _parent(node: ConfigNode, ir: StructuralIR) -> ConfigNode | None:
    if node.parent_id is None:
        return None
    try:
        return ir.node(node.parent_id)
    except KeyError:
        return None


def resolve_fortios_interface(node: ConfigNode, ir: StructuralIR) -> ScopeOutcome:
    edit = _parent(node, ir)
    config = _parent(edit, ir) if edit else None
    if (
        edit is None or config is None or edit.command != "edit" or len(edit.arguments) != 1
        or config.command != "config" or tuple(item.lower() for item in config.arguments) != ("system", "interface")
    ):
        return ScopeOutcome(None, context_node=edit, diagnostic_code="unsupported_interface_scope")
    name = edit.arguments[0].strip('"')
    if not name:
        return ScopeOutcome(None, context_node=edit, diagnostic_code="unsupported_interface_scope")
    return ScopeOutcome(ScopeRef("interface", f"interface:{name}", {"name": name}), context_node=edit)


def resolve_fortios_administrator(node: ConfigNode, ir: StructuralIR) -> ScopeOutcome:
    edit = _parent(node, ir)
    config = _parent(edit, ir) if edit else None
    if (
        edit is None or config is None or edit.command != "edit" or len(edit.arguments) != 1
        or config.command != "config" or tuple(item.lower() for item in config.arguments) != ("system", "admin")
    ):
        return ScopeOutcome(None, context_node=edit, diagnostic_code="unsupported_administrator_scope")
    name = edit.arguments[0].strip('"')
    if not name:
        return ScopeOutcome(None, context_node=edit, diagnostic_code="unsupported_administrator_scope")
    return ScopeOutcome(ScopeRef("administrator", f"administrator:{name}", {"name": name}), context_node=edit)


SCOPE_RESOLVERS = {
    "device": resolve_device_scope,
    "vty_range": resolve_vty_range,
    "interface": resolve_fortios_interface,
    "administrator": resolve_fortios_administrator,
}

SCOPE_RESOLVER_TYPES = {
    "device": "device",
    "vty_range": "vty_range",
    "interface": "interface",
    "administrator": "administrator",
}
