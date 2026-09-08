"""Bounded remediation read/preview service; it never executes recommendations."""
import ipaddress
import re
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.compliance.verdicts import FindingVerdict
from app.db.models import Audit, Finding, RemediationProcedure, RemediationProcedureStatus, User
from app.findings.service import FindingNotFoundError, _finding
from app.remediation.catalog import REVIEWED_CISCO_PROCEDURES_BY_RULE

class RemediationError(ValueError): pass
_PLACEHOLDER = re.compile(r"\{([A-Za-z][A-Za-z0-9_]*)\}")

def _profile(audit):
    pinned = audit.version_refs.get("device_profile_version_id")
    resolved = audit.profile_resolution.get("profile_version_id")
    if not pinned or not resolved or pinned != resolved or audit.profile_resolution.get("resolution_status") != "resolved": return None
    return pinned

def _applicable(procedure, finding, audit):
    profile = _profile(audit)
    rule = procedure.profile_applicability
    if not profile: return False, "profile_context_mismatch"
    if profile not in rule.get("profile_version_ids", []): return False, "unsupported_profile"
    return True, None

def _validate_procedure(procedure):
    names = []
    for item in procedure.required_parameters:
        if not isinstance(item, dict) or item.get("type") not in {"ip_address", "ip_network", "hostname", "integer", "port", "enum"} or not isinstance(item.get("name"), str): raise RemediationError("invalid_registry_entry")
        names.append(item["name"])
    if len(names) != len(set(names)) or not procedure.source_references or not procedure.validation_results: raise RemediationError("invalid_registry_entry")
    text = "\n".join(step.get("text", "") for step in procedure.ordered_steps if isinstance(step, dict))
    if not all(name in names for name in _PLACEHOLDER.findall(text)): raise RemediationError("invalid_registry_entry")

def _select(db, finding, audit):
    if finding.remediation_procedure_id:
        procedure = db.get(RemediationProcedure, finding.remediation_procedure_id)
        if not procedure or procedure.status not in {RemediationProcedureStatus.PUBLISHED, RemediationProcedureStatus.SUPERSEDED}: return None, "invalid_registry_entry", None
        source = "explicit_finding_reference"
    else:
        candidates = list(db.scalars(select(RemediationProcedure).where(RemediationProcedure.rule_id == finding.rule_id, RemediationProcedure.status == RemediationProcedureStatus.PUBLISHED)))
        applicable = [candidate for candidate in candidates if _applicable(candidate, finding, audit)[0]]
        if not applicable:
            procedure = REVIEWED_CISCO_PROCEDURES_BY_RULE.get(finding.rule_id)
            if procedure is None: return None, "no_published_procedure", None
            source = "built_in_reviewed_catalog"
        elif len(applicable) != 1: return None, "ambiguous_procedure", None
        else:
            procedure, source = applicable[0], "published_registry_resolution"
    try: _validate_procedure(procedure)
    except RemediationError as error: return None, str(error), None
    ok, reason = _applicable(procedure, finding, audit)
    return (procedure, None, source) if ok else (None, reason, None)

def _response(finding, procedure=None, reason=None, source=None):
    if finding.verdict != FindingVerdict.FAIL: return {"status": "not_required", "reason": "non_fail_verdict", "finding_id": finding.finding_id}
    if not procedure: return {"status": "unavailable", "reason": reason, "finding_id": finding.finding_id}
    required = [item for item in procedure.required_parameters if item.get("required", True)]
    return {"status": "requires_parameters" if required else "applicable", "reason": None, "finding_id": finding.finding_id, "procedure_id": procedure.procedure_id, "procedure_key": procedure.procedure_key, "procedure_version": procedure.version, "title": procedure.title, "security_objective": procedure.security_objective, "description": procedure.description, "profile_applicability": procedure.profile_applicability, "prerequisites": procedure.prerequisites, "safety_warnings": procedure.safety_warnings, "required_parameters": procedure.required_parameters, "configuration_context": procedure.configuration_context, "ordered_steps": procedure.ordered_steps, "verification_steps": procedure.verification_steps, "rollback_steps": procedure.rollback_steps, "source_references": procedure.source_references, "validation_results": procedure.validation_results, "reviewed_at": procedure.reviewed_at, "validated_at": procedure.validated_at, "selection_source": source}

def get_remediation(db: Session, user: User, finding_id: UUID):
    finding = _finding(db, user, finding_id); audit = db.get(Audit, finding.audit_id)
    procedure, reason, source = _select(db, finding, audit)
    return _response(finding, procedure, reason, source)

def _value(definition, value):
    if not isinstance(value, str) or any(ord(char) < 32 for char in value): raise RemediationError("invalid_parameters")
    kind = definition["type"]
    if kind in {"ip_address", "ip_network"}:
        try: return str(ipaddress.ip_address(value) if kind == "ip_address" else ipaddress.ip_network(value, strict=False))
        except ValueError: raise RemediationError("invalid_parameters") from None
    if kind == "hostname":
        try: return str(ipaddress.ip_address(value))
        except ValueError: pass
        if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", value): return value.lower()
    if kind in {"integer", "port"}:
        try: number = int(value)
        except ValueError: raise RemediationError("invalid_parameters") from None
        if kind == "port" and not 1 <= number <= 65535: raise RemediationError("invalid_parameters")
        return str(number)
    if kind == "enum" and value in definition.get("values", []): return value
    raise RemediationError("invalid_parameters")

def preview_remediation(db, user, finding_id, parameters):
    finding = _finding(db, user, finding_id); audit = db.get(Audit, finding.audit_id); procedure, reason, source = _select(db, finding, audit)
    base = _response(finding, procedure, reason, source)
    if not procedure: return base
    definitions = {item["name"]: item for item in procedure.required_parameters}
    if set(parameters) - set(definitions): raise RemediationError("invalid_parameters")
    values = {}
    for name, definition in definitions.items():
        if definition.get("required", True) and name not in parameters: raise RemediationError("missing_required_parameters")
        if name in parameters: values[name] = _value(definition, parameters[name])
    rendered = []
    for step in procedure.ordered_steps:
        text = step.get("text") if isinstance(step, dict) else None
        if not isinstance(text, str): raise RemediationError("invalid_registry_entry")
        rendered.append(_PLACEHOLDER.sub(lambda match: values[match.group(1)], text))
    return {**base, "status": "applicable", "rendered_steps": rendered}
