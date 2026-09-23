"""Bounded remediation read/preview service; it never executes recommendations."""
import ipaddress
import re
from types import SimpleNamespace
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.compliance.verdicts import FindingVerdict
from app.db.models import Audit, Finding, RemediationProcedure, RemediationProcedureStatus, User
from app.findings.service import FindingNotFoundError, _finding
from app.remediation.catalog import REMEDIATION_PROCEDURE_REGISTRY, unavailable_remediation_reason

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
    sections = tuple(
        getattr(procedure, name, [])
        for name in ("ordered_steps", "verification_steps", "rollback_steps")
    )
    if (
        len(names) != len(set(names)) or not getattr(procedure, "source_references", None)
        or not getattr(procedure, "validation_results", None)
        or not getattr(procedure, "prerequisites", None)
        or not getattr(procedure, "safety_warnings", None)
        or any(not section for section in sections)
    ): raise RemediationError("invalid_registry_entry")
    text = "\n".join(
        step.get("text", "") for section in sections for step in section
        if isinstance(step, dict)
    )
    if not all(name in names for name in _PLACEHOLDER.findall(text)): raise RemediationError("invalid_registry_entry")

def _validate_registry_identity(procedure):
    if (
        getattr(procedure, "schema_version", None) != "1.0.0"
        or not isinstance(getattr(procedure, "procedure_id", None), UUID)
        or procedure.procedure_id.int == 0
        or not isinstance(getattr(procedure, "procedure_key", None), str)
        or not procedure.procedure_key.strip()
        or not isinstance(getattr(procedure, "version", None), int)
        or procedure.version < 1
        or not isinstance(getattr(procedure, "rule_id", None), str)
        or not procedure.rule_id.strip()
    ):
        raise RemediationError("invalid_registry_entry")

def _select(db, finding, audit):
    if finding.remediation_procedure_id:
        procedure = db.get(RemediationProcedure, finding.remediation_procedure_id)
        if not procedure or procedure.status not in {RemediationProcedureStatus.PUBLISHED, RemediationProcedureStatus.SUPERSEDED}: return None, "invalid_registry_entry", None
        if procedure.rule_id != finding.rule_id: return None, "invalid_registry_entry", None
        source = "explicit_finding_reference"
    else:
        candidates = list(db.scalars(select(RemediationProcedure).where(RemediationProcedure.rule_id == finding.rule_id, RemediationProcedure.status == RemediationProcedureStatus.PUBLISHED)))
        applicable = [candidate for candidate in candidates if _applicable(candidate, finding, audit)[0]]
        if not applicable:
            procedure = REMEDIATION_PROCEDURE_REGISTRY.for_rule(
                finding.rule_id, _profile(audit)
            )
            if procedure is None:
                reason = (
                    unavailable_remediation_reason(_profile(audit), finding.rule_id)
                    or ("unsupported_profile" if REMEDIATION_PROCEDURE_REGISTRY.by_rule.get(finding.rule_id) else "no_published_procedure")
                )
                return None, reason, None
            source = "built_in_reviewed_catalog"
        elif len(applicable) != 1: return None, "ambiguous_procedure", None
        else:
            procedure, source = applicable[0], "published_registry_resolution"
    try:
        _validate_registry_identity(procedure)
        _validate_procedure(procedure)
    except RemediationError as error: return None, str(error), None
    ok, reason = _applicable(procedure, finding, audit)
    return (procedure, None, source) if ok else (None, reason, None)

def _response(finding, procedure=None, reason=None, source=None):
    if finding.verdict != FindingVerdict.FAIL: return {"status": "not_required", "reason": "non_fail_verdict", "finding_id": finding.finding_id}
    if not procedure: return {"status": "unavailable", "reason": reason, "finding_id": finding.finding_id}
    required = [item for item in procedure.required_parameters if item.get("required", True)]
    response = {"status": "requires_parameters" if required else "applicable", "reason": None, "finding_id": finding.finding_id, "procedure_id": procedure.procedure_id, "procedure_key": procedure.procedure_key, "procedure_version": procedure.version, "title": procedure.title, "security_objective": procedure.security_objective, "description": procedure.description, "profile_applicability": procedure.profile_applicability, "prerequisites": procedure.prerequisites, "safety_warnings": procedure.safety_warnings, "required_parameters": procedure.required_parameters, "configuration_context": procedure.configuration_context, "ordered_steps": procedure.ordered_steps, "verification_steps": procedure.verification_steps, "rollback_steps": procedure.rollback_steps, "source_references": procedure.source_references, "validation_results": procedure.validation_results, "reviewed_at": procedure.reviewed_at, "validated_at": procedure.validated_at, "selection_source": source}
    if not required:
        response.update(_render_sections(procedure, {}))
    return response

def get_remediation(db: Session, user: User, finding_id: UUID):
    finding = _finding(db, user, finding_id); audit = db.get(Audit, finding.audit_id)
    restored = _restore_preview(db, finding, audit, getattr(finding, "remediation_preview", {}))
    if restored is not None:
        return restored
    procedure, reason, source = _select(db, finding, audit)
    return _response(finding, procedure, reason, source)


def _rule_finding(user, audit, rule_id, verdict, reference_id):
    if audit is None or audit.organization_id != user.organization_id:
        raise FindingNotFoundError("Assessment result not found")
    try:
        normalized = FindingVerdict(verdict)
    except ValueError:
        raise RemediationError("invalid_assessment_verdict") from None
    return SimpleNamespace(
        finding_id=reference_id, rule_id=rule_id, verdict=normalized,
        remediation_procedure_id=None,
    )


def get_rule_remediation(db, user, audit, rule_id, verdict, reference_id, parameters=None, *, policy_parameters=None, persisted_preview=None):
    """Resolve remediation for a framework result without reusing a mismatched baseline verdict."""
    finding = _rule_finding(user, audit, rule_id, verdict, reference_id)
    restored = _restore_preview(db, finding, audit, persisted_preview, policy_parameters=policy_parameters)
    if restored is not None:
        restored["assessment_result_id"] = restored.pop("finding_id")
        restored["rule_id"] = rule_id
        return restored
    procedure, reason, source = _select(db, finding, audit)
    response = (
        _preview(db, finding, audit, parameters, policy_parameters=policy_parameters)
        if parameters is not None else _response(finding, procedure, reason, source)
    )
    response["assessment_result_id"] = response.pop("finding_id")
    response["rule_id"] = rule_id
    return response

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
        if "minimum" in definition and number < definition["minimum"]: raise RemediationError("invalid_parameters")
        if "maximum" in definition and number > definition["maximum"]: raise RemediationError("invalid_parameters")
        return str(number)
    if kind == "enum" and value in definition.get("values", []): return value
    raise RemediationError("invalid_parameters")


def _render_section(steps, values):
    rendered = []
    for step in steps:
        text = step.get("text") if isinstance(step, dict) else None
        if not isinstance(text, str): raise RemediationError("invalid_registry_entry")
        try:
            rendered.append(_PLACEHOLDER.sub(lambda match: values[match.group(1)], text))
        except KeyError as exc:
            raise RemediationError("missing_required_parameters") from exc
    return rendered


def _render_sections(procedure, values):
    return {
        "rendered_steps": _render_section(procedure.ordered_steps, values),
        "rendered_verification_steps": _render_section(procedure.verification_steps, values),
        "rendered_rollback_steps": _render_section(procedure.rollback_steps, values),
    }


def persisted_preview_payload(preview):
    """Persist validated rendering and exact procedure identity for later reports."""
    if preview.get("status") != "applicable":
        raise RemediationError("remediation_not_applicable")
    procedure_id = preview.get("procedure_id")
    if not isinstance(procedure_id, UUID) or not isinstance(preview.get("procedure_version"), int):
        raise RemediationError("invalid_registry_entry")
    payload = {
        "procedure_id": str(procedure_id), "procedure_key": preview.get("procedure_key"),
        "procedure_version": preview["procedure_version"],
        "parameters": dict(preview.get("validated_parameters") or {}),
        "rendered_steps": list(preview.get("rendered_steps") or []),
        "rendered_verification_steps": list(preview.get("rendered_verification_steps") or []),
        "rendered_rollback_steps": list(preview.get("rendered_rollback_steps") or []),
        "selection_source": preview.get("selection_source"),
    }
    if any(_PLACEHOLDER.search(step) for value in payload.values() if isinstance(value, list) for step in value if isinstance(step, str)):
        raise RemediationError("unresolved_parameters")
    return payload

def _validate_framework_parameters(policy_parameters, values):
    maximum = (policy_parameters or {}).get("maximum_admin_idle_timeout_seconds")
    if maximum is None or "minutes" not in values:
        return
    try:
        minutes, maximum_seconds = int(values["minutes"]), int(maximum)
    except (TypeError, ValueError) as exc:
        raise RemediationError("invalid_parameters") from exc
    if minutes * 60 > maximum_seconds:
        raise RemediationError("framework_parameter_exceeds_threshold")


def _restore_preview(db, finding, audit, stored, *, policy_parameters=None):
    if not isinstance(stored, dict) or not stored or finding.verdict != FindingVerdict.FAIL:
        return None
    try:
        procedure_id = UUID(str(stored["procedure_id"]))
        procedure = db.get(RemediationProcedure, procedure_id)
        if procedure is None:
            procedure = REMEDIATION_PROCEDURE_REGISTRY.by_id.get(procedure_id)
        version = int(stored["procedure_version"])
    except (KeyError, TypeError, ValueError):
        return {"status": "unavailable", "reason": "persisted_preview_invalid", "finding_id": finding.finding_id}
    if (
        procedure is None or procedure.status not in {RemediationProcedureStatus.PUBLISHED, RemediationProcedureStatus.SUPERSEDED}
        or procedure.version != version or procedure.rule_id != finding.rule_id
        or not _applicable(procedure, finding, audit)[0]
    ):
        return {"status": "unavailable", "reason": "persisted_preview_unavailable", "finding_id": finding.finding_id}
    try:
        _validate_registry_identity(procedure)
        _validate_procedure(procedure)
        definitions = {item["name"]: item for item in procedure.required_parameters}
        parameters = stored.get("parameters")
        if not isinstance(parameters, dict) or set(parameters) - set(definitions):
            raise RemediationError("invalid_parameters")
        if any(definition.get("required", True) and name not in parameters for name, definition in definitions.items()):
            raise RemediationError("missing_required_parameters")
        values = {name: _value(definitions[name], value) for name, value in parameters.items()}
        _validate_framework_parameters(policy_parameters, values)
        response = _response(finding, procedure, None, "persisted_preview")
        response.update({"status": "applicable", "validated_parameters": values, **_render_sections(procedure, values)})
        return response
    except RemediationError:
        return {"status": "unavailable", "reason": "persisted_preview_invalid", "finding_id": finding.finding_id}


def _preview(db, finding, audit, parameters, *, policy_parameters=None):
    procedure, reason, source = _select(db, finding, audit)
    base = _response(finding, procedure, reason, source)
    if not procedure or base["status"] not in {"applicable", "requires_parameters"}: return base
    definitions = {item["name"]: item for item in procedure.required_parameters}
    if set(parameters) - set(definitions): raise RemediationError("invalid_parameters")
    values = {}
    for name, definition in definitions.items():
        if definition.get("required", True) and name not in parameters: raise RemediationError("missing_required_parameters")
        if name in parameters: values[name] = _value(definition, parameters[name])
    _validate_framework_parameters(policy_parameters, values)
    return {**base, "status": "applicable", "validated_parameters": values, **_render_sections(procedure, values)}


def preview_remediation(db, user, finding_id, parameters):
    finding = _finding(db, user, finding_id)
    preview = _preview(db, finding, db.get(Audit, finding.audit_id), parameters)
    if preview.get("status") == "applicable":
        finding.remediation_preview = persisted_preview_payload(preview)
    return preview


def preview_rule_remediation(db, user, audit, rule_id, verdict, reference_id, parameters, *, policy_parameters=None):
    finding = _rule_finding(user, audit, rule_id, verdict, reference_id)
    response = _preview(db, finding, audit, parameters, policy_parameters=policy_parameters)
    response["assessment_result_id"] = response.pop("finding_id")
    response["rule_id"] = rule_id
    return response
