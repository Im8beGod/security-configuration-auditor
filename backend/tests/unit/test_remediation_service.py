from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from app.remediation.service import RemediationError, _applicable, _validate_procedure, _value
from app.remediation.catalog import REVIEWED_CISCO_PROCEDURES_BY_RULE
from app.remediation.service import _select, preview_remediation


def definition(kind, **extra): return {"name": "target", "type": kind, "required": True, **extra}

def procedure(**extra):
    values = {"required_parameters": [definition("ip_address")], "source_references": [{"source": "review"}], "validation_results": [{"result": "validated"}], "ordered_steps": [{"text": "set {target}"}], "profile_applicability": {"profile_version_ids": ["cisco.ios_xe.17@1.0.0"]}}
    values.update(extra)
    return SimpleNamespace(**values)

def test_parameter_validation_is_bounded_and_canonical():
    assert _value(definition("ip_address"), "2001:db8::1") == "2001:db8::1"
    assert _value(definition("ip_network"), "192.0.2.2/24") == "192.0.2.0/24"
    assert _value(definition("hostname"), "Edge-01.example") == "edge-01.example"
    assert _value(definition("hostname"), "192.0.2.10") == "192.0.2.10"
    assert _value(definition("port"), "443") == "443"
    assert _value(definition("enum", values=["ssh"]), "ssh") == "ssh"
    with pytest.raises((RemediationError, ValueError)): _value(definition("ip_network"), "192.0.2.1/99")
    with pytest.raises(RemediationError): _value(definition("hostname"), "safe\nnext")
    with pytest.raises(RemediationError): _value(definition("integer"), "not-a-number")
    with pytest.raises(RemediationError): _value(definition("port"), "65536")

def test_registry_schema_rejects_unknown_placeholder_and_duplicates():
    invalid = procedure(ordered_steps=[{"text": "set {unknown}"}])
    with pytest.raises(RemediationError): _validate_procedure(invalid)
    invalid = procedure(required_parameters=[definition("ip_address"), definition("hostname")])
    with pytest.raises(RemediationError): _validate_procedure(invalid)

def test_applicability_requires_consistent_exact_persisted_profile_pin():
    audit = SimpleNamespace(version_refs={"device_profile_version_id": "cisco.ios_xe.17@1.0.0"}, profile_resolution={"profile_version_id": "cisco.ios_xe.17@1.0.0", "resolution_status": "resolved"})
    assert _applicable(procedure(), SimpleNamespace(), audit) == (True, None)
    audit.profile_resolution["profile_version_id"] = "other"
    assert _applicable(procedure(), SimpleNamespace(), audit) == (False, "profile_context_mismatch")


class EmptyDb:
    def scalars(self, _statement):
        return ()

    def scalar(self, _statement):
        return self.finding

    def get(self, _model, _identifier):
        return self.audit


def _catalog_context(rule_id, profile="cisco.ios_xe.17@1.0.0"):
    finding = SimpleNamespace(finding_id=uuid4(), audit_id=UUID(int=2), rule_id=rule_id, remediation_procedure_id=None, verdict="fail")
    audit = SimpleNamespace(
        version_refs={"device_profile_version_id": profile},
        profile_resolution={"profile_version_id": profile, "resolution_status": "resolved"},
    )
    db = EmptyDb(); db.finding = finding; db.audit = audit
    return db, finding, audit


def test_reviewed_cisco_catalog_selects_only_three_supported_rules_and_previews_cli():
    expected = {
        "management.ssh.version_2": ([], "ip ssh version 2"),
        "logging.remote.destination.configured": (["destination"], "logging host 192.0.2.10"),
        "time.ntp.server.configured": (["server"], "ntp server time.example.invalid"),
    }
    for rule_id, (parameter_names, command) in expected.items():
        db, finding, audit = _catalog_context(rule_id)
        selected, reason, source = _select(db, finding, audit)
        assert selected is REVIEWED_CISCO_PROCEDURES_BY_RULE[rule_id]
        assert reason is None and source == "built_in_reviewed_catalog"
        parameters = {name: ("192.0.2.10" if name == "destination" else "time.example.invalid") for name in parameter_names}
        preview = preview_remediation(db, SimpleNamespace(organization_id=UUID(int=1)), finding.finding_id, parameters)
        assert command in preview["rendered_steps"]
        assert preview["verification_steps"] and preview["rollback_steps"] and preview["source_references"]
        assert preview["reviewed_at"] and preview["validated_at"]


def test_catalog_is_profile_isolated_and_unsupported_controls_remain_unavailable():
    db, finding, audit = _catalog_context("management.ssh.version_2", "fortinet.fortios.7@1.0.0")
    selected, reason, _source = _select(db, finding, audit)
    assert selected is None and reason == "unsupported_profile"
    db, finding, audit = _catalog_context("management.remote.telnet.enabled")
    selected, reason, _source = _select(db, finding, audit)
    assert selected is None and reason == "no_published_procedure"


def test_catalog_rejects_malformed_parameters_without_execution():
    db, finding, _audit = _catalog_context("logging.remote.destination.configured")
    with pytest.raises(RemediationError):
        preview_remediation(db, SimpleNamespace(organization_id=UUID(int=1)), finding.finding_id, {"destination": "bad value"})
