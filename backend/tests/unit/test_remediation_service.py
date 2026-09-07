from types import SimpleNamespace

import pytest

from app.remediation.service import RemediationError, _applicable, _validate_procedure, _value


def definition(kind, **extra): return {"name": "target", "type": kind, "required": True, **extra}

def procedure(**extra):
    values = {"required_parameters": [definition("ip_address")], "source_references": [{"source": "review"}], "validation_results": [{"result": "validated"}], "ordered_steps": [{"text": "set {target}"}], "profile_applicability": {"profile_version_ids": ["cisco.ios_xe.17@1.0.0"]}}
    values.update(extra)
    return SimpleNamespace(**values)

def test_parameter_validation_is_bounded_and_canonical():
    assert _value(definition("ip_address"), "2001:db8::1") == "2001:db8::1"
    assert _value(definition("ip_network"), "192.0.2.2/24") == "192.0.2.0/24"
    assert _value(definition("hostname"), "Edge-01.example") == "edge-01.example"
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
