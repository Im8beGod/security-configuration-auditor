import json

import pytest

from app.assessment_packs.catalog import CatalogImportError, parse_runtime_catalog, runtime_catalog_preview


def _payload(**overrides):
    payload = {
        "schema_version": "1.0.0",
        "pack_key": "tenant.custom.remote-access",
        "family": "Customer Security Standard",
        "name": "Customer remote access baseline",
        "version": 1,
        "source_version": "2026.1",
        "source_url": "https://standards.example.invalid/customer-baseline.json",
        "profile_version_ids": ["cisco.ios_xe.17@1.0.0"],
        "obligations": [
            {
                "obligation_key": "CUSTOM-SSH-1",
                "control_id": "CUSTOM-SSH-1",
                "title": "SSH must be enabled",
                "severity": "high",
                "scope": "device",
                "assessment_method": "automatic",
                "implementation_status": "implemented",
                "evaluator_rule_id": "management.ssh.enabled",
                "policy_parameters": {},
            },
            {
                "obligation_key": "CUSTOM-MANUAL-1",
                "control_id": "CUSTOM-MANUAL-1",
                "title": "Review incident process",
                "severity": "not_assigned",
                "scope": "organization",
                "assessment_method": "manual",
                "implementation_status": "manual",
            },
        ],
    }
    payload.update(overrides)
    return json.dumps(payload).encode()


def test_runtime_catalog_preview_validates_automatic_binding_and_manual_honesty():
    catalog = parse_runtime_catalog(_payload(), "customer.json")
    preview = runtime_catalog_preview(catalog)

    assert preview["automatic"] == 1
    assert preview["manual"] == 1
    assert catalog.obligations[0]["policy_parameters"]["required_canonical_fields"] == ["management.remote.ssh.enabled"]
    assert catalog.obligations[1]["evaluator_rule_id"] is None


@pytest.mark.parametrize("mutate", [
    lambda payload: payload["obligations"][0].update({"evaluator_rule_id": "not.a.real.rule"}),
    lambda payload: payload["obligations"][0].update({"policy_parameters": {"unexpected": True}}),
    lambda payload: payload["obligations"][1].update({"evaluator_rule_id": "management.ssh.enabled"}),
])
def test_runtime_catalog_rejects_unbound_or_dishonest_obligations(mutate):
    payload = json.loads(_payload())
    mutate(payload)
    with pytest.raises(CatalogImportError):
        parse_runtime_catalog(json.dumps(payload).encode(), "customer.json")


def test_runtime_catalog_uses_tenant_scoped_profile_lookup():
    profile_version_id = "runtime.acme.1@1.0.0"
    payload = json.loads(_payload(
        profile_version_ids=[profile_version_id],
        obligations=[{
            "obligation_key": "CUSTOM-MANUAL-1", "control_id": "CUSTOM-MANUAL-1",
            "title": "Manual", "severity": "not_assigned", "scope": "organization",
            "assessment_method": "manual", "implementation_status": "manual",
        }],
    ))

    catalog = parse_runtime_catalog(
        json.dumps(payload).encode(), "runtime.json",
        profile_lookup=lambda value: object() if value == profile_version_id else None,
    )

    assert catalog.profile_version_ids == (profile_version_id,)
    with pytest.raises(CatalogImportError, match="unsupported profile"):
        parse_runtime_catalog(json.dumps(payload).encode(), "runtime.json", profile_lookup=lambda _value: None)
