from types import SimpleNamespace
from uuid import UUID, uuid4

import app.interpretation.service  # noqa: F401
from app.compliance.rule_registry import RULE_PACK_BY_PROFILE
from app.knowledge_packs.arista_eos_4 import ARISTA_EOS_4_KNOWLEDGE_PACK
from app.knowledge_packs.cisco_iosxe_17.manifest import CISCO_IOS_XE_17_KNOWLEDGE_PACK
from app.knowledge_packs.fortios_7 import FORTIOS_7_KNOWLEDGE_PACK
from app.knowledge_packs.juniper_junos_18.manifest import JUNIPER_JUNOS_18_KNOWLEDGE_PACK
from app.remediation.catalog import UNAVAILABLE_REMEDIATION_REASONS
from app.remediation.service import _restore_preview, _select, persisted_preview_payload, preview_remediation
from app.db.models import RemediationProcedure


class EmptyDb:
    def scalars(self, _statement):
        return ()

    def scalar(self, _statement):
        return self.finding

    def get(self, _model, _identifier):
        return self.audit


def _context(profile, rule_id):
    finding = SimpleNamespace(
        finding_id=uuid4(), audit_id=UUID(int=2), rule_id=rule_id,
        remediation_procedure_id=None, verdict="fail",
    )
    audit = SimpleNamespace(
        version_refs={"device_profile_version_id": profile},
        profile_resolution={"profile_version_id": profile, "resolution_status": "resolved"},
    )
    db = EmptyDb(); db.finding = finding; db.audit = audit
    return db, finding, audit


def test_every_builtin_fail_capable_mapping_has_reviewed_or_explicit_unavailable_remediation():
    packs = (
        CISCO_IOS_XE_17_KNOWLEDGE_PACK,
        FORTIOS_7_KNOWLEDGE_PACK,
        JUNIPER_JUNOS_18_KNOWLEDGE_PACK,
        ARISTA_EOS_4_KNOWLEDGE_PACK,
    )
    covered = set()
    for pack in packs:
        fields = {mapping.field_id for mapping in pack.mappings}
        for rule in RULE_PACK_BY_PROFILE[pack.profile_version_id].rules:
            if rule.required_effective_states[0] not in fields:
                continue
            pair = (pack.profile_version_id, rule.rule_id)
            covered.add(pair)
            db, finding, audit = _context(*pair)
            procedure, reason, source = _select(db, finding, audit)
            if procedure is None:
                assert reason == UNAVAILABLE_REMEDIATION_REASONS[pair]
            else:
                assert reason is None and source == "built_in_reviewed_catalog"
                assert procedure.rule_id == rule.rule_id
                assert procedure.profile_applicability["profile_version_ids"] == [pack.profile_version_id]
                assert procedure.prerequisites and procedure.safety_warnings
                assert procedure.verification_steps and procedure.rollback_steps
                assert procedure.source_references
    assert covered


def test_new_bounded_procedures_render_vendor_specific_commands_and_validate_parameters():
    cases = (
        ("cisco.ios_xe.17@1.0.0", "management.idle_timeout.maximum", {"vty_range": "0 4", "minutes": "10"}, "exec-timeout 10 0"),
        ("fortinet.fortios.7@1.0.0", "management.idle_timeout.maximum", {"minutes": "10"}, "set admintimeout 10"),
        ("juniper.junos.18@1.0.0", "management.idle_timeout.maximum", {"minutes": "10"}, "set system login idle-timeout 10"),
        ("fortinet.fortios.7@1.0.0", "management.http.disabled", {"interface": "port1", "protocols": "https ssh"}, "set allowaccess https ssh"),
        ("fortinet.fortios.7@1.0.0", "management.https.enabled", {"interface": "port1", "protocols": "https ssh"}, "set allowaccess https ssh"),
        ("fortinet.fortios.7@1.0.0", "management.tls.minimum_1_2", {}, "set admin-https-ssl-versions tlsv1-2 tlsv1-3"),
        ("fortinet.fortios.7@1.0.0", "logging.enabled", {}, "set status enable"),
        ("fortinet.fortios.7@1.0.0", "logging.remote.destination.configured", {"destination": "logs.example.invalid"}, "set server logs.example.invalid"),
    )
    for profile, rule_id, parameters, command in cases:
        db, finding, _audit = _context(profile, rule_id)
        preview = preview_remediation(db, SimpleNamespace(organization_id=UUID(int=1)), finding.finding_id, parameters)
        assert preview["status"] == "applicable"
        assert command in preview["rendered_steps"]
        assert preview["rendered_verification_steps"] and preview["rendered_rollback_steps"]


def test_catalog_preview_is_restored_identically_when_no_database_copy_exists():
    db, finding, audit = _context(
        "fortinet.fortios.7@1.0.0", "management.http.disabled",
    )
    preview = preview_remediation(
        db, SimpleNamespace(organization_id=UUID(int=1)), finding.finding_id,
        {"interface": "port1", "protocols": "https ssh"},
    )
    stored = persisted_preview_payload(preview)
    db.get = lambda model, _identifier: None if model is RemediationProcedure else audit
    restored = _restore_preview(db, finding, audit, stored)
    assert restored["selection_source"] == "persisted_preview"
    assert restored["rendered_steps"] == preview["rendered_steps"]
    assert restored["rendered_verification_steps"] == preview["rendered_verification_steps"]
    assert restored["rendered_rollback_steps"] == preview["rendered_rollback_steps"]
