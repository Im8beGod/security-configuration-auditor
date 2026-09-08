from dataclasses import replace
from uuid import UUID

import pytest
from sqlalchemy import CheckConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB

from app.db.models import (
    FactState,
    FactValidationStatus,
    InterpretationConfidence,
    InterpretationMethod,
    SecurityFact,
)
from app.interpretation.extractors import EXTRACTORS
from app.interpretation.knowledge_pack import (
    KnowledgePackValidationError,
    validate_knowledge_pack,
)
from app.interpretation.scopes import SCOPE_RESOLVER_TYPES
from app.interpretation.service import load_validated_knowledge_pack
from app.interpretation.service import load_validated_knowledge_pack_by_version
from app.knowledge_packs.cisco_iosxe_17 import CISCO_IOS_XE_17_KNOWLEDGE_PACK
from app.knowledge_packs.fortios_7 import FORTIOS_7_KNOWLEDGE_PACK, FORTIOS_7_KNOWLEDGE_PACK_V1
from app.security_model import (
    FIELD_REGISTRY,
    FieldRegistryValidationError,
    ScopeRef,
    TypedValue,
    TypedValueType,
    get_field,
    validate_field_value_scope,
)


def _validate(pack=CISCO_IOS_XE_17_KNOWLEDGE_PACK):
    return validate_knowledge_pack(
        pack,
        expected_profile_id="cisco.ios_xe.17",
        expected_profile_version_id="cisco.ios_xe.17@1.0.0",
        allowed_extractors=frozenset(EXTRACTORS),
        scope_resolver_types=SCOPE_RESOLVER_TYPES,
    )


def test_field_registry_accepts_registered_compatible_values_and_scopes():
    field = validate_field_value_scope(
        "management.session.idle_timeout",
        TypedValue(TypedValueType.DURATION, 600, unit="seconds"),
        ScopeRef("vty_range", "vty:0-4", {"start": 0, "end": 4}),
    )
    assert field == get_field("management.session.idle_timeout")
    assert set(FIELD_REGISTRY) == {
        "management.remote.telnet.enabled",
        "management.remote.ssh.enabled",
        "management.remote.ssh.version",
        "management.session.idle_timeout",
        "logging.remote.destination",
        "time.ntp.server",
    }


def test_field_registry_rejects_unknown_wrong_type_and_wrong_scope():
    with pytest.raises(FieldRegistryValidationError, match="Unknown"):
        get_field("invented.field")
    with pytest.raises(FieldRegistryValidationError, match="type"):
        validate_field_value_scope(
            "management.remote.ssh.version",
            TypedValue(TypedValueType.STRING, "2"),
            ScopeRef("device", "device", {}),
        )
        with pytest.raises(FieldRegistryValidationError, match="Scope"):
            validate_field_value_scope(
                "management.remote.ssh.enabled",
                TypedValue(TypedValueType.BOOLEAN, True),
                ScopeRef("interface", "port1", {}),
            )
    with pytest.raises(FieldRegistryValidationError, match="value"):
        validate_field_value_scope(
            "management.remote.ssh.version",
            TypedValue(TypedValueType.INTEGER, True),
            ScopeRef("device", "device", {}),
        )


def test_ios_xe_pack_loads_with_stable_compatible_identity():
    pack = load_validated_knowledge_pack("cisco.ios_xe.17@1.0.0")
    assert pack is CISCO_IOS_XE_17_KNOWLEDGE_PACK
    assert pack.profile_id == "cisco.ios_xe.17"
    assert pack.profile_version_id == "cisco.ios_xe.17@1.0.0"
    assert pack.knowledge_pack_id == UUID("33ededa8-0c17-55e0-b104-302fc55de5b8")
    assert pack.knowledge_pack_version_id == UUID("dbad6d61-97d6-5e42-a1aa-feb4e28e15b0")
    assert [item.mapping_id for item in pack.mappings] == [
        UUID("c2a81d5b-9591-5ecd-beee-46beb57acced"),
        UUID("bc2cc368-40eb-53ed-896e-5efd779359d3"),
        UUID("79a68ade-607d-5148-98cf-5e9f5e92943a"),
        UUID("98f4ebb2-a48e-51f0-8611-430e6987e212"),
        UUID("3363d69a-c3e8-53a8-844a-9146e7eee8e3"),
        UUID("3f7d8702-ed3f-5c11-ab86-34d057d95678"),
    ]
    assert [item.mapping_version_id for item in pack.mappings] == [
        UUID("4e5634f2-c0f2-529e-912f-e42139aed61e"),
        UUID("82f62960-c06e-5ee1-a1ce-ccd574ead730"),
        UUID("a153b5c4-786d-5940-9fc7-2906ea7d42c7"),
        UUID("4b13928b-98eb-5dc2-a739-d978d5c8bd95"),
        UUID("f112df12-f860-5fad-b013-7b89701d2fcf"),
        UUID("31eadc31-751e-5451-bdd7-2532a26c9710"),
    ]


def test_immutable_knowledge_pack_versions_remain_independently_loadable():
    legacy = load_validated_knowledge_pack_by_version(
        UUID("17e3e913-17df-53bf-b8c1-5cae4bfa133e")
    )
    current = load_validated_knowledge_pack_by_version(
        UUID("dbad6d61-97d6-5e42-a1aa-feb4e28e15b0")
    )
    fortios_legacy = load_validated_knowledge_pack_by_version(
        FORTIOS_7_KNOWLEDGE_PACK_V1.knowledge_pack_version_id
    )
    fortios_current = load_validated_knowledge_pack_by_version(
        FORTIOS_7_KNOWLEDGE_PACK.knowledge_pack_version_id
    )
    assert legacy.version == "1.0.0"
    assert current.version == "1.1.0"
    assert legacy.mappings[0].mapping_version_id == current.mappings[0].mapping_version_id
    assert current.mappings[0].reset_mapping_version_id == UUID("e42c0eb2-1d5d-584a-b463-8ee80574a35c")
    assert fortios_legacy.version == "1.0.0"
    assert fortios_current.version == "1.1.0"
    assert fortios_legacy.mappings[0].mapping_version_id != fortios_current.mappings[0].mapping_version_id


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda pack: replace(pack, schema_version="999"), "schema"),
        (lambda pack: replace(pack, profile_version_id="other"), "incompatible"),
        (
            lambda pack: replace(pack, mappings=(pack.mappings[0], pack.mappings[0])),
            "Duplicate mapping ID",
        ),
        (
            lambda pack: replace(pack, mappings=(
                pack.mappings[0],
                replace(pack.mappings[1], mapping_version_id=pack.mappings[0].mapping_version_id),
            )),
            "Duplicate mapping-version ID",
        ),
        (
            lambda pack: replace(pack, mappings=(replace(
                pack.mappings[0], field_id="unknown.field"
            ),)),
            "unknown canonical field",
        ),
        (
            lambda pack: replace(pack, mappings=(replace(
                pack.mappings[0], extractor="unrestricted_expression"
            ),)),
            "unknown extractor",
        ),
        (
            lambda pack: replace(pack, mappings=(replace(
                pack.mappings[0], scope_resolver="invented_scope"
            ),)),
            "unknown scope resolver",
        ),
        (
            lambda pack: replace(pack, mappings=(replace(
                pack.mappings[0],
                matcher=replace(pack.mappings[0].matcher, command="bad command"),
            ),)),
            "malformed",
        ),
        (
            lambda pack: replace(pack, mappings=(replace(
                pack.mappings[3],
                matcher=replace(
                    pack.mappings[3].matcher,
                    parent_arguments_prefix=("vty",),
                ),
            ),)),
            "parent matcher is malformed",
        ),
        (
            lambda pack: replace(pack, mappings=(replace(
                pack.mappings[0], declared_value_types=frozenset({TypedValueType.STRING})
            ),)),
            "value type",
        ),
    ],
)
def test_invalid_knowledge_packs_are_rejected_before_interpretation(mutation, message):
    with pytest.raises(KnowledgePackValidationError, match=message):
        _validate(mutation(CISCO_IOS_XE_17_KNOWLEDGE_PACK))


def test_security_fact_orm_matches_frozen_contract():
    table = SecurityFact.__table__
    columns = table.c
    checks = {
        item.name for item in table.constraints if isinstance(item, CheckConstraint)
    }
    assert table.name == "security_facts"
    assert columns.fact_id.primary_key and isinstance(columns.fact_id.type, Uuid)
    assert columns.audit_id.index and columns.device_id.index and columns.snapshot_id.index
    assert isinstance(columns.value.type, JSONB) and isinstance(columns.scope.type, JSONB)
    assert isinstance(columns.evidence_refs.type, JSONB)
    assert isinstance(columns.source_ir_node_ids.type, JSONB)
    assert isinstance(columns.dependencies.type, JSONB)
    assert columns.mapping_id.nullable and columns.mapping_version_id.nullable
    assert not columns.knowledge_pack_version_id.nullable
    assert columns.state.type.enums == [item.value for item in FactState]
    assert columns.extraction_method.type.enums == [item.value for item in InterpretationMethod]
    assert columns.validation_status.type.enums == [item.value for item in FactValidationStatus]
    assert columns.interpretation_confidence.type.enums == [
        item.value for item in InterpretationConfidence
    ]
    assert {
        "ck_security_facts_field_id", "ck_security_facts_value",
        "ck_security_facts_scope", "ck_security_facts_evidence_refs",
        "ck_security_facts_source_ir_node_ids", "ck_security_facts_dependencies",
    } <= checks
