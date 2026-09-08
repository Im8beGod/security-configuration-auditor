from hashlib import sha256
from uuid import UUID, uuid4

from app.db.models import (
    Artifact,
    ArtifactContentFamily,
    ArtifactEvidenceType,
    ArtifactStatus,
    DeviceClass,
)
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.profile_resolution import (
    CISCO_IOS_XE_17,
    FORTIOS_7,
    MAX_ARTIFACT_INSPECTION_BYTES,
    PROFILE_REGISTRY,
    ResolutionConfidence,
    ResolutionStatus,
    SnapshotEvidence,
    aggregate_snapshot_evidence,
    resolve_profile,
)
from app.profile_resolution.evidence import EvidenceDocument


def _document(
    text: str,
    *,
    evidence_type: ArtifactEvidenceType = ArtifactEvidenceType.VERSION_OUTPUT,
    filename: str = "evidence.txt",
    artifact_number: int = 1,
) -> EvidenceDocument:
    return EvidenceDocument(
        artifact_id=UUID(int=artifact_number),
        organization_id=UUID(int=100),
        snapshot_id=UUID(int=200),
        device_id=UUID(int=300),
        evidence_type=evidence_type,
        original_filename=filename,
        sha256="a" * 64,
        source_metadata={"ingestion": "test"},
        text=text,
        inspected_bytes=len(text.encode()),
        truncated=False,
    )


def _resolve(*documents: EvidenceDocument):
    return resolve_profile(SnapshotEvidence(
        snapshot_id=UUID(int=200),
        organization_id=UUID(int=100),
        device_id=UUID(int=300),
        documents=documents,
        issues=(),
        inspected_bytes=sum(item.inspected_bytes for item in documents),
    ))


def test_registry_identity_and_capability_are_stable_and_bounded():
    assert PROFILE_REGISTRY == {
        "cisco.ios_xe.17@1.0.0": CISCO_IOS_XE_17,
        "fortinet.fortios.7@1.0.0": FORTIOS_7,
    }
    assert CISCO_IOS_XE_17.profile_id == "cisco.ios_xe.17"
    assert CISCO_IOS_XE_17.profile_version == "1.0.0"
    assert CISCO_IOS_XE_17.version_constraint.accepts("17.9.4a")
    assert not CISCO_IOS_XE_17.version_constraint.accepts("16.12.5")
    assert CISCO_IOS_XE_17.capabilities == {
        "profile_detection", "structural_parsing", "semantic_interpretation",
        "effective_state_resolution", "deterministic_compliance",
    }
    coverage = CISCO_IOS_XE_17.coverage_manifest
    assert coverage["profile_detection"] is True
    assert coverage["structural_parsing"] is True
    assert coverage["semantic_interpretation"] is True
    assert coverage["effective_state_resolution"] is True
    assert coverage["supported_version_family"] == "IOS XE 17.x"
    assert coverage["structural_reader"] == "indentation_cli.v1"
    assert set(coverage["canonical_fields"]) == {
        "management.remote.telnet.enabled",
        "management.remote.ssh.enabled",
        "management.remote.ssh.version",
        "management.session.idle_timeout",
        "logging.remote.destination",
        "time.ntp.server",
    }
    assert coverage["command_forms"] == (
        "transport input telnet|ssh|telnet ssh|ssh telnet|none",
        "exec-timeout <minutes> [seconds]",
        "ip ssh version 1|2",
        "logging host <ip-or-hostname>",
        "ntp server <ip-or-hostname>",
    )
    assert "no documented defaults, inheritance, references, or bindings" in coverage["limitations"]
    assert CISCO_IOS_XE_17.structural_reader_name == "indentation_cli.v1"
    assert CISCO_IOS_XE_17.knowledge_pack_name == "cisco_iosxe_17@1.1.0"


def test_explicit_ios_xe_17_version_selects_stable_supported_profile():
    result = _resolve(_document(
        "Cisco IOS XE Software, Version 17.9.4a\n"
        "cisco C9300-48P (X86) processor (revision V01) with 8388608K bytes of memory.\n"
    ))

    assert result.vendor == "Cisco"
    assert result.os == "IOS XE"
    assert result.os_version == "17.9.4a"
    assert result.model == "C9300-48P"
    assert result.product_family == "Catalyst"
    assert result.device_class == DeviceClass.SWITCH
    assert result.selected_profile_id == CISCO_IOS_XE_17.profile_id
    assert result.selected_profile_version_id == CISCO_IOS_XE_17.profile_version_id
    assert result.confidence == ResolutionConfidence.HIGH
    assert result.resolution_status == ResolutionStatus.RESOLVED


def test_realistic_ios_xe_image_signature_extracts_version():
    result = _resolve(_document(
        "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software "
        "(CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)"
    ))
    assert result.os == "IOS XE"
    assert result.os_version == "17.9.4a"
    assert result.resolution_status == ResolutionStatus.RESOLVED


def test_multi_artifact_evidence_combines_config_version_model_and_serial():
    result = _resolve(
        _document(
            "hostname branch-1\ninterface GigabitEthernet1\naaa new-model\nline vty 0 4\n",
            evidence_type=ArtifactEvidenceType.CONFIGURATION,
            filename="running-config.txt",
            artifact_number=1,
        ),
        _document(
            "Cisco IOS XE Software, Version 17.12.3\n"
            "cisco ISR4331/K9 (1RU) processor with 1795999K bytes of memory\n",
            filename="show-version.txt",
            artifact_number=2,
        ),
        _document(
            'NAME: "Chassis", DESCR: "Cisco ISR4331 Chassis"\n'
            "PID: ISR4331/K9, VID: V05, SN: FDO00000001\n",
            evidence_type=ArtifactEvidenceType.INVENTORY_OUTPUT,
            filename="show-inventory.txt",
            artifact_number=3,
        ),
    )

    assert result.model == "ISR4331/K9"
    assert result.serial_number == "FDO00000001"
    assert result.product_family == "ISR"
    assert result.device_class == DeviceClass.ROUTER
    assert {signal.artifact_id for signal in result.supporting_signals} == {
        UUID(int=1), UUID(int=2), UUID(int=3)
    }


def test_configuration_only_cisco_syntax_remains_low_confidence_and_not_ios_xe():
    result = _resolve(_document(
        "hostname edge\ninterface GigabitEthernet0/0\naaa new-model\n"
        "ip access-list extended FILTER\nline vty 0 4\nsnmp-server community example RO\n",
        evidence_type=ArtifactEvidenceType.CONFIGURATION,
        filename="running.cfg",
    ))

    assert result.vendor == "Cisco"
    assert result.os is None and result.os_version is None
    assert result.selected_profile_id is None
    assert result.confidence == ResolutionConfidence.LOW
    assert result.resolution_status == ResolutionStatus.PARTIALLY_RESOLVED


def test_traditional_cisco_ios_evidence_is_not_promoted_to_ios_xe():
    result = _resolve(_document(
        "Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), "
        "Version 15.7(3)M8, RELEASE SOFTWARE (fc1)"
    ))

    assert result.vendor == "Cisco"
    assert result.os == "IOS"
    assert result.os_version == "15.7(3)M8"
    assert result.selected_profile_id is None
    assert result.resolution_status == ResolutionStatus.UNSUPPORTED


def test_ios_xe_outside_17_x_is_preserved_but_profile_is_not_selected():
    result = _resolve(_document("Cisco IOS XE Software, Version 16.12.5"))
    assert result.vendor == "Cisco" and result.os == "IOS XE"
    assert result.os_version == "16.12.5"
    assert result.selected_profile_id is None
    assert result.confidence == ResolutionConfidence.HIGH
    assert result.resolution_status == ResolutionStatus.UNSUPPORTED


def test_ios_xe_without_version_does_not_establish_profile_applicability():
    result = _resolve(_document("Cisco IOS XE Software\nCopyright Cisco Systems"))
    assert result.os == "IOS XE" and result.os_version is None
    assert result.selected_profile_id is None
    assert result.confidence == ResolutionConfidence.MEDIUM
    assert result.resolution_status == ResolutionStatus.PARTIALLY_RESOLVED


def test_ios_xe_signature_inside_configuration_is_supported_but_not_high_confidence():
    result = _resolve(_document(
        "Cisco IOS XE Software, Version 17.9.4a",
        evidence_type=ArtifactEvidenceType.CONFIGURATION,
    ))
    assert result.selected_profile_id == CISCO_IOS_XE_17.profile_id
    assert result.confidence == ResolutionConfidence.MEDIUM


def test_unrelated_vendor_is_detected_without_selecting_cisco_profile():
    result = _resolve(_document("Junos: 23.4R1.9\nModel: ex4400-48mp"))
    assert result.vendor == "Juniper"
    assert result.os == "Junos"
    assert result.os_version == "23.4R1.9"
    assert result.selected_profile_id is None
    assert result.resolution_status == ResolutionStatus.UNSUPPORTED


def test_fortios_7_selects_the_fortinet_profile():
    result = _resolve(_document(
        "FortiOS v7.4.3,build2573", evidence_type=ArtifactEvidenceType.CONFIGURATION
    ))
    assert result.vendor == "Fortinet"
    assert result.product_family == "FortiGate"
    assert result.os == "FortiOS" and result.os_version == "7.4.3"
    assert result.selected_profile_version_id == FORTIOS_7.profile_version_id
    assert result.resolution_status == ResolutionStatus.RESOLVED


def test_cisco_evidence_is_not_misdetected_as_fortios():
    result = _resolve(_document("Cisco IOS XE Software, Version 17.9.4a"))
    assert result.vendor == "Cisco"
    assert result.selected_profile_id != FORTIOS_7.profile_id


def test_fortios_unsupported_or_ambiguous_evidence_fails_safely():
    unsupported = _resolve(_document("FortiOS v6.4.15"))
    conflict = _resolve(
        _document("FortiOS v7.4.3", artifact_number=1),
        _document("Cisco IOS XE Software, Version 17.9.4a", artifact_number=2),
    )
    assert unsupported.resolution_status == ResolutionStatus.UNSUPPORTED
    assert unsupported.selected_profile_id is None
    assert conflict.resolution_status == ResolutionStatus.CONFLICT


def test_generic_model_number_does_not_create_cisco_identity():
    result = _resolve(_document(
        "Model Number: unrelated-appliance-5000\nSystem Serial Number: REDACTED01",
        evidence_type=ArtifactEvidenceType.INVENTORY_OUTPUT,
    ))
    assert result.vendor is None
    assert result.model is None and result.serial_number is None
    assert result.resolution_status == ResolutionStatus.UNRESOLVED


def test_filename_hint_alone_cannot_establish_identification():
    result = _resolve(_document(
        "ordinary text without platform evidence",
        evidence_type=ArtifactEvidenceType.UNKNOWN_EVIDENCE,
        filename="cisco-ios-xe.cfg",
    ))
    assert result.vendor is None and result.os is None
    assert result.confidence == ResolutionConfidence.UNRESOLVED
    assert result.resolution_status == ResolutionStatus.UNRESOLVED
    assert [item.signal_id for item in result.supporting_signals] == ["cisco_filename_hint"]


def test_conflicting_strong_platform_evidence_is_controlled_and_unresolved():
    result = _resolve(
        _document("Cisco IOS XE Software, Version 17.9.4a", artifact_number=1),
        _document("JUNOS Software Release [22.4R3-S2.6]", artifact_number=2),
    )
    assert result.vendor is None and result.os is None
    assert result.selected_profile_id is None
    assert result.confidence == ResolutionConfidence.UNRESOLVED
    assert result.resolution_status == ResolutionStatus.CONFLICT
    assert result.conflicts[0].code == "platform_identity_conflict"


def test_conflicting_ios_xe_versions_are_not_arbitrarily_selected():
    result = _resolve(
        _document("Cisco IOS XE Software, Version 17.9.4a", artifact_number=1),
        _document("Cisco IOS XE Software, Version 17.12.3", artifact_number=2),
    )
    assert result.vendor == "Cisco" and result.os == "IOS XE"
    assert result.os_version is None and result.selected_profile_id is None
    assert result.resolution_status == ResolutionStatus.CONFLICT
    assert result.conflicts[0].code == "os_version_conflict"


def test_banner_comment_malformed_and_empty_content_do_not_crash_or_instruct_resolver():
    banner = _resolve(_document(
        "banner motd ^C\nCisco IOS XE Software, Version 17.9.4a\n^C\n"
        "! Cisco IOS XE Software, Version 17.9.4a\n"
        "hostname edge\ninterface Gi0/0\nline vty 0 4\n",
        evidence_type=ArtifactEvidenceType.CONFIGURATION,
        filename="odd.cfg",
    ))
    malformed = _resolve(_document("\ufffd\ufffd\n{{{{[[[\n" + "x" * 10_000))
    empty = _resolve(_document(" \n\t\n", evidence_type=ArtifactEvidenceType.UNKNOWN_EVIDENCE))

    assert banner.os is None and banner.selected_profile_id is None
    assert malformed.resolution_status == ResolutionStatus.UNRESOLVED
    assert empty.resolution_status == ResolutionStatus.UNRESOLVED


def test_persisted_shape_is_canonical_and_does_not_include_raw_or_diagnostics():
    result = _resolve(_document("Cisco IOS XE Software, Version 17.9.4a"))
    persisted = result.to_persisted()
    assert set(persisted) == {
        "profile_id", "profile_version_id", "vendor", "product_family", "os",
        "os_version", "model", "serial_number", "confidence", "resolution_status",
        "identity_provenance", "conflicts",
    }
    assert "Cisco IOS XE Software" not in str(persisted)
    assert "supporting_signals" not in persisted


def test_evidence_aggregation_is_ordered_bounded_and_storage_backed(tmp_path):
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    organization_id, snapshot_id = uuid4(), uuid4()
    content = b"Cisco IOS XE Software, Version 17.9.4a\n" + (
        b"x" * MAX_ARTIFACT_INSPECTION_BYTES
    )
    artifacts = []
    for evidence_type, filename in (
        (ArtifactEvidenceType.CONFIGURATION, "first.cfg"),
        (ArtifactEvidenceType.VERSION_OUTPUT, "second.txt"),
    ):
        artifact_id = uuid4()
        reference = storage.write(
            content, organization_id=organization_id, artifact_id=artifact_id
        )
        artifacts.append(Artifact(
            artifact_id=artifact_id,
            organization_id=organization_id,
            snapshot_id=snapshot_id,
            original_filename=filename,
            storage_reference=reference,
            byte_size=len(content),
            sha256=sha256(content).hexdigest(),
            content_family=ArtifactContentFamily.TEXT,
            evidence_type=evidence_type,
            status=ArtifactStatus.READY,
            encoding="utf-8",
        ))

    evidence = aggregate_snapshot_evidence(
        storage,
        snapshot_id=snapshot_id,
        organization_id=organization_id,
        device_id=uuid4(),
        artifacts=artifacts,
    )
    assert [item.evidence_type for item in evidence.documents] == [
        ArtifactEvidenceType.VERSION_OUTPUT, ArtifactEvidenceType.CONFIGURATION
    ]
    assert all(item.inspected_bytes == MAX_ARTIFACT_INSPECTION_BYTES for item in evidence.documents)
    assert all(item.truncated for item in evidence.documents)
    assert evidence.inspected_bytes == 2 * MAX_ARTIFACT_INSPECTION_BYTES
