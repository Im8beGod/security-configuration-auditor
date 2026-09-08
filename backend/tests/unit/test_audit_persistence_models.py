from sqlalchemy import CheckConstraint, UniqueConstraint, inspect
from sqlalchemy.dialects.postgresql import JSONB

from app.db.base import Base
from app.db.models import (
    Artifact,
    ArtifactContentFamily,
    ArtifactEvidenceType,
    ArtifactStatus,
    Audit,
    AuditProcessingStage,
    AuditReevaluationReason,
    AuditStatus,
    Device,
    DeviceClass,
    DeviceIdentityStatus,
    Snapshot,
    SnapshotGroupingStatus,
    SnapshotSource,
    SnapshotStatus,
)


EXPECTED_TABLES = {
    "artifacts", "audits", "devices", "effective_states", "findings", "jobs", "organizations", "security_facts",
    "snapshots", "users", "remediation_procedures", "reports", "unresolved_blocks", "mapping_versions", "mapping_validation_runs", "knowledge_packs", "knowledge_pack_versions", "assessment_pack_versions", "assessment_obligations", "audit_assessments", "assessment_results", "profile_manifest_versions", "profile_resolution_decisions"
}


def enum_values(enum_type: type) -> list[str]:
    return [member.value for member in enum_type]


def check_names(model: type) -> set[str]:
    return {
        constraint.name
        for constraint in model.__table__.constraints
        if isinstance(constraint, CheckConstraint)
    }


def test_metadata_contains_only_frozen_step_3_6_tables() -> None:
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_artifact_contract_metadata() -> None:
    table = Artifact.__table__
    columns = table.c

    assert table.name == "artifacts"
    assert columns.artifact_id.primary_key is True
    assert columns.snapshot_id.nullable is True
    assert columns.sha256.type.length == 64
    assert columns.sha256.index is True
    assert columns.snapshot_id.index is True
    assert columns.schema_version.nullable is False
    assert "ck_artifacts_byte_size" in check_names(Artifact)
    assert "ck_artifacts_sha256" in check_names(Artifact)
    assert not ({"raw_bytes", "bytes", "blob", "content"} & set(columns.keys()))
    assert columns.content_family.type.enums == enum_values(ArtifactContentFamily)
    assert columns.evidence_type.type.enums == enum_values(ArtifactEvidenceType)
    assert columns.status.type.enums == enum_values(ArtifactStatus)


def test_device_contract_excludes_historical_configuration_truth() -> None:
    columns = Device.__table__.c
    forbidden = {
        "vendor", "os", "os_version", "firmware_version", "resolved_profile",
        "active_config", "model_detection_result",
    }

    assert Device.__table__.name == "devices"
    assert not (forbidden & set(columns.keys()))
    assert columns.device_class.type.enums == enum_values(DeviceClass)
    assert columns.identity_status.type.enums == enum_values(DeviceIdentityStatus)
    assert columns.schema_version.nullable is False


def test_snapshot_contract_and_relationships() -> None:
    table = Snapshot.__table__
    device_fk = next(iter(table.c.device_id.foreign_keys))

    assert device_fk.target_fullname == "devices.device_id"
    assert table.c.captured_at.nullable is True
    assert table.c.artifact_count.nullable is False
    assert "ck_snapshots_artifact_count" in check_names(Snapshot)
    assert table.c.status.type.enums == enum_values(SnapshotStatus)
    assert table.c.grouping_status.type.enums == enum_values(SnapshotGroupingStatus)
    assert table.c.source.type.enums == enum_values(SnapshotSource)
    assert inspect(Snapshot).relationships.artifacts.back_populates == "snapshot"
    assert table.c.schema_version.nullable is False


def test_audit_contract_metadata() -> None:
    table = Audit.__table__
    unique_columns = {
        tuple(constraint.columns.keys())
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    json_columns = {
        "selected_frameworks", "version_refs", "profile_resolution",
        "verdict_counts", "severity_counts", "coverage",
    }

    assert next(iter(table.c.snapshot_id.foreign_keys)).target_fullname == "snapshots.snapshot_id"
    assert next(iter(table.c.device_id.foreign_keys)).target_fullname == "devices.device_id"
    assert ("snapshot_id", "revision_number") in unique_columns
    assert "ck_audits_revision_number" in check_names(Audit)
    assert table.c.previous_audit_id.nullable is True
    assert next(iter(table.c.previous_audit_id.foreign_keys)).target_fullname == "audits.audit_id"
    assert table.c.status.type.enums == enum_values(AuditStatus)
    assert table.c.processing_stage.type.enums == enum_values(AuditProcessingStage)
    assert table.c.reevaluation_reason.type.enums == enum_values(AuditReevaluationReason)
    assert all(isinstance(table.c[name].type, JSONB) for name in json_columns)
    assert table.c.schema_version.nullable is False


def test_history_relationships_do_not_delete_orphans() -> None:
    relationships = [
        inspect(Device).relationships.snapshots,
        inspect(Device).relationships.audits,
        inspect(Snapshot).relationships.artifacts,
        inspect(Snapshot).relationships.audits,
    ]

    assert Artifact.__table__.c.snapshot_id.nullable is True
    assert Audit.__table__.c.snapshot_id.nullable is False
    for relationship in relationships:
        assert "delete" not in relationship.cascade
        assert "delete-orphan" not in relationship.cascade
