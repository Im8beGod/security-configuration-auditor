import os
from hashlib import sha256
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from app.cli.bootstrap_admin import bootstrap_admin
from app.compliance.verdicts import FindingSeverity, FindingVerdict
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Audit, AuditReevaluationReason, AuditStatus, Device, Finding, KnowledgePackVersionRecord, MappingStatus, MappingVersion,
    Organization, Snapshot, SnapshotGroupingStatus, SnapshotSource, SnapshotStatus,
    UnresolvedBlock, UnresolvedReviewStatus, User, UserRole,
)
from app.training.dsl import MappingDefinition
from app.training.service import (
    TrainingError, TrainingNotFound, approve_mapping, create_mapping,
    execute_validation, get_mapping, impact_analysis, publish_mapping,
    reject_mapping, request_validation, update_review_status,
    update_mapping,
)


pytestmark = pytest.mark.skipif(os.environ.get("SIH_TRAINING_POSTGRES_TEST") != "1", reason="Set SIH_TRAINING_POSTGRES_TEST=1 with development PostgreSQL settings")


def _definition():
    base = {"command": "exec-timeout", "arguments": ["5", "0"], "parent_command": "line", "scope_type": "vty_range"}
    variants = {
        "positive": (base, True, 300.0),
        "alternate_values": ({**base, "arguments": ["10", "30"]}, True, 630.0),
        "negative": ({**base, "command": "hostname"}, False, None),
        "wrong_scope": ({**base, "parent_command": "interface"}, False, None),
        "negation": ({**base, "negated": True}, True, 300.0),
        "conflict": (base, True, 300.0),
        "regression": ({**base, "command": "login"}, False, None),
    }
    return MappingDefinition.model_validate({
        "profile_applicability": {"profile_version_ids": ["cisco.ios_xe.17@1.0.0"]},
        "structural_match": {"command": "exec-timeout", "parent_command": "line", "scope_type": "vty_range", "arguments": [{"operation": "capture", "name": "minutes", "value_type": "integer"}, {"operation": "capture", "name": "seconds", "value_type": "integer"}]},
        "target_field_id": "management.session.idle_timeout",
        "value_extraction": {"operation": "duration_from_parts", "parts": ["minutes", "seconds"], "output_type": "duration"},
        "scope_resolution": {"strategy": "vty_range"},
        "negation_behavior": {"operation": "reset_to_default"},
        "removal_behavior": {"operation": "remove_value"},
        "default_behavior": {"operation": "unknown"},
        "examples": [{"family": family, "node": node, "expected_match": matched, "expected_value": value} for family, (node, matched, value) in variants.items()],
    })


def test_learning_lifecycle_is_tenant_scoped_immutable_and_never_revises_audits():
    engine = create_database_engine(get_settings())
    connection = engine.connect(); outer = connection.begin()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint", autoflush=False, autocommit=False, expire_on_commit=False)
    suffix = uuid4().hex
    try:
        organization_id, admin_id = bootstrap_admin(factory, "Training", f"training-{suffix}", f"admin-{suffix}@example.invalid", "test-only-password")
        other_organization_id, other_id = bootstrap_admin(factory, "Other", f"other-{suffix}", f"other-{suffix}@example.invalid", "test-only-password")
        with factory.begin() as db:
            admin = db.get(User, admin_id)
            device = Device(organization_id=organization_id, display_name="Learning router")
            db.add(device); db.flush()
            snapshot = Snapshot(organization_id=organization_id, device_id=device.device_id, label="learning", grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED, snapshot_hash=sha256(suffix.encode()).hexdigest(), artifact_count=0, source=SnapshotSource.UPLOAD, status=SnapshotStatus.LOCKED, created_by=admin_id)
            db.add(snapshot); db.flush()
            audit = Audit(organization_id=organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id, revision_number=1, reevaluation_reason=AuditReevaluationReason.INITIAL, status=AuditStatus.COMPLETED_WITH_UNKNOWNS, selected_frameworks=[], version_refs={"knowledge_pack_version_id": "sealed-pack", "device_profile_version_id": "cisco.ios_xe.17@1.0.0"}, profile_resolution={"profile_version_id": "cisco.ios_xe.17@1.0.0"}, verdict_counts={"unknown": 1}, severity_counts={}, coverage={}, created_by=admin_id)
            db.add(audit); db.flush()
            block = UnresolvedBlock(organization_id=organization_id, audit_id=audit.audit_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id, profile_id="cisco.ios_xe.17", profile_version_id="cisco.ios_xe.17@1.0.0", source_ir_node_ids=["node-1"], evidence_refs=[{"artifact_id": str(uuid4()), "start_line": 2, "end_line": 2}], raw_text="exec-timeout 5 0", surrounding_context="line vty 0 4\n exec-timeout 5 0", unknown_reason="unmapped_syntax", candidate_field_ids=["management.session.idle_timeout"], affected_rule_ids=["rule.unknown"], fingerprint=sha256(f"{audit.audit_id}:node-1".encode()).hexdigest(), occurrence={"command": "exec-timeout", "arguments": ["5", "0"], "parent_command": "line", "scope_type": "vty_range"})
            db.add(block)
            finding = Finding(finding_id=uuid4(), audit_id=audit.audit_id, device_id=device.device_id, comparison_key="unknown", rule_id="rule.unknown", rule_pack_version_id=uuid4(), title="Unknown", security_domain="management", verdict=FindingVerdict.UNKNOWN, severity=FindingSeverity.MEDIUM, expected_state={}, observed_state=None, explanation="Persisted unknown", affected_scope=None, effective_state_refs=[], evidence_refs=[], unknown_reason="missing_evidence", framework_references=[], remediation_procedure_id=None)
            db.add(finding)
            audit_id, original_refs = audit.audit_id, dict(audit.version_refs)
            finding_id, original_finding = finding.finding_id, (finding.verdict, finding.explanation, finding.unknown_reason)

        with factory() as db:
            admin = db.get(User, admin_id)
            block_id = db.scalar(select(UnresolvedBlock.unresolved_block_id).where(UnresolvedBlock.audit_id == audit_id))
            assert update_review_status(db, admin, block_id, UnresolvedReviewStatus.UNDER_REVIEW).review_status == UnresolvedReviewStatus.UNDER_REVIEW
            mapping = create_mapping(db, admin, mapping_key="iosxe.exec-timeout", title="VTY timeout", description="Maps bounded timeout syntax", definition=_definition(), unresolved_block_id=block_id)
            with pytest.raises(TrainingError):
                publish_mapping(db, admin, mapping.mapping_version_id)
            run, _job = request_validation(db, admin, mapping.mapping_version_id)
        with factory.begin() as db:
            completed = execute_validation(db, run.validation_run_id, mapping.mapping_version_id, organization_id)
            assert completed.results["passed"] is True
        with factory() as db:
            admin = db.get(User, admin_id)
            analyst = User(organization_id=organization_id, email=f"analyst-{suffix}@example.invalid", password_hash="test-hash", role=UserRole.ANALYST)
            db.add(analyst); db.commit()
            with pytest.raises(TrainingError):
                approve_mapping(db, analyst, mapping.mapping_version_id)
            with pytest.raises(TrainingError):
                publish_mapping(db, analyst, mapping.mapping_version_id)
            with pytest.raises(TrainingError):
                publish_mapping(db, admin, mapping.mapping_version_id)
            approved = approve_mapping(db, admin, mapping.mapping_version_id)
            assert approved.status == MappingStatus.APPROVED and approved.approved_by == admin_id
            published, pack_v1 = publish_mapping(db, admin, mapping.mapping_version_id)
            assert published.status == MappingStatus.PUBLISHED
            with pytest.raises(TrainingError):
                update_mapping(db, admin, published.mapping_version_id, title="mutated", description="mutated", definition=_definition())
            assert db.get(UnresolvedBlock, block_id).review_status.value == "mapped"
            draft_v2 = create_mapping(db, admin, mapping_key=published.mapping_key, title="VTY timeout v2", description="New immutable version", definition=_definition(), previous_mapping_version_id=published.mapping_version_id)
            assert draft_v2.mapping_id == published.mapping_id and draft_v2.version == 2
            run_v2, _job_v2 = request_validation(db, admin, draft_v2.mapping_version_id)
            execute_validation(db, run_v2.validation_run_id, draft_v2.mapping_version_id, organization_id); db.commit()
            approve_mapping(db, admin, draft_v2.mapping_version_id)
            published_v2, pack_v2 = publish_mapping(db, admin, draft_v2.mapping_version_id)
            assert published_v2.status == MappingStatus.PUBLISHED
            assert get_mapping(db, admin, published.mapping_version_id).status == MappingStatus.SUPERSEDED
            assert pack_v2.previous_knowledge_pack_version_id == pack_v1.knowledge_pack_version_id
            assert pack_v1.mapping_version_ids == [str(published.mapping_version_id)]
            for statement in (
                update(MappingVersion).where(MappingVersion.mapping_version_id == published.mapping_version_id).values(title="forbidden"),
                delete(MappingVersion).where(MappingVersion.mapping_version_id == published.mapping_version_id),
                update(KnowledgePackVersionRecord).where(KnowledgePackVersionRecord.knowledge_pack_version_id == pack_v1.knowledge_pack_version_id).values(mapping_version_ids=[]),
                delete(KnowledgePackVersionRecord).where(KnowledgePackVersionRecord.knowledge_pack_version_id == pack_v1.knowledge_pack_version_id),
            ):
                with pytest.raises(DBAPIError), db.begin_nested():
                    db.execute(statement)
            failed_payload = _definition().model_dump(mode="json")
            failed_payload["examples"][0]["expected_value"] = 999
            failed_mapping = create_mapping(db, admin, mapping_key="iosxe.failed-validation", title="Failed candidate", description="Must remain untrusted", definition=MappingDefinition.model_validate(failed_payload))
            failed_run, _failed_job = request_validation(db, admin, failed_mapping.mapping_version_id)
            assert execute_validation(db, failed_run.validation_run_id, failed_mapping.mapping_version_id, organization_id).status.value == "failed"
            db.commit()
            with pytest.raises(TrainingError):
                approve_mapping(db, admin, failed_mapping.mapping_version_id)
            with pytest.raises(TrainingError):
                publish_mapping(db, admin, failed_mapping.mapping_version_id)
            assert reject_mapping(db, admin, failed_mapping.mapping_version_id).status == MappingStatus.REJECTED
            impact = impact_analysis(db, admin, published.mapping_version_id)
            assert impact["potentially_affected_unknown_findings"] == 1
            assert impact["creates_audit_revision"] is False
            assert db.scalar(select(func.count(Audit.audit_id)).where(Audit.snapshot_id == db.get(Audit, audit_id).snapshot_id)) == 1
            assert db.get(Audit, audit_id).version_refs == original_refs
            persisted_finding = db.get(Finding, finding_id)
            assert (persisted_finding.verdict, persisted_finding.explanation, persisted_finding.unknown_reason) == original_finding
            foreign = db.get(User, other_id)
            with pytest.raises(TrainingNotFound):
                get_mapping(db, foreign, published.mapping_version_id)
            assert pack_v1.mapping_version_ids == [str(published.mapping_version_id)]
    finally:
        outer.rollback(); connection.close(); engine.dispose()
