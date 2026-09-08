"""Opt-in PostgreSQL proof for T2 fresh-audit published-pack reuse."""

import os
from copy import deepcopy
from datetime import timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import sessionmaker

from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Artifact,
    ArtifactContentFamily,
    ArtifactEvidenceType,
    ArtifactStatus,
    Audit,
    AuditReevaluationReason,
    AuditStatus,
    Device,
    KnowledgePackRecord,
    KnowledgePackVersionRecord,
    MappingOrigin,
    MappingStatus,
    MappingVersion,
    Snapshot,
    SnapshotGroupingStatus,
    SnapshotSource,
    SnapshotStatus,
    User,
)
from app.db.models.common import utc_now
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.interpretation.service import load_active_published_knowledge_pack
from app.jobs.handlers.audit import AuditJobHandler
from app.jobs.runner import WorkerRuntime
from app.jobs.service import enqueue_job
from app.jobs.enums import JobType
from app.snapshots.service import calculate_snapshot_hash
from app.training.dsl import MappingDefinition
from app.training.service import approve_mapping, create_mapping, execute_validation, publish_mapping, request_validation


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_T2_POSTGRES_TEST") != "1",
    reason="Set SIH_T2_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def _definition() -> MappingDefinition:
    examples = []
    for family, command, expected in (
        ("positive", "idle-timeout", True),
        ("alternate_values", "idle-timeout", True),
        ("negative", "hostname", False),
        ("wrong_scope", "idle-timeout", False),
        ("negation", "idle-timeout", True),
        ("conflict", "idle-timeout", True),
        ("regression", "login", False),
    ):
        examples.append({
            "family": family,
            "node": {
                "command": command,
                "arguments": ["5", "0"],
                "parent_command": "line" if family != "wrong_scope" else "interface",
                "scope_type": "vty_range",
                "negated": family == "negation",
            },
            "expected_match": expected,
            "expected_value": 300.0 if expected else None,
        })
    return MappingDefinition.model_validate({
        "profile_applicability": {"profile_version_ids": ["cisco.ios_xe.17@1.0.0"]},
        "structural_match": {
            "command": "idle-timeout",
            "parent_command": "line",
            "scope_type": "vty_range",
            "arguments": [
                {"operation": "capture", "name": "minutes", "value_type": "integer"},
                {"operation": "capture", "name": "seconds", "value_type": "integer"},
            ],
        },
        "target_field_id": "management.session.idle_timeout",
        "value_extraction": {"operation": "duration_from_parts", "parts": ["minutes", "seconds"], "output_type": "duration"},
        "scope_resolution": {"strategy": "vty_range"},
        "negation_behavior": {"operation": "reset_to_default"},
        "removal_behavior": {"operation": "remove_value"},
        "default_behavior": {"operation": "unknown"},
        "examples": examples,
    })


def _new_audit(factory, storage, organization_id, user_id, device_id, suffix):
    config = b"line vty 0 4\n idle-timeout 5 0\n"
    version = b"Cisco IOS XE Software, Version 17.9.4a\n"
    with factory.begin() as db:
        artifacts = []
        for name, evidence_type, content in (
            ("version.txt", ArtifactEvidenceType.VERSION_OUTPUT, version),
            ("running.cfg", ArtifactEvidenceType.CONFIGURATION, config),
        ):
            artifact_id = uuid4()
            reference = storage.write(content, organization_id=organization_id, artifact_id=artifact_id)
            artifacts.append(Artifact(
                artifact_id=artifact_id,
                organization_id=organization_id,
                original_filename=f"{suffix}-{name}",
                storage_reference=reference,
                byte_size=len(content),
                sha256=sha256(content).hexdigest(),
                encoding="utf-8",
                content_family=ArtifactContentFamily.TEXT,
                evidence_type=evidence_type,
                status=ArtifactStatus.READY,
                uploaded_by=user_id,
            ))
        snapshot = Snapshot(
            organization_id=organization_id,
            device_id=device_id,
            grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
            snapshot_hash=calculate_snapshot_hash([item.sha256 for item in artifacts]),
            artifact_count=len(artifacts),
            source=SnapshotSource.UPLOAD,
            status=SnapshotStatus.LOCKED,
            created_by=user_id,
        )
        db.add(snapshot)
        db.flush()
        for artifact in artifacts:
            artifact.snapshot_id = snapshot.snapshot_id
        db.add_all(artifacts)
        audit = Audit(
            organization_id=organization_id,
            device_id=device_id,
            snapshot_id=snapshot.snapshot_id,
            revision_number=1,
            reevaluation_reason=AuditReevaluationReason.INITIAL,
            status=AuditStatus.QUEUED,
            selected_frameworks=[],
            version_refs={},
            profile_resolution={},
            verdict_counts={},
            severity_counts={},
            coverage={},
            created_by=user_id,
        )
        db.add(audit)
        db.flush()
        job = enqueue_job(db, JobType.AUDIT, audit_id=audit.audit_id, device_id=device_id)
        return audit.audit_id, job.job_id


def test_fresh_audit_reuses_published_pack_after_worker_restart_and_filters_candidates(tmp_path):
    engine = create_database_engine(get_settings())
    connection = engine.connect()
    outer = connection.begin()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint", autoflush=False, expire_on_commit=False)
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    suffix = uuid4().hex
    organization_id = None
    other_organization_id = None
    try:
        organization_id, user_id = bootstrap_admin(factory, "T2", f"t2-{suffix}", f"t2-{suffix}@example.invalid", "test-only-password")
        other_organization_id, other_user_id = bootstrap_admin(factory, "T2 Other", f"t2-other-{suffix}", f"t2-other-{suffix}@example.invalid", "test-only-password")
        with factory.begin() as db:
            device = Device(organization_id=organization_id, display_name="T2 router")
            db.add(device)
            db.flush()
            device_id = device.device_id

        old_audit_id, old_job_id = _new_audit(factory, storage, organization_id, user_id, device_id, "old")
        first_runtime = WorkerRuntime(
            factory,
            handlers={JobType.AUDIT: AuditJobHandler(factory, storage)},
            poll_interval_seconds=get_settings().worker_poll_interval_seconds,
        )
        assert first_runtime.run_iteration() is True
        with factory() as db:
            old_audit = db.get(Audit, old_audit_id)
            assert old_audit.status == AuditStatus.COMPLETED_WITH_UNKNOWNS
            old_state = (
                deepcopy(old_audit.version_refs),
                deepcopy(old_audit.profile_resolution),
                deepcopy(old_audit.verdict_counts),
            )
            block = db.scalar(select(__import__("app.db.models", fromlist=["UnresolvedBlock"]).UnresolvedBlock).where(
                __import__("app.db.models", fromlist=["UnresolvedBlock"]).UnresolvedBlock.audit_id == old_audit_id
            ))
            admin = db.get(User, user_id)
            mapping = create_mapping(
                db,
                admin,
                mapping_key="t2.idle-timeout",
                title="T2 idle timeout",
                description="Approved T2 mapping",
                definition=_definition(),
                unresolved_block_id=block.unresolved_block_id,
            )
            validation, _ = request_validation(db, admin, mapping.mapping_version_id)
        with factory.begin() as db:
            execute_validation(db, validation.validation_run_id, mapping.mapping_version_id, organization_id)
        with factory() as db:
            admin = db.get(User, user_id)
            approve_mapping(db, admin, mapping.mapping_version_id)
            published, pack_version = publish_mapping(db, admin, mapping.mapping_version_id)
            published_id = published.mapping_version_id
            published_pack_id = pack_version.knowledge_pack_version_id

        with factory() as db:
            assert load_active_published_knowledge_pack(db, other_organization_id, "cisco.ios_xe.17@1.0.0") is None
            incompatible_mapping = MappingVersion(
                mapping_id=uuid4(),
                organization_id=organization_id,
                mapping_key="t2.incompatible",
                version=1,
                title="Incompatible",
                description="Incompatible profile candidate",
                status=MappingStatus.PUBLISHED,
                profile_applicability={"profile_version_ids": ["fortinet.fortios.7@1.0.0"]},
                structural_match=published.structural_match,
                target_field_id=published.target_field_id,
                value_extraction=published.value_extraction,
                unit_conversion=published.unit_conversion,
                scope_resolution=published.scope_resolution,
                negation_behavior=published.negation_behavior,
                removal_behavior=published.removal_behavior,
                default_behavior=published.default_behavior,
                examples=published.examples,
                validation_results=published.validation_results,
                origin=MappingOrigin.ADMINISTRATOR,
                created_by=user_id,
                approved_by=user_id,
                approved_at=utc_now(),
                published_at=utc_now(),
            )
            db.add(incompatible_mapping)
            db.flush()
            incompatible_pack = KnowledgePackRecord(
                organization_id=organization_id,
                pack_key=f"t2-incompatible-{suffix}",
                name="Incompatible pack",
            )
            db.add(incompatible_pack)
            db.flush()
            db.add(KnowledgePackVersionRecord(
                knowledge_pack_id=incompatible_pack.knowledge_pack_id,
                organization_id=organization_id,
                version=1,
                mapping_version_ids=[str(incompatible_mapping.mapping_version_id)],
                published_by=user_id,
                published_at=utc_now() + timedelta(seconds=2),
            ))
            db.flush()
            selected = load_active_published_knowledge_pack(
                db, organization_id, "cisco.ios_xe.17@1.0.0"
            )
            assert selected is not None
            assert selected.knowledge_pack_version_id == published_pack_id

        fresh_audit_id, fresh_job_id = _new_audit(factory, storage, organization_id, user_id, device_id, "fresh")
        second_runtime = WorkerRuntime(
            factory,
            handlers={JobType.AUDIT: AuditJobHandler(factory, storage)},
            poll_interval_seconds=get_settings().worker_poll_interval_seconds,
        )
        assert second_runtime.run_iteration() is True
        with factory() as db:
            fresh = db.get(Audit, fresh_audit_id)
            old = db.get(Audit, old_audit_id)
            assert fresh.status in {AuditStatus.COMPLETED, AuditStatus.COMPLETED_WITH_UNKNOWNS}
            assert fresh.version_refs["knowledge_pack_version_id"] == str(published_pack_id)
            assert fresh.version_refs["device_profile_version_id"] == "cisco.ios_xe.17@1.0.0"
            assert old.status == AuditStatus.COMPLETED_WITH_UNKNOWNS
            assert (old.version_refs, old.profile_resolution, old.verdict_counts) == old_state
            assert db.get(__import__("app.db.models", fromlist=["Job"]).Job, old_job_id).status.value == "completed"
            assert db.get(__import__("app.db.models", fromlist=["Job"]).Job, fresh_job_id).status.value == "completed"
            assert str(published_id) in [str(item.mapping_version_id) for item in db.scalars(select(__import__("app.db.models", fromlist=["SecurityFact"]).SecurityFact).where(__import__("app.db.models", fromlist=["SecurityFact"]).SecurityFact.audit_id == fresh_audit_id))]

            compatible_pack = KnowledgePackRecord(
                organization_id=organization_id,
                pack_key=f"t2-compatible-ambiguous-{suffix}",
                name="Ambiguous compatible pack",
            )
            db.add(compatible_pack)
            db.flush()
            db.add(KnowledgePackVersionRecord(
                knowledge_pack_id=compatible_pack.knowledge_pack_id,
                organization_id=organization_id,
                version=1,
                mapping_version_ids=[str(published_id)],
                published_by=user_id,
                published_at=utc_now() + timedelta(seconds=1),
            ))
            db.flush()
            assert load_active_published_knowledge_pack(
                db, organization_id, "cisco.ios_xe.17@1.0.0"
            ) is None
    finally:
        outer.rollback()
        connection.close()
        engine.dispose()
