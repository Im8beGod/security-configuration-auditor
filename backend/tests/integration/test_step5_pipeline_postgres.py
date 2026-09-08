"""Opt-in end-to-end verification for the complete Step-5 domain pipeline."""

import os
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, func, select, text

from app.audit.errors import AuditConflictError, AuditNotFoundError
from app.audit.pipeline import AuditPipelineCoordinator
from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.base import Base
from app.db.engine import create_database_engine
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
    EffectiveState,
    Finding,
    Job,
    JobStatus,
    JobType,
    Organization,
    SecurityFact,
    Snapshot,
    SnapshotGroupingStatus,
    SnapshotSource,
    SnapshotStatus,
    User,
    UnresolvedBlock,
)
from app.db.session import create_session_factory
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.jobs.errors import JobError
from app.jobs.handlers import (
    AuditJobHandler,
    handle_mapping_validation,
    handle_pdf_generation,
    handle_reevaluation,
    handle_system_noop,
)
from app.jobs.runner import PRODUCTION_HANDLERS
from app.jobs.service import enqueue_job
from app.knowledge_packs.cisco_iosxe_17 import CISCO_IOS_XE_17_KNOWLEDGE_PACK
from app.profile_resolution import CISCO_IOS_XE_17, ResolutionStatus
from app.snapshots.service import calculate_snapshot_hash


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_STEP5_POSTGRES_TEST") != "1",
    reason="Set SIH_STEP5_POSTGRES_TEST=1 with development PostgreSQL settings",
)

SEMANTIC_CONFIG = (
    Path(__file__).parents[1] / "fixtures" / "cisco_ios_xe" / "semantic.cfg"
).read_bytes()


def test_complete_step5_pipeline_is_bounded_versioned_and_idempotent(
    tmp_path, monkeypatch
):
    settings = get_settings()
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    organization_ids = []
    unrelated_job_id = None
    invalid_job_id = None

    try:
        with engine.connect() as connection:
            assert connection.scalar(
                text("SELECT version_num FROM alembic_version")
            ) == "20260909_0015"

        suffix = uuid4().hex
        organization_id, user_id = bootstrap_admin(
            factory,
            "Step 5 Pipeline",
            f"step5-{suffix}",
            f"step5-{suffix}@example.invalid",
            "test-only-password",
        )
        foreign_organization_id, foreign_user_id = bootstrap_admin(
            factory,
            "Step 5 Foreign",
            f"step5-foreign-{suffix}",
            f"step5-foreign-{suffix}@example.invalid",
            "test-only-password",
        )
        organization_ids.extend([organization_id, foreign_organization_id])

        with factory.begin() as db:
            device = Device(
                organization_id=organization_id, display_name="Supported Edge"
            )
            unsupported_device = Device(
                organization_id=organization_id, display_name="Unsupported Edge"
            )
            non_cisco_device = Device(
                organization_id=organization_id, display_name="Non-Cisco Edge"
            )
            conflict_device = Device(
                organization_id=organization_id, display_name="Conflicting Edge"
            )
            db.add_all([
                device, unsupported_device, non_cisco_device, conflict_device
            ])
            db.flush()

            supported_snapshot, supported_artifacts = _snapshot(
                db,
                storage,
                organization_id,
                device.device_id,
                user_id,
                (
                    (
                        "show-version.txt",
                        ArtifactEvidenceType.VERSION_OUTPUT,
                        b"Cisco IOS XE Software, Version 17.9.4a\n"
                        b"cisco C9300-48P (X86) processor with memory\n",
                    ),
                    (
                        "show-inventory.txt",
                        ArtifactEvidenceType.INVENTORY_OUTPUT,
                        b'NAME: "Chassis", DESCR: "Cisco Catalyst 9300"\n'
                        b"PID: C9300-48P, VID: V02, SN: FCW00000001\n",
                    ),
                    (
                        "running-config.txt",
                        ArtifactEvidenceType.CONFIGURATION,
                        SEMANTIC_CONFIG,
                    ),
                ),
            )
            unsupported_snapshot, _ = _snapshot(
                db,
                storage,
                organization_id,
                unsupported_device.device_id,
                user_id,
                (
                    (
                        "show-version-16.txt",
                        ArtifactEvidenceType.VERSION_OUTPUT,
                        b"Cisco IOS XE Software, Version 16.12.5\n",
                    ),
                    (
                        "running-config-16.txt",
                        ArtifactEvidenceType.CONFIGURATION,
                        SEMANTIC_CONFIG,
                    ),
                ),
            )
            non_cisco_snapshot, _ = _snapshot(
                db,
                storage,
                organization_id,
                non_cisco_device.device_id,
                user_id,
                (
                    (
                        "show-version-junos.txt",
                        ArtifactEvidenceType.VERSION_OUTPUT,
                        b"Junos: 23.4R1.9\n",
                    ),
                    (
                        "configuration.txt",
                        ArtifactEvidenceType.CONFIGURATION,
                        SEMANTIC_CONFIG,
                    ),
                ),
            )
            conflict_snapshot, _ = _snapshot(
                db,
                storage,
                organization_id,
                conflict_device.device_id,
                user_id,
                (
                    (
                        "show-version-xe.txt",
                        ArtifactEvidenceType.VERSION_OUTPUT,
                        b"Cisco IOS XE Software, Version 17.9.4a\n",
                    ),
                    (
                        "show-version-conflict.txt",
                        ArtifactEvidenceType.VERSION_OUTPUT,
                        b"Junos: 23.4R1.9\n",
                    ),
                    (
                        "running-config-conflict.txt",
                        ArtifactEvidenceType.CONFIGURATION,
                        SEMANTIC_CONFIG,
                    ),
                ),
            )

            audit = _audit(
                organization_id, device.device_id, supported_snapshot.snapshot_id,
                user_id,
            )
            unsupported_audit = _audit(
                organization_id,
                unsupported_device.device_id,
                unsupported_snapshot.snapshot_id,
                user_id,
            )
            non_cisco_audit = _audit(
                organization_id,
                non_cisco_device.device_id,
                non_cisco_snapshot.snapshot_id,
                user_id,
            )
            conflict_audit = _audit(
                organization_id,
                conflict_device.device_id,
                conflict_snapshot.snapshot_id,
                user_id,
            )
            db.add_all([audit, unsupported_audit, non_cisco_audit, conflict_audit])
            db.flush()
            audit_job = enqueue_job(
                db,
                JobType.AUDIT,
                audit_id=audit.audit_id,
                device_id=device.device_id,
            )
            unrelated_job = enqueue_job(
                db, JobType.AUDIT, payload={"unrelated": True}
            )
            audit_id = audit.audit_id
            unsupported_audit_id = unsupported_audit.audit_id
            non_cisco_audit_id = non_cisco_audit.audit_id
            conflict_audit_id = conflict_audit.audit_id
            audit_job_id = audit_job.job_id
            unrelated_job_id = unrelated_job.job_id
            supported_snapshot_id = supported_snapshot.snapshot_id
            config_artifact_id = next(
                item.artifact_id
                for item in supported_artifacts
                if item.evidence_type == ArtifactEvidenceType.CONFIGURATION
            )
            if os.environ.get("SIH_B5_ACCEPTANCE_REPORT") == "1":
                print(
                    "B5_CISCO_PERSISTED_IDS "
                    f"artifact={config_artifact_id} snapshot={supported_snapshot_id} "
                    f"audit={audit_id} job={audit_job_id}"
                )

        parsed_readers = []
        import app.interpretation.service as interpretation_service

        original_parse_artifact = interpretation_service.parse_artifact

        def track_reader(*args, **kwargs):
            ir = original_parse_artifact(*args, **kwargs)
            parsed_readers.append(ir.reader_id)
            return ir

        monkeypatch.setattr(interpretation_service, "parse_artifact", track_reader)
        coordinator = AuditPipelineCoordinator(factory, storage)

        with pytest.raises(AuditNotFoundError):
            coordinator.run(audit_id, foreign_organization_id)

        first = coordinator.run(audit_id, organization_id)
        assert first.profile_resolution.resolution_status == ResolutionStatus.RESOLVED
        assert first.stages == (
            AuditProcessingStage.IDENTIFYING,
            AuditProcessingStage.PARSING,
            AuditProcessingStage.INTERPRETING,
                AuditProcessingStage.RESOLVING_STATE,
                AuditProcessingStage.EVALUATING,
        )
        assert first.interpretation is not None
        assert first.effective_states is not None
        assert first.findings is not None
        assert parsed_readers == ["indentation_cli.v1"]
        first_fact_ids = {fact.fact_id for fact in first.interpretation.facts}
        first_effective_state_ids = {
            state.effective_state_id for state in first.effective_states
        }
        assert len(first_fact_ids) == 16
        # Two logging facts resolve into one canonical repeatable collection.
        assert len(first_effective_state_ids) == 15
        first_finding_ids = {finding.finding_id for finding in first.findings}
        assert len(first_finding_ids) == 11

        with factory() as db:
            persisted = db.get(Audit, audit_id)
            started_at = persisted.started_at
            assert persisted.status == AuditStatus.COMPLETED_WITH_UNKNOWNS
            assert persisted.processing_stage == AuditProcessingStage.FINALIZING
            assert started_at is not None and persisted.completed_at is not None
            assert persisted.version_refs["device_profile_version_id"] == CISCO_IOS_XE_17.profile_version_id
            assert persisted.version_refs["knowledge_pack_version_id"] == str(CISCO_IOS_XE_17_KNOWLEDGE_PACK.knowledge_pack_version_id)
            assert persisted.version_refs["rule_pack_versions"] == ["e3763b76-edcd-55b8-9825-b82933a3e2f9"]
            assert persisted.version_refs["organization_policy_version_id"]
            assert persisted.verdict_counts
            assert persisted.severity_counts
            assert persisted.coverage == {}
            assert db.get(Snapshot, supported_snapshot_id).status == SnapshotStatus.LOCKED

            facts = list(db.scalars(select(SecurityFact).where(
                SecurityFact.audit_id == audit_id
            )))
            assert {fact.fact_id for fact in facts} == first_fact_ids
            assert {fact.knowledge_pack_version_id for fact in facts} == {
                CISCO_IOS_XE_17_KNOWLEDGE_PACK.knowledge_pack_version_id
            }
            assert sorted(
                fact.value["value"]
                for fact in facts
                if fact.field_id == "management.session.idle_timeout"
            ) == [330, 600]
            assert {
                fact.scope["key"]
                for fact in facts
                if fact.field_id == "management.session.idle_timeout"
            } == {"vty:0-4", "vty:5-15"}
            assert all(
                ref["artifact_id"] == str(config_artifact_id)
                for fact in facts
                for ref in fact.evidence_refs
            )
            assert {
                ref["start_line"]
                for fact in facts
                for ref in fact.evidence_refs
            } >= {3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18}
            assert all(fact.source_ir_node_ids for fact in facts)
            assert all(
                "203.0.113.20" not in str(fact.value)
                for fact in facts
            )
            audit_job_status = db.get(Job, audit_job_id).status
            assert audit_job_status in {JobStatus.QUEUED, JobStatus.COMPLETED}
            states = list(db.scalars(select(EffectiveState).where(
                EffectiveState.audit_id == audit_id
            )))
            assert {state.effective_state_id for state in states} == first_effective_state_ids
            assert all(state.source_fact_ids for state in states)
            findings = list(db.scalars(select(Finding).where(Finding.audit_id == audit_id)))
            assert {finding.finding_id for finding in findings} == first_finding_ids
            assert {str(finding.rule_pack_version_id) for finding in findings} == {"e3763b76-edcd-55b8-9825-b82933a3e2f9"}
            assert all(finding.evidence_refs == [] and finding.remediation_procedure_id is None for finding in findings)
            unrelated = db.get(Job, unrelated_job_id)
            assert unrelated.status == JobStatus.QUEUED
            assert unrelated.attempt_count == 0

        if audit_job_status is JobStatus.QUEUED:
            assert AuditJobHandler(factory, storage)(audit_job_id) is None
        with factory() as db:
            retried = db.get(Audit, audit_id)
            assert retried.started_at == started_at
            assert db.scalar(select(func.count()).select_from(SecurityFact).where(
                SecurityFact.audit_id == audit_id
            )) == 16
            assert {fact.fact_id for fact in db.scalars(select(SecurityFact).where(
                SecurityFact.audit_id == audit_id
            ))} == first_fact_ids
            assert {state.effective_state_id for state in db.scalars(select(
                EffectiveState
            ).where(EffectiveState.audit_id == audit_id))} == first_effective_state_ids
            assert {finding.finding_id for finding in db.scalars(select(Finding).where(Finding.audit_id == audit_id))} == first_finding_ids
            assert retried.status == AuditStatus.COMPLETED_WITH_UNKNOWNS
            assert retried.processing_stage == AuditProcessingStage.FINALIZING
            assert retried.completed_at is not None

        for candidate_id, expected_status in (
            (unsupported_audit_id, ResolutionStatus.UNSUPPORTED),
            (non_cisco_audit_id, ResolutionStatus.UNSUPPORTED),
            (conflict_audit_id, ResolutionStatus.CONFLICT),
        ):
            outcome = coordinator.run(candidate_id, organization_id)
            assert outcome.profile_resolution.resolution_status == expected_status
            assert outcome.interpretation is None
            assert outcome.stages == (AuditProcessingStage.IDENTIFYING,)
            with factory() as db:
                candidate = db.get(Audit, candidate_id)
                assert candidate.status == AuditStatus.FAILED
                assert candidate.processing_stage == AuditProcessingStage.IDENTIFYING
                assert candidate.completed_at is not None
                assert candidate.version_refs == {}
                assert db.scalar(select(func.count()).select_from(SecurityFact).where(
                    SecurityFact.audit_id == candidate_id
                )) == 0
                assert db.scalar(select(func.count()).select_from(EffectiveState).where(
                    EffectiveState.audit_id == candidate_id
                )) == 0

        with factory.begin() as db:
            invalid_job = enqueue_job(
                db,
                JobType.AUDIT,
                payload={"password": "must-not-escape"},
            )
            invalid_job_id = invalid_job.job_id
        with pytest.raises(JobError) as error:
            AuditJobHandler(factory, storage)(invalid_job_id)
        assert str(error.value) == "Audit Job reference is invalid"

        assert handle_system_noop(uuid4()) is None
        assert PRODUCTION_HANDLERS == {
            JobType.SYSTEM_NOOP: handle_system_noop,
            JobType.PDF_GENERATION: handle_pdf_generation,
            JobType.MAPPING_VALIDATION: handle_mapping_validation,
            JobType.RE_EVALUATION: handle_reevaluation,
        }
        assert "effective_states" in Base.metadata.tables
        assert "findings" in Base.metadata.tables
    finally:
        if organization_ids:
            with factory.begin() as db:
                audit_ids = select(Audit.audit_id).where(
                    Audit.organization_id.in_(organization_ids)
                )
                db.execute(delete(Finding).where(Finding.audit_id.in_(audit_ids)))
                db.execute(delete(EffectiveState).where(
                    EffectiveState.audit_id.in_(audit_ids)
                ))
                db.execute(delete(UnresolvedBlock).where(UnresolvedBlock.audit_id.in_(audit_ids)))
                db.execute(delete(SecurityFact).where(
                    SecurityFact.audit_id.in_(audit_ids)
                ))
                db.execute(delete(Job).where(Job.audit_id.in_(audit_ids)))
                db.execute(delete(Audit).where(
                    Audit.organization_id.in_(organization_ids)
                ))
                db.execute(delete(Artifact).where(
                    Artifact.organization_id.in_(organization_ids)
                ))
                db.execute(delete(Snapshot).where(
                    Snapshot.organization_id.in_(organization_ids)
                ))
                db.execute(delete(Device).where(
                    Device.organization_id.in_(organization_ids)
                ))
                db.execute(delete(User).where(
                    User.organization_id.in_(organization_ids)
                ))
                db.execute(delete(Organization).where(
                    Organization.organization_id.in_(organization_ids)
                ))
                if unrelated_job_id is not None:
                    db.execute(delete(Job).where(Job.job_id == unrelated_job_id))
                if invalid_job_id is not None:
                    db.execute(delete(Job).where(Job.job_id == invalid_job_id))
        engine.dispose()


def test_step7_pipeline_preserves_unknown_conflict_and_missing_state(tmp_path):
    settings = get_settings()
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    storage = LocalFilesystemArtifactStorage(tmp_path / "step7-gate")
    organization_id = None
    try:
        organization_id, user_id = bootstrap_admin(
            factory, "Step 7 Gate", f"step7-gate-{uuid4().hex}",
            f"step7-gate-{uuid4().hex}@example.invalid", "test-only-password",
        )
        with factory.begin() as db:
            audits = []
            scenarios = (
                ("unknown", (("reset.cfg", ArtifactEvidenceType.CONFIGURATION, b"no ip ssh version\n"),)),
                ("conflict", (("ssh-one.cfg", ArtifactEvidenceType.CONFIGURATION, b"ip ssh version 1\n"), ("ssh-two.cfg", ArtifactEvidenceType.CONFIGURATION, b"ip ssh version 2\n"))),
                ("missing", (("partial.cfg", ArtifactEvidenceType.CONFIGURATION, b"ip ssh version 2\n"),)),
            )
            for name, configs in scenarios:
                device = Device(organization_id=organization_id, display_name=name)
                db.add(device)
                db.flush()
                evidence = (("version.txt", ArtifactEvidenceType.VERSION_OUTPUT, b"Cisco IOS XE Software, Version 17.9.4a\n"), *configs)
                snapshot, _ = _snapshot(db, storage, organization_id, device.device_id, user_id, evidence)
                audit = _audit(organization_id, device.device_id, snapshot.snapshot_id, user_id)
                db.add(audit)
                db.flush()
                audits.append((name, audit.audit_id))
        coordinator = AuditPipelineCoordinator(factory, storage)
        results = {name: coordinator.run(audit_id, organization_id) for name, audit_id in audits}
        with factory() as db:
            by_name = {name: db.get(Audit, audit_id) for name, audit_id in audits}
            for audit in by_name.values():
                assert audit.status is AuditStatus.COMPLETED_WITH_UNKNOWNS
                assert audit.processing_stage is AuditProcessingStage.FINALIZING
                assert audit.completed_at is not None
            unknown_audit = by_name["unknown"]
            unknown_state = db.scalar(select(EffectiveState).where(EffectiveState.audit_id == unknown_audit.audit_id, EffectiveState.field_id == "management.remote.ssh.version"))
            assert unknown_state.resolution_status.value == "unknown"
            assert unknown_state.unresolved_reason.value == "unresolved_default"
            unknown_finding = db.scalar(select(Finding).where(Finding.audit_id == unknown_audit.audit_id, Finding.rule_id == "management.ssh.version_2"))
            assert unknown_finding.verdict.value == "unknown"
            assert unknown_finding.unknown_reason == unknown_state.unresolved_reason
            assert unknown_finding.effective_state_refs == [str(unknown_state.effective_state_id)]
            conflict_audit = by_name["conflict"]
            conflict_state = db.scalar(select(EffectiveState).where(EffectiveState.audit_id == conflict_audit.audit_id, EffectiveState.field_id == "management.remote.ssh.version"))
            assert conflict_state.resolution_status.value == "conflicting"
            assert conflict_state.effective_value is None
            conflict_finding = db.scalar(select(Finding).where(Finding.audit_id == conflict_audit.audit_id, Finding.rule_id == "management.ssh.version_2"))
            assert conflict_finding.verdict.value == "unknown"
            assert conflict_finding.unknown_reason.value == "conflicting_evidence"
            assert conflict_finding.effective_state_refs == [str(conflict_state.effective_state_id)]
            missing_audit = by_name["missing"]
            assert db.scalar(select(EffectiveState).where(EffectiveState.audit_id == missing_audit.audit_id, EffectiveState.field_id == "logging.remote.destination")) is None
            missing_finding = db.scalar(select(Finding).where(Finding.audit_id == missing_audit.audit_id, Finding.rule_id == "logging.remote.destination.configured"))
            assert missing_finding.verdict.value == "unknown"
            assert missing_finding.unknown_reason.value == "missing_evidence"
            assert missing_finding.effective_state_refs == []
            first = {(item.finding_id, item.comparison_key, item.verdict, item.unknown_reason, tuple(item.effective_state_refs)) for item in db.scalars(select(Finding).where(Finding.audit_id == unknown_audit.audit_id))}
            started_at = unknown_audit.started_at
        with pytest.raises(AuditConflictError) as error:
            coordinator.run(by_name["unknown"].audit_id, organization_id)
        assert error.value.code == "audit_not_processable"
        with factory() as db:
            retried = db.get(Audit, by_name["unknown"].audit_id)
            second = {(item.finding_id, item.comparison_key, item.verdict, item.unknown_reason, tuple(item.effective_state_refs)) for item in db.scalars(select(Finding).where(Finding.audit_id == retried.audit_id))}
            assert second == first and retried.started_at == started_at
    finally:
        if organization_id is not None:
            with factory.begin() as db:
                ids = select(Audit.audit_id).where(Audit.organization_id == organization_id)
                db.execute(delete(Finding).where(Finding.audit_id.in_(ids)))
                db.execute(delete(EffectiveState).where(EffectiveState.audit_id.in_(ids)))
                db.execute(delete(UnresolvedBlock).where(UnresolvedBlock.audit_id.in_(ids)))
                db.execute(delete(SecurityFact).where(SecurityFact.audit_id.in_(ids)))
                db.execute(delete(Audit).where(Audit.organization_id == organization_id))
                db.execute(delete(Artifact).where(Artifact.organization_id == organization_id))
                db.execute(delete(Snapshot).where(Snapshot.organization_id == organization_id))
                db.execute(delete(Device).where(Device.organization_id == organization_id))
                db.execute(delete(User).where(User.organization_id == organization_id))
                db.execute(delete(Organization).where(Organization.organization_id == organization_id))
        engine.dispose()


def _snapshot(
    db,
    storage,
    organization_id,
    device_id,
    user_id,
    evidence,
):
    artifacts = []
    hashes = []
    for filename, evidence_type, content in evidence:
        artifact_id = uuid4()
        reference = storage.write(
            content, organization_id=organization_id, artifact_id=artifact_id
        )
        digest = sha256(content).hexdigest()
        hashes.append(digest)
        artifacts.append(Artifact(
            artifact_id=artifact_id,
            organization_id=organization_id,
            original_filename=filename,
            storage_reference=reference,
            byte_size=len(content),
            sha256=digest,
            encoding="utf-8",
            content_family=ArtifactContentFamily.TEXT,
            evidence_type=evidence_type,
            status=ArtifactStatus.READY,
            uploaded_by=user_id,
        ))
    snapshot = Snapshot(
        device_id=device_id,
        organization_id=organization_id,
        grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
        snapshot_hash=calculate_snapshot_hash(hashes),
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
    return snapshot, artifacts


def _audit(organization_id, device_id, snapshot_id, created_by):
    return Audit(
        organization_id=organization_id,
        device_id=device_id,
        snapshot_id=snapshot_id,
        revision_number=1,
        reevaluation_reason=AuditReevaluationReason.INITIAL,
        status=AuditStatus.QUEUED,
        processing_stage=None,
        selected_frameworks=[],
        version_refs={},
        profile_resolution={},
        verdict_counts={},
        severity_counts={},
        coverage={},
        created_by=created_by,
    )
