"""Opt-in persistent B5 Junos audit using published development XML evidence."""

import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text

from app.audit.pipeline import AuditPipelineCoordinator
from app.audit.schemas import AuditCreate
from app.audit.service import create_audit, resolve_audit_profile, start_audit
from app.assessment_packs.service import pin_assessment
from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Artifact, ArtifactContentFamily, ArtifactEvidenceType, Audit, AuditProcessingStage, Device, EffectiveState, Finding, Job, Organization,
    SecurityFact, Snapshot, UnresolvedBlock, User,
)
from app.db.session import create_session_factory
from app.ingestion.service import ingest_artifact
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.snapshots.schemas import SnapshotCreate
from app.snapshots.service import add_artifact, create_snapshot, finalize_snapshot


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_STEP13_POSTGRES_TEST") != "1",
    reason="Set SIH_STEP13_POSTGRES_TEST=1 with development PostgreSQL settings",
)


# This is the published B3/B5 development-shaped XML, not a held-out fixture.
JUNOS_XML = b"""<configuration><version>18.4R1-S2.4</version><system>
<services><ssh/></services><login><idle-timeout>15</idle-timeout></login>
<syslog><host><name>logs.example.invalid</name></host></syslog><ntp>
<server><name>time.example.invalid</name></server>
<server><name>198.51.100.10</name><routing-instance>blue</routing-instance></server>
</ntp></system></configuration>"""
JUNOS_VERSION = b"JUNOS Software Release [18.4R1-S2.4]\n"


def test_b5_junos_audit_persists_scoped_semantics_through_normal_workflow(tmp_path):
    settings = get_settings()
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    organization_id = None
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260908_0013"
        suffix = uuid4().hex
        organization_id, _ = bootstrap_admin(
            factory, "B5 Junos E2E", f"b5-junos-{suffix}",
            f"b5-junos-{suffix}@example.invalid", "test-only-password",
        )
        with factory() as db:
            user = db.scalar(select(User).where(User.organization_id == organization_id))
            device = Device(organization_id=organization_id, display_name="Junos development device")
            db.add(device)
            db.commit()
            db.refresh(device)
            version_artifact = ingest_artifact(db, storage, user, JUNOS_VERSION, "version.txt", "text/plain")
            xml_artifact = ingest_artifact(db, storage, user, JUNOS_XML, "development-junos.xml", "application/xml")
            assert xml_artifact.content_family is ArtifactContentFamily.XML
            assert xml_artifact.evidence_type is ArtifactEvidenceType.STRUCTURED_EXPORT
            snapshot = create_snapshot(db, user, device.device_id, SnapshotCreate(label="B5 Junos development"))
            add_artifact(db, user, snapshot.snapshot_id, version_artifact.artifact_id)
            add_artifact(db, user, snapshot.snapshot_id, xml_artifact.artifact_id)
            finalize_snapshot(db, user, snapshot.snapshot_id)
            audit = create_audit(db, user, AuditCreate(snapshot_id=snapshot.snapshot_id))
            audit, job = start_audit(db, user, audit.audit_id)
            audit_id, snapshot_id, job_id = audit.audit_id, snapshot.snapshot_id, job.job_id
            artifact_id = xml_artifact.artifact_id

        # Execute the real worker stages through durable fact/state persistence.
        # Junos deliberately has no framework rule pack, and B5 acceptance ends
        # before that unrelated later stage.
        coordinator = AuditPipelineCoordinator(factory, storage)
        coordinator._begin_processing(audit_id, organization_id)
        with factory() as db:
            resolution = resolve_audit_profile(db, storage, audit_id, organization_id)
            audit = db.get(Audit, audit_id)
            pin_assessment(db, audit, resolution.selected_profile_version_id)
            db.commit()
        pack = coordinator._load_audit_pack(audit_id, organization_id, resolution.selected_profile_version_id)
        coordinator._pin_versions_and_set_stage(
            audit_id, organization_id, profile_version_id=resolution.selected_profile_version_id,
            knowledge_pack_version_id=pack.knowledge_pack_version_id, stage=AuditProcessingStage.PARSING,
        )
        with factory() as db:
            from app.interpretation import interpret_audit

            interpret_audit(
                db, storage, audit_id, organization_id,
                before_interpret=lambda: coordinator._pin_versions_and_set_stage(
                    audit_id, organization_id, profile_version_id=resolution.selected_profile_version_id,
                    knowledge_pack_version_id=pack.knowledge_pack_version_id,
                    stage=AuditProcessingStage.INTERPRETING,
                ), knowledge_pack=pack,
            )
        coordinator._pin_versions_and_set_stage(
            audit_id, organization_id, profile_version_id=resolution.selected_profile_version_id,
            knowledge_pack_version_id=pack.knowledge_pack_version_id, stage=AuditProcessingStage.RESOLVING_STATE,
        )
        with factory() as db:
            from app.effective_state.service import resolve_audit_effective_states

            resolve_audit_effective_states(db, audit_id=audit_id, organization_id=organization_id)
            db.commit()

        with factory() as db:
            persisted = db.get(Audit, audit_id)
            assert persisted is not None and persisted.processing_stage.value == "resolving_state"
            assert persisted.profile_resolution["profile_version_id"] == "juniper.junos.18@1.0.0"
            assert persisted.version_refs["knowledge_pack_version_id"] == "b3050000-0000-5000-8000-000000000018"
            facts = list(db.scalars(select(SecurityFact).where(SecurityFact.audit_id == audit_id)))
            by_field = {}
            for fact in facts:
                by_field.setdefault(fact.field_id, []).append(fact)
            assert "management.remote.ssh.enabled" in by_field
            assert by_field["management.remote.ssh.enabled"][0].value["value"] is True
            assert by_field["management.session.idle_timeout"][0].value["value"] == 900
            assert [item.value["value"] for item in by_field["logging.remote.destination"]] == ["logs.example.invalid"]
            assert [item.value["value"] for item in by_field["time.ntp.server"]] == ["time.example.invalid"]
            assert by_field["time.ntp.configured"][0].value["value"] is True
            assert all("198.51.100.10" not in str(item.value) for item in facts)
            assert all(str(artifact_id) == item.evidence_refs[0]["artifact_id"] for item in facts)
            states = list(db.scalars(select(EffectiveState).where(EffectiveState.audit_id == audit_id)))
            assert {item.field_id for item in states} >= set(by_field)
            assert all(item.scope["type"] == "device" for item in states)
            assert db.scalar(select(UnresolvedBlock).where(UnresolvedBlock.audit_id == audit_id)) is not None
            if os.environ.get("SIH_B5_ACCEPTANCE_REPORT") == "1":
                print(
                    "B5_JUNOS_PERSISTED_IDS "
                    f"artifact={artifact_id} snapshot={snapshot_id} audit={audit_id} job={job_id}"
                )
    finally:
        if organization_id is not None:
            with factory.begin() as db:
                audit_ids = select(Audit.audit_id).where(Audit.organization_id == organization_id)
                db.execute(delete(Finding).where(Finding.audit_id.in_(audit_ids)))
                db.execute(delete(EffectiveState).where(EffectiveState.audit_id.in_(audit_ids)))
                db.execute(delete(UnresolvedBlock).where(UnresolvedBlock.audit_id.in_(audit_ids)))
                db.execute(delete(SecurityFact).where(SecurityFact.audit_id.in_(audit_ids)))
                db.execute(delete(Job).where(Job.audit_id.in_(audit_ids)))
                db.execute(delete(Audit).where(Audit.organization_id == organization_id))
                db.execute(delete(Artifact).where(Artifact.organization_id == organization_id))
                db.execute(delete(Snapshot).where(Snapshot.organization_id == organization_id))
                db.execute(delete(Device).where(Device.organization_id == organization_id))
                db.execute(delete(User).where(User.organization_id == organization_id))
                db.execute(delete(Organization).where(Organization.organization_id == organization_id))
        engine.dispose()
