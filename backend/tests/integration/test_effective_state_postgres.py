"""Opt-in PostgreSQL coverage for canonical EffectiveState persistence."""

import os
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select, text

from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Audit,
    AuditReevaluationReason,
    AuditStatus,
    Device,
    EffectiveState,
    FactState,
    FactValidationStatus,
    InterpretationConfidence,
    InterpretationMethod,
    Organization,
    SecurityFact,
    Snapshot,
    SnapshotGroupingStatus,
    SnapshotSource,
    SnapshotStatus,
    User,
)
from app.db.session import create_session_factory
from app.effective_state import ResolutionStatus, make_effective_state_draft
from app.effective_state.service import persist_effective_state
from app.knowledge_packs.cisco_iosxe_17 import CISCO_IOS_XE_17_KNOWLEDGE_PACK
from app.profile_resolution import CISCO_IOS_XE_17
from app.security_model import ScopeRef, TypedValue, TypedValueType


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_STEP6_POSTGRES_TEST") != "1",
    reason="Set SIH_STEP6_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def test_effective_state_persistence_is_unique_and_retains_fact_provenance():
    settings = get_settings()
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    organization_id = None
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260907_0010"

        suffix = uuid4().hex
        organization_id, user_id = bootstrap_admin(
            factory, "Step 6 State", f"step6-{suffix}",
            f"step6-{suffix}@example.invalid", "test-only-password",
        )
        mapping = next(
            item for item in CISCO_IOS_XE_17_KNOWLEDGE_PACK.mappings
            if item.field_id == "management.remote.ssh.enabled"
        )
        with factory.begin() as db:
            device = Device(organization_id=organization_id, display_name="State Device")
            db.add(device)
            db.flush()
            snapshot = Snapshot(
                device_id=device.device_id,
                organization_id=organization_id,
                grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
                snapshot_hash="a" * 64,
                artifact_count=0,
                source=SnapshotSource.UPLOAD,
                status=SnapshotStatus.LOCKED,
                created_by=user_id,
            )
            db.add(snapshot)
            db.flush()
            audit = Audit(
                organization_id=organization_id,
                device_id=device.device_id,
                snapshot_id=snapshot.snapshot_id,
                revision_number=1,
                reevaluation_reason=AuditReevaluationReason.INITIAL,
                status=AuditStatus.PROCESSING,
                selected_frameworks=[],
                version_refs={
                    "device_profile_version_id": CISCO_IOS_XE_17.profile_version_id,
                    "knowledge_pack_version_id": str(CISCO_IOS_XE_17_KNOWLEDGE_PACK.knowledge_pack_version_id),
                },
                profile_resolution={
                    "profile_id": CISCO_IOS_XE_17.profile_id,
                    "profile_version_id": CISCO_IOS_XE_17.profile_version_id,
                    "resolution_status": "resolved",
                },
                verdict_counts={}, severity_counts={}, coverage={}, created_by=user_id,
            )
            db.add(audit)
            db.flush()
            fact = SecurityFact(
                fact_id=uuid4(), audit_id=audit.audit_id, device_id=device.device_id,
                snapshot_id=snapshot.snapshot_id, field_id=mapping.field_id,
                value=TypedValue(TypedValueType.BOOLEAN, True).to_dict(), entity=None,
                scope=ScopeRef("vty_range", "vty:0-4", {"start": 0, "end": 4}).to_dict(),
                state=FactState.EXPLICIT, evidence_refs=[], source_ir_node_ids=["node-1"],
                extraction_method=InterpretationMethod.DECLARATIVE_MAPPING,
                mapping_id=mapping.mapping_id, mapping_version_id=mapping.mapping_version_id,
                knowledge_pack_version_id=CISCO_IOS_XE_17_KNOWLEDGE_PACK.knowledge_pack_version_id,
                validation_status=FactValidationStatus.VALIDATED, dependencies=[],
                interpretation_confidence=InterpretationConfidence.HIGH,
            )
            db.add(fact)
            db.flush()
            draft = make_effective_state_draft(
                audit_id=audit.audit_id, device_id=device.device_id, field_id=fact.field_id,
                scope=ScopeRef("vty_range", "vty:0-4", {"start": 0, "end": 4}),
                effective_value=TypedValue(TypedValueType.BOOLEAN, True),
                resolution_status=ResolutionStatus.RESOLVED, source_fact_ids=(fact.fact_id,),
            )
            first = persist_effective_state(db, organization_id=organization_id, draft=draft)
            db.flush()
            second = persist_effective_state(db, organization_id=organization_id, draft=draft)
            assert first.effective_state_id == second.effective_state_id == draft.effective_state_id
            assert second.source_fact_ids == [str(fact.fact_id)]
            assert db.scalar(select(func.count()).select_from(EffectiveState).where(
                EffectiveState.audit_id == audit.audit_id
            )) == 1
    finally:
        if organization_id is not None:
            with factory.begin() as db:
                audit_ids = select(Audit.audit_id).where(Audit.organization_id == organization_id)
                db.execute(delete(EffectiveState).where(EffectiveState.audit_id.in_(audit_ids)))
                db.execute(delete(SecurityFact).where(SecurityFact.audit_id.in_(audit_ids)))
                db.execute(delete(Audit).where(Audit.organization_id == organization_id))
                db.execute(delete(Snapshot).where(Snapshot.organization_id == organization_id))
                db.execute(delete(Device).where(Device.organization_id == organization_id))
                db.execute(delete(User).where(User.organization_id == organization_id))
                db.execute(delete(Organization).where(Organization.organization_id == organization_id))
        engine.dispose()
