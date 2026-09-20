"""Opt-in PostgreSQL proof for multi-framework selection and honest results."""

import os
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.assessment_packs.service import compatible_packs, pin_assessment, persist_assessment_results
from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    AssessmentObligation, AssessmentResult, Audit, AuditFrameworkAssessment,
    AuditReevaluationReason, AuditStatus, Device, Snapshot, SnapshotGroupingStatus,
    SnapshotSource, SnapshotStatus, User,
)


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_PHASE4_POSTGRES_TEST") != "1",
    reason="Set SIH_PHASE4_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def test_all_frameworks_pin_and_never_invent_pass_without_evidence():
    engine = create_database_engine(get_settings())
    connection = engine.connect()
    outer = connection.begin()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False)
    try:
        organization_id, user_id = bootstrap_admin(factory, "P4", f"p4-{uuid4().hex}", f"p4-{uuid4().hex}@example.invalid", "test-only-password")
        with factory.begin() as db:
            device = Device(organization_id=organization_id, display_name="P4 Cisco")
            db.add(device); db.flush()
            snapshot = Snapshot(organization_id=organization_id, device_id=device.device_id, status=SnapshotStatus.LOCKED, grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED, snapshot_hash="a" * 64, artifact_count=0, source=SnapshotSource.UPLOAD, created_by=user_id)
            db.add(snapshot); db.flush()
            audit = Audit(organization_id=organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id, revision_number=1, reevaluation_reason=AuditReevaluationReason.INITIAL, status=AuditStatus.PROCESSING, selected_frameworks=["cis", "nist", "disa", "iso"], version_refs={}, profile_resolution={"resolution_status": "resolved", "profile_version_id": "cisco.ios_xe.17@1.0.0"}, verdict_counts={}, severity_counts={}, coverage={}, created_by=user_id)
            db.add(audit); db.flush()
            pin_assessment(db, audit, "cisco.ios_xe.17@1.0.0")
            coverage = persist_assessment_results(db, audit_id=audit.audit_id, organization_id=organization_id, profile_version_id="cisco.ios_xe.17@1.0.0", findings=[])
            assert len(list(db.scalars(select(AuditFrameworkAssessment).where(AuditFrameworkAssessment.audit_id == audit.audit_id)))) == 4
            assert coverage["pass"] == 0 and coverage["unknown"] > 0
            assert len(coverage["assessment_packs"]) == 4
            rows = db.execute(select(AssessmentResult, AssessmentObligation).join(AssessmentObligation).where(AssessmentResult.audit_id == audit.audit_id)).all()
            assert rows and all(result.verdict in {None, "unknown"} for result, _obligation in rows)
            assert all(obligation.source_url.startswith("https://") and obligation.control_id for _result, obligation in rows)
            assert all(pack.family != "CIS Benchmark" for pack in compatible_packs(db, organization_id, "fortinet.fortios.7@1.0.0"))
    finally:
        outer.rollback(); connection.close(); engine.dispose()
