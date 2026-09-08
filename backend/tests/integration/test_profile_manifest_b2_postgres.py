"""Focused PostgreSQL proof for B2 manifest persistence and review decisions."""
import os
from uuid import uuid4

import pytest
from sqlalchemy import select, text

from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Audit, AuditReevaluationReason, AuditStatus, Device, Organization,
    ProfileManifestVersion, ProfileResolutionDecision, Snapshot,
    SnapshotGroupingStatus, SnapshotSource, SnapshotStatus, User, UserRole,
)
from app.db.session import create_session_factory

pytestmark = pytest.mark.skipif(os.environ.get("SIH_B2_POSTGRES_TEST") != "1", reason="Set SIH_B2_POSTGRES_TEST=1")


def test_manifest_migration_immutability_tenant_scope_and_review_decision():
    engine = create_database_engine(get_settings())
    factory = create_session_factory(engine)
    with factory.begin() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "20260909_0014"
        global_profile = db.scalar(select(ProfileManifestVersion).where(ProfileManifestVersion.profile_version_id == "cisco.ios_xe.17@1.0.0"))
        assert global_profile is not None and global_profile.organization_id is None
        with pytest.raises(Exception, match="immutable"):
            global_profile.status = "retired"
            db.flush()
        db.rollback()

    with factory.begin() as db:
        org = Organization(name="B2 Review", slug=f"b2-{uuid4().hex[:12]}")
        db.add(org); db.flush()
        user = User(organization_id=org.organization_id, email=f"b2-{uuid4().hex}@example.invalid", password_hash="test", role=UserRole.ADMIN)
        device = Device(organization_id=org.organization_id, display_name="B2 device")
        db.add_all([user, device]); db.flush()
        snapshot = Snapshot(device_id=device.device_id, organization_id=org.organization_id, status=SnapshotStatus.LOCKED, grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED, snapshot_hash="a" * 64, artifact_count=0, source=SnapshotSource.UPLOAD, created_by=user.user_id)
        db.add(snapshot); db.flush()
        audit = Audit(organization_id=org.organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id, revision_number=1, reevaluation_reason=AuditReevaluationReason.INITIAL, status=AuditStatus.FAILED, selected_frameworks=[], version_refs={}, profile_resolution={"resolution_status": "unsupported", "identity_provenance": {}}, verdict_counts={}, severity_counts={}, coverage={}, created_by=user.user_id)
        db.add(audit); db.flush()
        decision = ProfileResolutionDecision(organization_id=org.organization_id, snapshot_id=snapshot.snapshot_id, audit_id=audit.audit_id, resolution_status="unsupported", selected_profile_id=None, selected_profile_version_id=None, applicability_status="unsupported", identity_provenance={}, evidence_summary={"artifact_ids": []})
        db.add(decision); db.flush()
        assert db.get(ProfileResolutionDecision, decision.decision_id).resolution_status == "unsupported"
