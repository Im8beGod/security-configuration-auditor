"""Opt-in proof that a tenant can publish and immediately pin a custom pack."""

import json
import os
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.assessment_packs.catalog import CatalogImportError, parse_runtime_catalog, publish_runtime_catalog
from app.assessment_packs.service import compatible_packs, pin_assessment, persist_assessment_results
from app.compliance.verdicts import FindingSeverity, FindingVerdict
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    AssessmentResult, Audit, AuditReevaluationReason, AuditStatus, Device,
    EffectiveState, Finding, Organization, Snapshot, SnapshotGroupingStatus,
    SnapshotSource, SnapshotStatus, User, UserRole,
)
from app.db.session import create_session_factory
from app.effective_state.contracts import ResolutionStatus
from app.profile_resolution.runtime import parse_runtime_profile, profile_for, publish_runtime_profile


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_RUNTIME_PACK_POSTGRES_TEST") != "1",
    reason="Set SIH_RUNTIME_PACK_POSTGRES_TEST=1 with PostgreSQL available",
)


def _catalog():
    return json.dumps({
        "schema_version": "1.0.0", "pack_key": f"tenant.runtime.{uuid4().hex}",
        "family": "Customer Security Standard", "name": "Runtime pack", "version": 1,
        "source_version": "2026.1", "source_url": "https://standards.example.invalid/runtime.json",
        "profile_version_ids": ["cisco.ios_xe.17@1.0.0"], "obligations": [
            {"obligation_key": "CUSTOM-SSH-1", "control_id": "CUSTOM-SSH-1", "title": "SSH enabled",
             "severity": "high", "scope": "device", "assessment_method": "automatic",
             "implementation_status": "implemented", "evaluator_rule_id": "management.ssh.enabled",
             "policy_parameters": {}},
            {"obligation_key": "CUSTOM-MANUAL-1", "control_id": "CUSTOM-MANUAL-1", "title": "Manual review",
             "severity": "not_assigned", "scope": "organization", "assessment_method": "manual",
             "implementation_status": "manual"},
        ],
    }).encode()


def _runtime_profile(profile_id):
    return {
        "schema_version": "1.0.0", "profile_id": profile_id,
        "profile_version": "1.0.0", "profile_version_id": f"{profile_id}@1.0.0",
        "vendor": "Fictitious", "product_family": "Edge", "os": "NetOS",
        "structural_reader": "indentation_cli.v1", "evidence_types": ["configuration"],
        "device_classes": ["router"], "detection": {"tokens": ["Fictitious", "NetOS"]},
        "version_constraints": {"supported_major_versions": [1]},
        "capabilities": ["structural_parsing", "semantic_interpretation", "effective_state_resolution", "administrator_training"],
    }


def _runtime_profile_catalog(profile_version_id):
    return json.dumps({
        "schema_version": "1.0.0", "pack_key": f"tenant.runtime.{uuid4().hex}",
        "family": "Customer Security Standard", "name": "Runtime profile pack", "version": 1,
        "source_version": "2026.1", "source_url": "https://standards.example.invalid/runtime-profile.json",
        "profile_version_ids": [profile_version_id], "obligations": [{
            "obligation_key": "CUSTOM-MANUAL-1", "control_id": "CUSTOM-MANUAL-1",
            "title": "Review runtime profile", "severity": "not_assigned", "scope": "organization",
            "assessment_method": "manual", "implementation_status": "manual",
        }],
    }).encode()


def test_runtime_published_pack_is_pinned_and_evaluated_from_a_fresh_session():
    engine = create_database_engine(get_settings())
    connection = engine.connect()
    outer = connection.begin()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False)
    catalog = parse_runtime_catalog(_catalog(), "runtime-pack.json")
    try:
        with factory.begin() as db:
            organization = Organization(name="Runtime pack org", slug=f"runtime-pack-{uuid4().hex[:12]}")
            db.add(organization)
            db.flush()
            organization_id = organization.organization_id
            pack = publish_runtime_catalog(db, organization_id, catalog, "runtime-pack.json")
            pack_id = pack.assessment_pack_version_id
            with pytest.raises(CatalogImportError, match="already published"):
                publish_runtime_catalog(db, organization_id, catalog, "runtime-pack.json")

        # A new session is the process/redeployment boundary: only immutable DB state is used.
        with factory.begin() as db:
            user = User(organization_id=organization_id, email=f"runtime-{uuid4().hex}@example.invalid", password_hash="test-only", role=UserRole.ADMIN)
            device = Device(organization_id=organization_id, display_name="runtime device")
            db.add_all([user, device])
            db.flush()
            snapshot = Snapshot(device_id=device.device_id, organization_id=organization_id, status=SnapshotStatus.LOCKED,
                                grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED, snapshot_hash="d" * 64,
                                artifact_count=0, source=SnapshotSource.UPLOAD, created_by=user.user_id)
            db.add(snapshot)
            db.flush()
            audit = Audit(organization_id=organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id,
                          revision_number=1, reevaluation_reason=AuditReevaluationReason.INITIAL, status=AuditStatus.PROCESSING,
                          selected_frameworks=[], version_refs={"assessment_pack_version_id": str(pack_id)},
                          profile_resolution={"profile_version_id": "cisco.ios_xe.17@1.0.0"}, verdict_counts={}, severity_counts={}, coverage={}, created_by=user.user_id)
            db.add(audit)
            db.flush()
            state = EffectiveState(effective_state_id=uuid4(), audit_id=audit.audit_id, device_id=device.device_id,
                                   field_id="management.remote.ssh.enabled", scope={"type": "device", "key": str(device.device_id)},
                                   scope_key=f"device::{device.device_id}", effective_value={"type": "boolean", "value": True},
                                   resolution_status=ResolutionStatus.RESOLVED, source_fact_ids=[], resolution_trace=[], referenced_objects=[], precedence_applied=[])
            finding = Finding(finding_id=uuid4(), audit_id=audit.audit_id, device_id=device.device_id,
                              comparison_key="management.ssh.enabled::unscoped::rule", rule_id="management.ssh.enabled",
                              rule_pack_version_id=uuid4(), title="SSH", security_domain="management", verdict=FindingVerdict.PASS,
                              severity=FindingSeverity.HIGH, expected_state={}, observed_state={}, explanation="test", affected_scope=None,
                              effective_state_refs=[], evidence_refs=[], unknown_reason=None, framework_references=[])
            db.add_all([state, finding])
            db.flush()
            pin_assessment(db, audit, "cisco.ios_xe.17@1.0.0")
            coverage = persist_assessment_results(db, audit_id=audit.audit_id, organization_id=organization_id,
                                                  profile_version_id="cisco.ios_xe.17@1.0.0", findings=[finding])
            results = list(db.scalars(select(AssessmentResult).where(AssessmentResult.audit_id == audit.audit_id)))
            assert audit.version_refs["assessment_pack_version_id"] == str(pack_id)
            assert coverage["automatic_verdicts"]["pass"] == 1 and coverage["manual"] == 1
            assert coverage["assessment_pack"]["version"] == 1
            assert {row.verdict for row in results} == {"pass", None}
    finally:
        outer.rollback()
        connection.close()
        engine.dispose()


def test_runtime_profile_pack_is_tenant_scoped_and_pinned_from_a_fresh_session():
    engine = create_database_engine(get_settings())
    connection = engine.connect()
    outer = connection.begin()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False)
    profile_id = f"runtime.fictitious.{uuid4().hex[:8]}"
    raw_profile = _runtime_profile(profile_id)
    profile_version_id = raw_profile["profile_version_id"]
    try:
        with factory.begin() as db:
            organization = Organization(name="Runtime profile pack org", slug=f"runtime-profile-pack-{uuid4().hex[:10]}")
            other = Organization(name="Other runtime profile pack org", slug=f"other-runtime-profile-pack-{uuid4().hex[:10]}")
            db.add_all([organization, other]); db.flush()
            organization_id, other_organization_id = organization.organization_id, other.organization_id
            publish_runtime_profile(db, organization_id, parse_runtime_profile(json.dumps(raw_profile).encode()), raw_profile)
            content = _runtime_profile_catalog(profile_version_id)
            catalog = parse_runtime_catalog(
                content, "runtime-profile-pack.json",
                profile_lookup=lambda value: profile_for(db, organization_id, value),
            )
            pack = publish_runtime_catalog(db, organization_id, catalog, "runtime-profile-pack.json")
            pack_id = pack.assessment_pack_version_id
            with pytest.raises(CatalogImportError, match="unsupported profile"):
                parse_runtime_catalog(
                    content, "runtime-profile-pack.json",
                    profile_lookup=lambda value: profile_for(db, other_organization_id, value),
                )

        with factory.begin() as db:
            assert profile_for(db, organization_id, profile_version_id).profile_id == profile_id
            assert [item.assessment_pack_version_id for item in compatible_packs(db, organization_id, profile_version_id)] == [pack_id]
            user = User(organization_id=organization_id, email=f"runtime-profile-{uuid4().hex}@example.invalid", password_hash="test-only", role=UserRole.ADMIN)
            device = Device(organization_id=organization_id, display_name="runtime profile device")
            db.add_all([user, device]); db.flush()
            snapshot = Snapshot(device_id=device.device_id, organization_id=organization_id, status=SnapshotStatus.LOCKED,
                                grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED, snapshot_hash="e" * 64,
                                artifact_count=0, source=SnapshotSource.UPLOAD, created_by=user.user_id)
            db.add(snapshot); db.flush()
            audit = Audit(organization_id=organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id,
                          revision_number=1, reevaluation_reason=AuditReevaluationReason.INITIAL, status=AuditStatus.PROCESSING,
                          selected_frameworks=[], version_refs={"assessment_pack_version_id": str(pack_id)},
                          profile_resolution={"profile_version_id": profile_version_id}, verdict_counts={}, severity_counts={}, coverage={}, created_by=user.user_id)
            db.add(audit); db.flush()
            pinned = pin_assessment(db, audit, profile_version_id)
            assert pinned.assessment_pack_version_id == pack_id
    finally:
        outer.rollback()
        connection.close()
        engine.dispose()
