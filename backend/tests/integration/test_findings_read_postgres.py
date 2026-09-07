"""Opt-in PostgreSQL/FastAPI coverage for the Step 8.1 findings read boundary."""

import os
from hashlib import sha256
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, text

from app.cli.bootstrap_admin import bootstrap_admin
from app.compliance.verdicts import FindingSeverity, FindingVerdict
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Artifact, ArtifactContentFamily, ArtifactEvidenceType, ArtifactStatus, Audit,
    AuditReevaluationReason, AuditStatus, Device, EffectiveState, FactState,
    FactValidationStatus, Finding, InterpretationConfidence, InterpretationMethod,
    Organization, SecurityFact, Snapshot, SnapshotGroupingStatus, SnapshotSource,
    SnapshotStatus, User, RemediationProcedure, RemediationProcedureStatus,
)
from app.db.session import create_session_factory, get_db
from app.effective_state import ResolutionStatus, UnresolvedReason
from app.ingestion.storage import LocalFilesystemArtifactStorage, get_artifact_storage
from app.main import create_app


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_STEP8_POSTGRES_TEST") != "1",
    reason="Set SIH_STEP8_POSTGRES_TEST=1 with development PostgreSQL settings",
)


def _snapshot(organization_id, device_id, user_id, label):
    return Snapshot(
        organization_id=organization_id, device_id=device_id, label=label,
        grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
        snapshot_hash=sha256(label.encode()).hexdigest(), artifact_count=1,
        source=SnapshotSource.UPLOAD, status=SnapshotStatus.LOCKED, created_by=user_id,
    )


def _audit(organization_id, device_id, snapshot_id, user_id, revision):
    return Audit(
        organization_id=organization_id, device_id=device_id, snapshot_id=snapshot_id,
        revision_number=revision, reevaluation_reason=AuditReevaluationReason.INITIAL,
        status=AuditStatus.PROCESSING, selected_frameworks=[], version_refs={"device_profile_version_id": "cisco.ios_xe.17@1.0.0"},
        profile_resolution={"resolution_status": "resolved", "profile_version_id": "cisco.ios_xe.17@1.0.0"}, verdict_counts={},
        severity_counts={}, coverage={}, created_by=user_id,
    )


def _finding(audit, key, *, verdict=FindingVerdict.FAIL, severity=FindingSeverity.HIGH,
             state_refs=None, unknown_reason=None):
    return Finding(
        finding_id=uuid4(), audit_id=audit.audit_id, device_id=audit.device_id,
        comparison_key=key, rule_id="iosxe.management.ssh", rule_pack_version_id=uuid4(),
        title="SSH management", security_domain="management", verdict=verdict,
        severity=severity, expected_state={"type": "boolean", "value": True},
        observed_state={"type": "boolean", "value": False},
        explanation="Persisted explanation", affected_scope={"type": "device", "key": "device"},
        effective_state_refs=state_refs or [], evidence_refs=[{"kind": "persisted"}],
        unknown_reason=unknown_reason, framework_references=[{"framework": "CIS", "control": "1.1"}],
        remediation_procedure_id=None,
    )


def _cleanup(db, organization_ids):
    audit_ids = select(Audit.audit_id).where(Audit.organization_id.in_(organization_ids))
    db.execute(delete(Finding).where(Finding.audit_id.in_(audit_ids)))
    db.execute(delete(RemediationProcedure))
    db.execute(delete(EffectiveState).where(EffectiveState.audit_id.in_(audit_ids)))
    db.execute(delete(SecurityFact).where(SecurityFact.audit_id.in_(audit_ids)))
    db.execute(delete(Audit).where(Audit.organization_id.in_(organization_ids)))
    db.execute(delete(Artifact).where(Artifact.organization_id.in_(organization_ids)))
    db.execute(delete(Snapshot).where(Snapshot.organization_id.in_(organization_ids)))
    db.execute(delete(Device).where(Device.organization_id.in_(organization_ids)))
    db.execute(delete(User).where(User.organization_id.in_(organization_ids)))
    db.execute(delete(Organization).where(Organization.organization_id.in_(organization_ids)))


def _procedure(rule_id, *, status=RemediationProcedureStatus.PUBLISHED, profile="cisco.ios_xe.17@1.0.0"):
    return RemediationProcedure(procedure_key=f"test.{uuid4()}", version=1, rule_id=rule_id,
        title="Synthetic recommendation", security_objective="test", description="test only", status=status,
        profile_applicability={"profile_version_ids": [profile]}, prerequisites=[], safety_warnings=[],
        required_parameters=[{"name": "network", "type": "ip_network", "required": True}], configuration_context=[],
        ordered_steps=[{"text": "synthetic network {network}"}], verification_steps=[], rollback_steps=[],
        validation_results=[{"result": "synthetic"}], source_references=[{"source": "synthetic"}])


def test_remediation_api_registry_preview_and_fail_closed_postgres(tmp_path):
    settings = get_settings().model_copy(update={"api_prefix": "/api/v1", "auth_cookie_name": "step9_test", "auth_cookie_secure": False})
    engine = create_database_engine(settings); factory = create_session_factory(engine); organizations = []
    try:
        suffix = uuid4().hex
        org, user_id = bootstrap_admin(factory, "Step 9", f"step9-{suffix}", f"step9-{suffix}@example.invalid", "test-only-password")
        other, _ = bootstrap_admin(factory, "Step 9 Other", f"step9-other-{suffix}", f"step9-other-{suffix}@example.invalid", "test-only-password")
        organizations.extend((org, other))
        with factory.begin() as db:
            device = Device(organization_id=org, display_name="Step 9 device"); db.add(device); db.flush()
            snapshot = _snapshot(org, device.device_id, user_id, f"step9-{suffix}"); db.add(snapshot); db.flush()
            audit = _audit(org, device.device_id, snapshot.snapshot_id, user_id, 1); db.add(audit); db.flush()
            finding = _finding(audit, "step9-fail"); unknown = _finding(audit, "step9-unknown", verdict=FindingVerdict.UNKNOWN, severity=FindingSeverity.LOW, unknown_reason=UnresolvedReason.MISSING_EVIDENCE)
            procedure = _procedure(finding.rule_id); db.add_all((finding, unknown, procedure)); db.flush()
            finding_id, unknown_id, audit_id, procedure_id = finding.finding_id, unknown.finding_id, audit.audit_id, procedure.procedure_id
            before_finding = (finding.verdict, finding.explanation, finding.remediation_procedure_id, finding.created_at)
            before_audit = (audit.status, audit.processing_stage, audit.version_refs, audit.profile_resolution, audit.completed_at)
        app = create_app(settings)
        def dependency():
            with factory() as db: yield db
        app.dependency_overrides[get_db] = dependency
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[get_artifact_storage] = lambda: LocalFilesystemArtifactStorage(tmp_path / "artifacts")
        with TestClient(app) as client:
            assert client.post("/api/v1/auth/login", json={"email": f"step9-{suffix}@example.invalid", "password": "test-only-password"}).status_code == 200
            get = client.get(f"/api/v1/findings/{finding_id}/remediation"); assert get.status_code == 200
            assert get.json()["procedure_id"] == str(procedure_id) and get.json()["selection_source"] == "published_registry_resolution"
            preview = client.post(f"/api/v1/findings/{finding_id}/remediation/preview", json={"parameters": {"network": "192.0.2.3/24"}})
            assert preview.status_code == 200 and preview.json()["rendered_steps"] == ["synthetic network 192.0.2.0/24"]
            assert client.post(f"/api/v1/findings/{finding_id}/remediation/preview", json={"parameters": {"network": "bad"}}).status_code == 422
            assert client.get(f"/api/v1/findings/{unknown_id}/remediation").json()["status"] == "not_required"
            with factory.begin() as db:
                audit_row = db.get(Audit, audit_id)
                ambiguous = _finding(audit_row, "step9-ambiguous"); ambiguous.rule_id = "synthetic.ambiguous"
                first = _procedure(ambiguous.rule_id); second = _procedure(ambiguous.rule_id)
                pinned = _finding(audit_row, "step9-pinned"); pinned.rule_id = "synthetic.pinned"
                pinned_a = _procedure(pinned.rule_id); pinned_a.procedure_id = uuid4(); pinned_b = _procedure(pinned.rule_id); pinned.remediation_procedure_id = pinned_a.procedure_id
                invalid_pin = _finding(audit_row, "step9-invalid-pin"); invalid_pin.rule_id = "synthetic.invalid-pin"
                incompatible = _procedure(invalid_pin.rule_id, profile="other.profile@1"); incompatible.procedure_id = uuid4(); matching = _procedure(invalid_pin.rule_id); invalid_pin.remediation_procedure_id = incompatible.procedure_id
                db.add_all((ambiguous, first, second, pinned, pinned_a, pinned_b, invalid_pin, incompatible, matching)); db.flush()
                ambiguous_id, pinned_id, invalid_pin_id = ambiguous.finding_id, pinned.finding_id, invalid_pin.finding_id
                pinned_a_id = pinned_a.procedure_id
            ambiguous_response = client.get(f"/api/v1/findings/{ambiguous_id}/remediation").json()
            assert ambiguous_response["status"] == "unavailable" and ambiguous_response["reason"] == "ambiguous_procedure"
            pinned_response = client.get(f"/api/v1/findings/{pinned_id}/remediation").json()
            assert pinned_response["procedure_id"] == str(pinned_a_id) and pinned_response["selection_source"] == "explicit_finding_reference"
            invalid_response = client.get(f"/api/v1/findings/{invalid_pin_id}/remediation").json()
            assert invalid_response["status"] == "unavailable" and invalid_response["reason"] == "unsupported_profile"
            client.cookies.clear(); assert client.post("/api/v1/auth/login", json={"email": f"step9-other-{suffix}@example.invalid", "password": "test-only-password"}).status_code == 200
            assert client.get(f"/api/v1/findings/{finding_id}/remediation").status_code == 404
            assert client.post(f"/api/v1/findings/{finding_id}/remediation/preview", json={"parameters": {}}).status_code == 404
        with factory() as db:
            persisted_finding = db.get(Finding, finding_id); persisted_audit = db.get(Audit, audit_id)
            assert (persisted_finding.verdict, persisted_finding.explanation, persisted_finding.remediation_procedure_id, persisted_finding.created_at) == before_finding
            assert (persisted_audit.status, persisted_audit.processing_stage, persisted_audit.version_refs, persisted_audit.profile_resolution, persisted_audit.completed_at) == before_audit
    finally:
        if organizations:
            with factory.begin() as db: _cleanup(db, organizations)
        engine.dispose()


def test_findings_read_api_preserves_canonical_values_and_fails_closed(tmp_path):
    settings = get_settings().model_copy(update={
        "api_prefix": "/api/v1", "auth_cookie_name": "step8_findings_test",
        "auth_cookie_secure": False, "auth_cookie_samesite": "lax",
    })
    engine = create_database_engine(settings)
    factory = create_session_factory(engine)
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    organization_ids = []
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260907_0010"
        suffix = uuid4().hex
        organization_id, user_id = bootstrap_admin(factory, "Step 8 Read", f"step8-read-{suffix}", f"step8-read-{suffix}@example.invalid", "test-only-password")
        other_organization_id, _ = bootstrap_admin(factory, "Step 8 Other", f"step8-other-{suffix}", f"step8-other-{suffix}@example.invalid", "test-only-password")
        organization_ids.extend((organization_id, other_organization_id))
        with factory.begin() as db:
            device = Device(organization_id=organization_id, display_name="Read Boundary Device")
            db.add(device)
            db.flush()
            snapshot_a = _snapshot(organization_id, device.device_id, user_id, "snapshot-a")
            snapshot_b = _snapshot(organization_id, device.device_id, user_id, "snapshot-b")
            db.add_all((snapshot_a, snapshot_b))
            db.flush()
            audit_a = _audit(organization_id, device.device_id, snapshot_a.snapshot_id, user_id, 1)
            audit_b = _audit(organization_id, device.device_id, snapshot_b.snapshot_id, user_id, 1)
            db.add_all((audit_a, audit_b))
            db.flush()
            artifact_id = uuid4()
            raw = b"hostname edge\nline vty 0 4\n transport input ssh\n"
            reference = storage.write(raw, organization_id=organization_id, artifact_id=artifact_id)
            artifact = Artifact(
                artifact_id=artifact_id, organization_id=organization_id, snapshot_id=snapshot_a.snapshot_id,
                original_filename="edge.cfg", storage_reference=reference, byte_size=len(raw),
                sha256=sha256(raw).hexdigest(), mime_type="text/plain", encoding="utf-8",
                content_family=ArtifactContentFamily.TEXT, evidence_type=ArtifactEvidenceType.CONFIGURATION,
                status=ArtifactStatus.READY, validation_issues=[], source_metadata={}, uploaded_by=user_id,
            )
            fact = SecurityFact(
                fact_id=uuid4(), audit_id=audit_a.audit_id, device_id=device.device_id,
                snapshot_id=snapshot_a.snapshot_id, field_id="management.remote.ssh.enabled",
                value={"type": "boolean", "value": True}, entity=None,
                scope={"type": "device", "key": "device"}, state=FactState.EXPLICIT,
                evidence_refs=[{"artifact_id": str(artifact_id), "path": "line vty 0 4", "start_line": 2, "end_line": 3}],
                source_ir_node_ids=["node-1"], extraction_method=InterpretationMethod.DECLARATIVE_MAPPING,
                mapping_id=uuid4(), mapping_version_id=uuid4(), knowledge_pack_version_id=uuid4(),
                validation_status=FactValidationStatus.VALIDATED, dependencies=[],
                interpretation_confidence=InterpretationConfidence.HIGH,
            )
            state = EffectiveState(
                effective_state_id=uuid4(), audit_id=audit_a.audit_id, device_id=device.device_id,
                field_id=fact.field_id, scope={"type": "device", "key": "device"},
                scope_key="device::device", effective_value={"type": "boolean", "value": True},
                resolution_status=ResolutionStatus.RESOLVED, source_fact_ids=[str(fact.fact_id)],
                resolution_trace=[{"operation": "explicit"}], inherited_from=None,
                default_reference=None, referenced_objects=[], precedence_applied=[], unresolved_reason=None,
            )
            primary = _finding(audit_a, "a-primary", state_refs=[str(state.effective_state_id)])
            secondary = _finding(audit_a, "z-secondary", verdict=FindingVerdict.PASS, severity=FindingSeverity.LOW)
            missing = _finding(audit_a, "m-missing", verdict=FindingVerdict.UNKNOWN,
                               severity=FindingSeverity.LOW,
                               unknown_reason=UnresolvedReason.MISSING_EVIDENCE)
            foreign_state = EffectiveState(
                effective_state_id=uuid4(), audit_id=audit_b.audit_id, device_id=device.device_id,
                field_id="management.remote.telnet.enabled", scope={"type": "device", "key": "device"},
                scope_key="device::device", effective_value={"type": "boolean", "value": False},
                resolution_status=ResolutionStatus.RESOLVED, source_fact_ids=[], resolution_trace=[],
                inherited_from=None, default_reference=None, referenced_objects=[], precedence_applied=[], unresolved_reason=None,
            )
            cross_audit = _finding(audit_a, "x-cross-audit", state_refs=[str(foreign_state.effective_state_id)])
            db.add_all((artifact, fact, state, primary, secondary, missing, foreign_state, cross_audit))
            db.flush()

            foreign_artifact_id = uuid4()
            foreign_raw = b"foreign artifact bytes\n"
            foreign_reference = storage.write(foreign_raw, organization_id=other_organization_id, artifact_id=foreign_artifact_id)
            foreign_artifact = Artifact(
                artifact_id=foreign_artifact_id, organization_id=other_organization_id, snapshot_id=None,
                original_filename="foreign.cfg", storage_reference=foreign_reference, byte_size=len(foreign_raw),
                sha256=sha256(foreign_raw).hexdigest(), mime_type="text/plain", encoding="utf-8",
                content_family=ArtifactContentFamily.TEXT, evidence_type=ArtifactEvidenceType.CONFIGURATION,
                status=ArtifactStatus.READY, validation_issues=[], source_metadata={}, uploaded_by=None,
            )
            foreign_artifact_finding = _finding(audit_a, "y-foreign-artifact", state_refs=[str(state.effective_state_id)])
            db.add_all((foreign_artifact, foreign_artifact_finding))
            db.flush()
            foreign_fact_ref = {"artifact_id": str(foreign_artifact_id), "path": "foreign", "start_line": 1, "end_line": 1}
            foreign_artifact_finding.effective_state_refs = [str(state.effective_state_id)]
            db.flush()
            audit_a_id = audit_a.audit_id
            primary_id = primary.finding_id
            secondary_id = secondary.finding_id
            missing_id = missing.finding_id
            cross_audit_id = cross_audit.finding_id
            foreign_artifact_finding_id = foreign_artifact_finding.finding_id
            state_id = state.effective_state_id
            fact_id = fact.fact_id
            mapping_id = fact.mapping_id
            mapping_version_id = fact.mapping_version_id
            primary_expected = {
                "finding_id": str(primary.finding_id), "audit_id": str(primary.audit_id),
                "device_id": str(primary.device_id), "comparison_key": primary.comparison_key,
                "rule_id": primary.rule_id, "rule_pack_version_id": str(primary.rule_pack_version_id),
                "title": primary.title, "security_domain": primary.security_domain,
                "verdict": primary.verdict.value, "severity": primary.severity.value,
                "expected_state": primary.expected_state, "observed_state": primary.observed_state,
                "explanation": primary.explanation, "affected_scope": primary.affected_scope,
                "effective_state_refs": primary.effective_state_refs,
                "unknown_reason": primary.unknown_reason,
                "framework_references": primary.framework_references,
            }

        application = create_app(settings)
        application.dependency_overrides[get_settings] = lambda: settings
        application.dependency_overrides[get_artifact_storage] = lambda: storage

        def session_dependency():
            with factory() as db:
                yield db

        application.dependency_overrides[get_db] = session_dependency
        with TestClient(application) as client:
            assert client.post("/api/v1/auth/login", json={"email": f"step8-read-{suffix}@example.invalid", "password": "test-only-password"}).status_code == 200
            listing = client.get(f"/api/v1/audits/{audit_a_id}/findings")
            assert listing.status_code == 200
            listed = listing.json()
            assert [(item["created_at"], item["finding_id"]) for item in listed["items"]] == sorted(
                (item["created_at"], item["finding_id"]) for item in listed["items"]
            )
            assert listed["total"] == 5
            assert client.get(f"/api/v1/audits/{audit_a_id}/findings", params={"verdict": "pass"}).json()["items"][0]["finding_id"] == str(secondary_id)
            filtered = client.get(f"/api/v1/audits/{audit_a_id}/findings", params={"severity": "high", "security_domain": "management", "rule_id": "iosxe.management.ssh"})
            assert [item["finding_id"] for item in filtered.json()["items"]] == [str(primary_id), str(cross_audit_id), str(foreign_artifact_finding_id)]
            detail = client.get(f"/api/v1/findings/{primary_id}")
            assert detail.status_code == 200
            body = detail.json()
            for name, expected in primary_expected.items():
                assert body[name] == expected
            assert "storage_reference" not in str(body)
            evidence = client.get(f"/api/v1/findings/{primary_id}")
            assert evidence.json()["verdict"] == "fail" and evidence.json()["severity"] == "high" and evidence.json()["explanation"] == "Persisted explanation"
            evidence = client.get(f"/api/v1/findings/{primary_id}/evidence")
            assert evidence.status_code == 200
            evidence_body = evidence.json()
            state_body, fact_body, artifact_body = evidence_body["states"][0], evidence_body["states"][0]["facts"][0], evidence_body["states"][0]["facts"][0]["artifacts"][0]
            assert state_body["effective_state_id"] == str(state_id)
            assert fact_body["fact_id"] == str(fact_id)
            assert fact_body["mapping_id"] == str(mapping_id) and fact_body["mapping_version_id"] == str(mapping_version_id)
            assert artifact_body["artifact_id"] == str(artifact_id) and artifact_body["original_filename"] == "edge.cfg"
            assert artifact_body["excerpt"] == "line vty 0 4\n transport input ssh"
            assert fact_body["evidence_refs"][0]["path"] == "line vty 0 4"
            assert "storage_reference" not in str(evidence_body) and str(tmp_path) not in str(evidence_body)
            assert client.get(f"/api/v1/findings/{missing_id}/evidence").json() == {"finding_id": str(missing_id), "states": [], "status": "no_evidence"}
            assert client.get(f"/api/v1/findings/{cross_audit_id}/evidence").status_code == 422

            with factory.begin() as db:
                db.get(SecurityFact, fact_id).evidence_refs = [foreign_fact_ref]
            assert client.get(f"/api/v1/findings/{foreign_artifact_finding_id}/evidence").status_code == 422

            client.cookies.clear()
            assert client.post("/api/v1/auth/login", json={"email": f"step8-other-{suffix}@example.invalid", "password": "test-only-password"}).status_code == 200
            assert client.get(f"/api/v1/audits/{audit_a_id}/findings").status_code == 404
            assert client.get(f"/api/v1/findings/{primary_id}").status_code == 404
    finally:
        if organization_ids:
            with factory.begin() as db:
                _cleanup(db, organization_ids)
        engine.dispose()
