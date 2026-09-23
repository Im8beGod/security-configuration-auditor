import os
import json
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from app.cli.bootstrap_admin import bootstrap_admin
from app.compliance.verdicts import FindingSeverity, FindingVerdict
from app.core.config import get_settings
from app.audit.pipeline import AuditPipelineCoordinator
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


from app.training.ai import DeterministicFakeSuggestionProvider, MappingSuggestion, OllamaSuggestionProvider
from app.training.service import suggest_mapping, adopt_suggestion
from app.reevaluation.service import start as start_reevaluation
from app.snapshots.service import calculate_snapshot_hash
from app.audit.schemas import AuditCreate
from app.audit.service import create_audit, start_audit
from app.ingestion.service import ingest_artifact
from app.ingestion.storage import LocalFilesystemArtifactStorage
from app.profile_resolution.runtime import parse_runtime_profile, publish_runtime_profile
from app.profile_resolution.runtime import profile_for
from app.assessment_packs.catalog import parse_runtime_catalog, publish_runtime_catalog
from app.compliance.runtime_rules import publish_runtime_rule, runtime_rule_for
from app.snapshots.schemas import SnapshotCreate
from app.snapshots.service import add_artifact, create_snapshot, finalize_snapshot
from test_training_postgres import _definition

pytestmark = pytest.mark.skipif(os.environ.get("SIH_TRAINING_POSTGRES_TEST") != "1", reason="Requires development PostgreSQL")


def test_ai_preview_adoption_and_executable_validation():
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
            count = db.scalar(select(func.count()).select_from(MappingVersion))
            key = "test-only-suggestion-key-at-least-32-characters"
            provider = DeterministicFakeSuggestionProvider(MappingSuggestion(definition=_definition(), description="AI proposal", confidence=0.7))
            preview = suggest_mapping(db, admin, block_id, provider, key)
            assert db.scalar(select(func.count()).select_from(MappingVersion)) == count
            assert db.get(UnresolvedBlock, block_id).assigned_mapping_version_id is None
            other = db.get(User, other_id)
            with pytest.raises(TrainingNotFound):
                suggest_mapping(db, other, block_id, provider, key)
            with pytest.raises(TrainingNotFound):
                adopt_suggestion(db, other, block_id, preview.adoption_token, key)
            mapping = adopt_suggestion(db, admin, block_id, preview.adoption_token, key)
            assert mapping.status == MappingStatus.DRAFT
            assert db.scalar(select(func.count()).select_from(MappingVersion)) == count + 1
            with pytest.raises(TrainingError):
                adopt_suggestion(db, admin, block_id, preview.adoption_token, key)
            with pytest.raises(TrainingError):
                approve_mapping(db, admin, mapping.mapping_version_id)
            with pytest.raises(TrainingError):
                publish_mapping(db, admin, mapping.mapping_version_id)
            run, _ = request_validation(db, admin, mapping.mapping_version_id)
            result = execute_validation(db, run.validation_run_id, mapping.mapping_version_id, organization_id)
            assert result.results["passed"] is True
            assert mapping.approved_by is None and mapping.knowledge_pack_version_id is None
            assert db.get(Audit, audit_id).version_refs == original_refs
            finding = db.get(Finding, finding_id)
            assert (finding.verdict, finding.explanation, finding.unknown_reason) == original_finding
    finally:
        outer.rollback()
        connection.close()
        engine.dispose()


def test_xml_api_adoption_produces_candidate_facts_and_states(tmp_path, monkeypatch):
    real_ollama = False
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app.auth.dependencies import get_current_user
    from app.db.session import get_db
    from app.db.models import Artifact, ArtifactContentFamily, ArtifactEvidenceType, ArtifactStatus, SecurityFact, EffectiveState
    from app.api.v1.training import get_ai_suggestion_provider
    from app.ingestion.storage import LocalFilesystemArtifactStorage
    from app.training.ai import AISuggestionUnavailable
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    monkeypatch.setattr("app.ingestion.storage.get_artifact_storage", lambda: storage)
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
            audit = Audit(organization_id=organization_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id, revision_number=1, reevaluation_reason=AuditReevaluationReason.INITIAL, status=AuditStatus.COMPLETED_WITH_UNKNOWNS, selected_frameworks=[], version_refs={"knowledge_pack_version_id": "sealed-pack", "device_profile_version_id": "juniper.junos.18@1.0.0"}, profile_resolution={"profile_id": "juniper.junos.18", "profile_version_id": "juniper.junos.18@1.0.0", "resolution_status": "resolved", "confidence": "high", "vendor": "Juniper", "product_family": "Junos", "os": "Junos", "metadata": {}}, verdict_counts={"unknown": 1}, severity_counts={}, coverage={}, created_by=admin_id)
            db.add(audit); db.flush()
            content = b"<configuration><system><services><ssh/></services></system></configuration>"
            artifact_id = uuid4()
            reference = storage.write(content, organization_id=organization_id, artifact_id=artifact_id)
            artifact = Artifact(artifact_id=artifact_id, organization_id=organization_id, snapshot_id=snapshot.snapshot_id, original_filename="b4-development.xml", storage_reference=reference, byte_size=len(content), sha256=sha256(content).hexdigest(), encoding="utf-8", content_family=ArtifactContentFamily.XML, evidence_type=ArtifactEvidenceType.STRUCTURED_EXPORT, status=ArtifactStatus.READY)
            negative_content = b"<configuration><system><services/></system></configuration>"
            negative_artifact_id = uuid4()
            negative_reference = storage.write(negative_content, organization_id=organization_id, artifact_id=negative_artifact_id)
            negative_artifact = Artifact(artifact_id=negative_artifact_id, organization_id=organization_id, snapshot_id=snapshot.snapshot_id, original_filename="b4-negative.xml", storage_reference=negative_reference, byte_size=len(negative_content), sha256=sha256(negative_content).hexdigest(), encoding="utf-8", content_family=ArtifactContentFamily.XML, evidence_type=ArtifactEvidenceType.STRUCTURED_EXPORT, status=ArtifactStatus.READY)
            db.add_all([artifact, negative_artifact]); db.flush()
            snapshot.artifact_count = 2
            snapshot.snapshot_hash = calculate_snapshot_hash([artifact.sha256, negative_artifact.sha256])
            block = UnresolvedBlock(organization_id=organization_id, audit_id=audit.audit_id, device_id=device.device_id, snapshot_id=snapshot.snapshot_id, profile_id="juniper.junos.18", profile_version_id="juniper.junos.18@1.0.0", source_ir_node_ids=["node-1"], evidence_refs=[{"artifact_id": str(artifact_id)}], raw_text="<ssh/>", surrounding_context=content.decode(), unknown_reason="unmapped_syntax", candidate_field_ids=["management.remote.ssh.enabled"], affected_rule_ids=["rule.unknown"], fingerprint=sha256(f"{audit.audit_id}:node-1".encode()).hexdigest(), occurrence={"xml_path": ["configuration[1]", "system[1]", "services[1]", "ssh[1]"]})
            db.add(block)
            finding = Finding(finding_id=uuid4(), audit_id=audit.audit_id, device_id=device.device_id, comparison_key="unknown", rule_id="rule.unknown", rule_pack_version_id=uuid4(), title="Unknown", security_domain="management", verdict=FindingVerdict.UNKNOWN, severity=FindingSeverity.MEDIUM, expected_state={}, observed_state=None, explanation="Persisted unknown", affected_scope=None, effective_state_refs=[], evidence_refs=[], unknown_reason="missing_evidence", framework_references=[], remediation_procedure_id=None)
            db.add(finding)
            audit_id, original_refs = audit.audit_id, dict(audit.version_refs)
            finding_id, original_finding = finding.finding_id, (finding.verdict, finding.explanation, finding.unknown_reason)

        with factory() as db:
            admin = db.get(User, admin_id)
            block_id = db.scalar(select(UnresolvedBlock.unresolved_block_id).where(UnresolvedBlock.audit_id == audit_id))
            definition = MappingDefinition.model_validate({
                "profile_applicability": {"profile_version_ids": ["juniper.junos.18@1.0.0"]},
                "structural_match": {"operation": "xml_path", "command": "xml", "xml_path": {"path": [{"local_name": name} for name in ["configuration", "system", "services", "ssh"]], "source": "presence"}},
                "target_field_id": "management.remote.ssh.enabled", "value_extraction": {"operation": "boolean_from_presence", "output_type": "boolean"}, "scope_resolution": {"strategy": "device"},
                "negation_behavior": {"operation": "unsupported"}, "removal_behavior": {"operation": "unsupported"}, "default_behavior": {"operation": "unknown"}, "examples": [],
            })
            import httpx
            import json
            transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"done": True, "message": {"content": json.dumps({"definition": definition.model_dump(mode="json"), "description": "Unreviewed XML proposal", "confidence": 0.7})}}))
            provider = OllamaSuggestionProvider(get_settings(), transport=None if real_ollama else transport)
            app = create_app(get_settings())
            app.dependency_overrides[get_current_user] = lambda: admin
            app.dependency_overrides[get_db] = lambda: db
            app.dependency_overrides[get_ai_suggestion_provider] = lambda: provider
            count_models = [MappingVersion, KnowledgePackVersionRecord, SecurityFact, EffectiveState, Finding]
            counts = lambda: [db.scalar(select(func.count()).select_from(model)) for model in count_models]
            before = counts()
            with TestClient(app) as client:
                if real_ollama:
                    assert provider.status()["available"] is True
                response = client.post(f"/api/v1/training/unresolved/{block_id}/suggest")
                assert response.status_code == 200, response.text
                preview = response.json()
                assert counts() == before
                assert db.get(UnresolvedBlock, block_id).assigned_mapping_version_id is None
                adopted = client.post(f"/api/v1/training/unresolved/{block_id}/adopt", json={"adoption_token": preview["adoption_token"]})
                assert adopted.status_code == 201, adopted.text
                assert adopted.json()["status"] == "draft"
                provenance = adopted.json()["ai_suggestion_metadata"]
                assert provenance["provider"]["input_digest"] == preview["suggestion"]["provider_metadata"]["input_digest"]
                assert provenance["evidence_refs"] == [{"artifact_id": str(artifact_id)}]
                assert adopted.json()["structural_match"] == preview["suggestion"]["definition"]["structural_match"]
                from uuid import UUID
                mapping_id = UUID(adopted.json()["mapping_version_id"])
                assert client.post(f"/api/v1/training/mappings/{mapping_id}/approve").status_code == 409
                assert client.post(f"/api/v1/training/mappings/{mapping_id}/publish").status_code == 409
                queued = client.post(f"/api/v1/training/mappings/{mapping_id}/validate", json={"evidence_artifact_id": str(artifact_id), "negative_evidence_artifact_id": str(negative_artifact_id)})
                assert queued.status_code == 202, queued.text
                run_id = UUID(queued.json()["validation_run_id"])
                result = execute_validation(db, run_id, mapping_id, organization_id)
                assert result.results["passed"] is True
                assert result.results["semantic"]["facts"]
                assert result.results["semantic"]["effective_states"]
                assert counts()[1:] == before[1:]
                assert db.get(MappingVersion, mapping_id).approved_by is None
                assert db.get(Audit, audit_id).version_refs == original_refs
                finding = db.get(Finding, finding_id)
                assert (finding.verdict, finding.explanation, finding.unknown_reason) == original_finding
                approved = approve_mapping(db, admin, mapping_id)
                published, pack = publish_mapping(db, admin, approved.mapping_version_id)
                assert published.status == MappingStatus.PUBLISHED
                reprocessed, _ = start_reevaluation(db, admin, audit_id, pack.knowledge_pack_version_id)
                reused = AuditPipelineCoordinator(factory, storage).run(reprocessed.audit_id, organization_id)
                assert reused.interpretation is not None
                assert any(fact.mapping_version_id == published.mapping_version_id for fact in reused.interpretation.facts)
                # Role checks and nonfatal outage apply to the same API surface.
                app.dependency_overrides[get_current_user] = lambda: type("Analyst", (), {"role": UserRole.ANALYST})()
                assert client.get("/api/v1/training/ai/status").status_code == 403
                assert client.post(f"/api/v1/training/unresolved/{block_id}/suggest").status_code == 403
                assert client.post(f"/api/v1/training/unresolved/{block_id}/adopt", json={"adoption_token": preview["adoption_token"]}).status_code == 403
                app.dependency_overrides[get_current_user] = lambda: admin
                class OfflineProvider:
                    def suggest_mapping(self, context, profile):
                        del context, profile
                        raise AISuggestionUnavailable("offline")
                app.dependency_overrides[get_ai_suggestion_provider] = OfflineProvider
                assert client.post(f"/api/v1/training/unresolved/{block_id}/suggest").status_code == 503
                assert client.get("/api/v1/training/canonical-fields").status_code == 200
    finally:
        outer.rollback()
        connection.close()
        engine.dispose()


@pytest.mark.parametrize("real_ollama", [False, pytest.param(True, marks=pytest.mark.skipif(os.environ.get("SIH_REAL_OLLAMA_TEST") != "1", reason="Real local Ollama acceptance is opt-in"))])
def test_runtime_cli_ai_training_lifecycle(tmp_path, monkeypatch, real_ollama):
    """Exercise a genuinely new CLI syntax through the complete supervised lifecycle."""
    from fastapi.testclient import TestClient
    from app.api.v1.training import get_ai_suggestion_provider
    from app.auth.dependencies import get_current_user
    from app.db.session import get_db
    from app.db.models import AssessmentResult, EffectiveState, SecurityFact
    from app.profile_resolution import PROFILE_REGISTRY

    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    monkeypatch.setattr("app.ingestion.storage.get_artifact_storage", lambda: storage)
    engine = create_database_engine(get_settings())
    connection = engine.connect(); outer = connection.begin()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint", autoflush=False, autocommit=False, expire_on_commit=False)
    suffix = uuid4().hex
    profile_version_id = f"runtime.helios.{suffix[:8]}@1.0.0"
    profile_id = profile_version_id.split("@", 1)[0]
    profile_manifest = {
        "schema_version": "1.0.0", "profile_id": profile_id, "profile_version": "1.0.0",
        "profile_version_id": profile_version_id, "vendor": "Fictitious Helios",
        "product_family": "Helios Edge", "os": "HeliosOS", "structural_reader": "indentation_cli.v1",
        "evidence_types": ["configuration"], "device_classes": ["router"],
        "detection": {"tokens": ["Fictitious Helios", "HeliosOS"]},
        "version_constraints": {"supported_major_versions": [1]},
        "canonical_fields": ["management.remote.ssh.enabled"],
        "capabilities": ["structural_parsing", "semantic_interpretation", "effective_state_resolution", "administrator_training"],
    }
    definition_payload = {
        "profile_applicability": {"profile_version_ids": [profile_version_id]},
        "structural_match": {"operation": "command_equality", "command": "secure-shell", "arguments": [{"operation": "literal", "value": "enable"}]},
        "target_field_id": "management.remote.ssh.enabled",
        "value_extraction": {"operation": "boolean_from_presence", "output_type": "boolean"},
        "scope_resolution": {"strategy": "device"},
        "negation_behavior": {"operation": "unsupported"}, "removal_behavior": {"operation": "unsupported"},
        "default_behavior": {"operation": "unknown"},
        "examples": [
            {"family": family, "node": {"command": "secure-shell", "arguments": ["enable"], "negated": False}, "expected_match": True, "expected_value": True}
            for family in ("positive", "alternate_values", "wrong_scope", "negation", "conflict")
        ] + [
            {"family": "negative", "node": {"command": "secure-shell", "arguments": ["disable"], "negated": False}, "expected_match": False},
            {"family": "regression", "node": {"command": "other-command", "arguments": ["enable"], "negated": False}, "expected_match": False},
        ],
    }
    try:
        organization_id, admin_id = bootstrap_admin(factory, "Helios", f"helios-{suffix}", f"admin-{suffix}@example.invalid", "test-only-password")
        other_organization_id, other_id = bootstrap_admin(factory, "Other Helios", f"other-helios-{suffix}", f"other-{suffix}@example.invalid", "test-only-password")
        with factory() as db:
            profile = parse_runtime_profile(json.dumps(profile_manifest).encode())
            publish_runtime_profile(db, organization_id, profile, profile_manifest)
            assert profile_version_id not in PROFILE_REGISTRY
            assert db.scalar(select(MappingVersion.mapping_version_id).where(MappingVersion.organization_id == organization_id)) is None
            admin = db.get(User, admin_id)
            device = Device(organization_id=organization_id, display_name="Helios acceptance router")
            db.add(device); db.flush()
            unknown = ingest_artifact(db, storage, admin, b"! Fictitious Helios HeliosOS version 1.0.0\nsecure-shell enable\n", "helios.cfg", "text/plain")
            snapshot = create_snapshot(db, admin, device.device_id, SnapshotCreate(label="initial unknown"))
            add_artifact(db, admin, snapshot.snapshot_id, unknown.artifact_id)
            finalize_snapshot(db, admin, snapshot.snapshot_id)
            audit = create_audit(db, admin, AuditCreate(snapshot_id=snapshot.snapshot_id, selected_frameworks=[]))
            audit, _ = start_audit(db, admin, audit.audit_id)
            audit_id = audit.audit_id

        initial = AuditPipelineCoordinator(factory, storage).run(audit_id, organization_id)
        assert initial.profile_resolution.selected_profile_version_id == profile_version_id
        with factory() as db:
            block = db.scalar(select(UnresolvedBlock).where(UnresolvedBlock.audit_id == audit_id))
            assert block is not None and block.raw_text == "secure-shell enable"
            assert block.candidate_field_ids == ["management.remote.ssh.enabled"]
            assert db.scalar(select(MappingVersion.mapping_version_id).where(MappingVersion.organization_id == organization_id)) is None
            admin = db.get(User, admin_id)
            positive = ingest_artifact(db, storage, admin, b"secure-shell enable\n", "helios-positive.cfg", "text/plain")
            negative = ingest_artifact(db, storage, admin, b"secure-shell disable\n", "helios-negative.cfg", "text/plain")
            for artifact, label in ((positive, "positive"), (negative, "negative")):
                validation_snapshot = create_snapshot(db, admin, device.device_id, SnapshotCreate(label=label))
                add_artifact(db, admin, validation_snapshot.snapshot_id, artifact.artifact_id)
                finalize_snapshot(db, admin, validation_snapshot.snapshot_id)
            block_id = block.unresolved_block_id
            positive_id, negative_id = positive.artifact_id, negative.artifact_id

        import httpx
        provider = OllamaSuggestionProvider(
            get_settings(),
            transport=None if real_ollama else httpx.MockTransport(
                lambda request: httpx.Response(200, json={"done": True, "message": {"content": json.dumps({"definition": definition_payload, "description": "Helios SSH mapping proposal", "confidence": 0.8})}})
            ),
        )
        app = __import__("app.main", fromlist=["create_app"]).create_app(get_settings())
        app.dependency_overrides[get_ai_suggestion_provider] = lambda: provider
        with factory() as db:
            app.dependency_overrides[get_current_user] = lambda: db.get(User, admin_id)
            app.dependency_overrides[get_db] = lambda: db
            if real_ollama:
                assert provider.status()["available"] is True
            before = db.scalar(select(func.count()).select_from(MappingVersion).where(MappingVersion.organization_id == organization_id))
            other = db.get(User, other_id)
            with TestClient(app) as client:
                preview_response = client.post(f"/api/v1/training/unresolved/{block_id}/suggest")
                assert preview_response.status_code == 200, preview_response.text
                preview = preview_response.json()
                assert before == db.scalar(select(func.count()).select_from(MappingVersion).where(MappingVersion.organization_id == organization_id))
                assert 1 <= int(preview["suggestion"]["provider_metadata"]["attempt_count"]) <= 2
                app.dependency_overrides[get_current_user] = lambda: other
                assert client.post(f"/api/v1/training/unresolved/{block_id}/suggest").status_code == 404
                app.dependency_overrides[get_current_user] = lambda: db.get(User, admin_id)
                adopted = client.post(f"/api/v1/training/unresolved/{block_id}/adopt", json={"adoption_token": preview["adoption_token"]})
                assert adopted.status_code == 201 and adopted.json()["status"] == "draft"
                mapping_id = adopted.json()["mapping_version_id"]
                assert client.post(f"/api/v1/training/mappings/{mapping_id}/approve").status_code == 409
                assert client.post(f"/api/v1/training/mappings/{mapping_id}/publish").status_code == 409
                queued = client.post(f"/api/v1/training/mappings/{mapping_id}/validate", json={"evidence_artifact_id": str(positive_id), "negative_evidence_artifact_id": str(negative_id)})
                assert queued.status_code == 202, queued.text
            run_id = UUID(queued.json()["validation_run_id"])
            mapping_uuid = UUID(mapping_id)
            result = execute_validation(db, run_id, mapping_uuid, organization_id)
            assert result.results["passed"] is True, result.results
            approved = approve_mapping(db, admin, mapping_uuid)
            published, knowledge_pack = publish_mapping(db, admin, approved.mapping_version_id)
            assert published.status == MappingStatus.PUBLISHED
            runtime_rule = publish_runtime_rule(db, organization_id, {"rule_id": f"helios.runtime.ssh.{suffix[:8]}", "profile_version_ids": [profile_version_id], "canonical_field": "management.remote.ssh.enabled", "operator": "equals", "expected": True, "title": "Helios SSH enabled", "security_domain": "management", "severity": "high", "framework_references": []})
            catalog_payload = {"schema_version": "1.0.0", "pack_key": f"helios.runtime.{suffix[:8]}", "family": "Helios Acceptance Framework", "name": "Helios controls", "version": 1, "source_version": "1", "source_url": "https://example.invalid/helios", "profile_version_ids": [profile_version_id], "obligations": [{"obligation_key": "HEL-SSH-1", "control_id": "HEL-SSH-1", "title": "Helios SSH enabled", "severity": "high", "scope": "device", "assessment_method": "automatic", "implementation_status": "implemented", "evaluator_rule_id": runtime_rule.rule_id, "policy_parameters": {}}]}
            catalog = parse_runtime_catalog(json.dumps(catalog_payload).encode(), "helios.json", profile_lookup=lambda value: profile_for(db, organization_id, value), rule_lookup=lambda rule_id, profile_id: runtime_rule_for(db, organization_id, rule_id, profile_id))
            assessment_pack = publish_runtime_catalog(db, organization_id, catalog, "helios.json")
            reprocessed, _ = start_reevaluation(db, admin, audit_id, knowledge_pack.knowledge_pack_version_id, assessment_pack.assessment_pack_version_id)
            db.commit()
            reused_audit_id = reprocessed.audit_id
        reused = AuditPipelineCoordinator(factory, storage).run(reused_audit_id, organization_id)
        assert reused.interpretation is not None
        with factory() as db:
            assert db.scalar(select(SecurityFact).where(SecurityFact.audit_id == reused_audit_id, SecurityFact.mapping_version_id == published.mapping_version_id)) is not None
            assert db.scalar(select(EffectiveState).where(EffectiveState.audit_id == reused_audit_id, EffectiveState.field_id == "management.remote.ssh.enabled")) is not None
            assert db.scalar(select(AssessmentResult).where(AssessmentResult.audit_id == reused_audit_id, AssessmentResult.verdict == "pass")) is not None
    finally:
        outer.rollback(); connection.close(); engine.dispose()
