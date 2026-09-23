"""Compose acceptance proof for persisted CLI, JSON, and XML training mappings."""
from __future__ import annotations

import json
import os
import sys
import time
from hashlib import sha256
from uuid import uuid4

from sqlalchemy import func, select

from app.audit.pipeline import AuditPipelineCoordinator
from app.cli.bootstrap_admin import bootstrap_admin
from app.compliance.verdicts import FindingVerdict
from app.compliance.runtime_rules import publish_runtime_rule, runtime_rule_for
from app.assessment_packs.catalog import parse_runtime_catalog, publish_runtime_catalog
from app.assessment_packs.service import compatible_packs
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import (
    Artifact, ArtifactContentFamily, ArtifactEvidenceType, ArtifactStatus,
    Audit, AuditReevaluationReason, AuditStatus, Device, Finding, Job,
    MappingVersion, Organization, SecurityFact, Snapshot,
    SnapshotGroupingStatus, SnapshotSource, SnapshotStatus, UnresolvedBlock,
    User,
    AssessmentResult, AssessmentPackVersion, Report, ReportStatus,
)
from app.db.session import create_session_factory
from app.ingestion.storage import get_artifact_storage
from app.interpretation.service import load_active_published_knowledge_pack
from app.jobs.enums import JobStatus, JobType
from app.jobs.service import enqueue_job
from app.snapshots.service import calculate_snapshot_hash
from app.training.dsl import MappingDefinition
from app.training.service import (
    approve_mapping, create_mapping, publish_mapping, request_validation,
)
from app.profile_resolution.runtime import parse_runtime_profile, profile_for, publish_runtime_profile
from app.reporting.service import create_report


RUN_ID = os.environ.get("SIH_RESTART_REUSE_RUN_ID")
if not RUN_ID:
    raise SystemExit("SIH_RESTART_REUSE_RUN_ID is required")

FACT = "management.remote.ssh.enabled"
RULE = "management.ssh.enabled"
PROFILES = {
    "cli": "generic.cli@1.0.0",
    "json": "generic.json@1.0.0",
    "xml": "generic.xml@1.0.0",
    "runtime": f"runtime.compose.{RUN_ID}@1.0.0",
}
PAYLOADS = {
    "cli": (b"nebula-ssh enable\n", b"hostname edge\n", ArtifactContentFamily.TEXT, ArtifactEvidenceType.CONFIGURATION),
    "json": (
        json.dumps({"management": {"ssh": {"enabled": True}}}).encode(),
        json.dumps({"management": {"ssh": {"port": 22}}}).encode(),
        ArtifactContentFamily.JSON,
        ArtifactEvidenceType.STRUCTURED_EXPORT,
    ),
    "xml": (
        b"<root><management><ssh><enabled/></ssh></management></root>",
        b"<root><management><ssh/></management></root>",
        ArtifactContentFamily.XML,
        ArtifactEvidenceType.STRUCTURED_EXPORT,
    ),
    "runtime": (b"! Fictitious NebulaOS version 1.0.0\nnebula-ssh enable\n", b"! Fictitious NebulaOS version 1.0.0\nhostname edge\n", ArtifactContentFamily.TEXT, ArtifactEvidenceType.CONFIGURATION),
}


def definition(kind: str) -> MappingDefinition:
    common = {
        "profile_applicability": {"profile_version_ids": [PROFILES[kind]]},
        "target_field_id": FACT,
        "scope_resolution": {"strategy": "device"},
        "negation_behavior": {"operation": "unsupported"},
        "removal_behavior": {"operation": "unsupported"},
        "default_behavior": {"operation": "unknown"},
        "examples": [],
    }
    if kind in {"cli", "runtime"}:
        examples = []
        for family, command, scope, expected in (
            ("positive", "nebula-ssh", "device", True),
            ("alternate_values", "nebula-ssh", "device", True),
            ("negative", "hostname", "device", False),
            ("wrong_scope", "nebula-ssh", "interface", False),
            ("negation", "nebula-ssh", "device", True),
            ("conflict", "nebula-ssh", "device", True),
            ("regression", "login", "device", False),
        ):
            examples.append({
                "family": family,
                "node": {"command": command, "arguments": ["enable"], "scope_type": scope, "negated": family == "negation"},
                "expected_match": expected,
                "expected_value": True if expected else None,
            })
        mapping = {
            **common,
            "structural_match": {"command": "nebula-ssh", "scope_type": "device", "arguments": [{"operation": "literal", "value": "enable"}]},
            "value_extraction": {"operation": "constant", "value": True, "output_type": "boolean"},
            "negation_behavior": {"operation": "emit_value"},
            "removal_behavior": {"operation": "remove_value"},
            "examples": examples,
        }
        if kind == "runtime":
            mapping["structural_match"]["arguments"] = [{"operation": "capture", "name": "state", "value_type": "string"}]
            mapping["value_extraction"] = {"operation": "enum_mapping", "capture": "state", "values": {"enable": True, "disable": False}, "output_type": "boolean"}
        return MappingDefinition.model_validate(mapping)
    if kind == "json":
        return MappingDefinition.model_validate({
            **common,
            "structural_match": {"operation": "json_path", "command": "json", "json_path": {"path": [{"key": "management"}, {"key": "ssh"}, {"key": "enabled"}], "source": "value", "capture": "enabled", "value_type": "boolean"}},
            "value_extraction": {"operation": "capture", "capture": "enabled", "output_type": "boolean"},
        })
    return MappingDefinition.model_validate({
        **common,
        "structural_match": {"operation": "xml_path", "command": "xml", "xml_path": {"path": [{"local_name": item, "occurrence": "exact"} for item in ("root", "management", "ssh", "enabled")], "source": "presence", "capture": None, "value_type": "boolean", "start_mode": "document_root"}},
        "value_extraction": {"operation": "boolean_from_presence", "capture": None, "output_type": "boolean"},
    })


def factory():
    return create_session_factory(create_database_engine(get_settings()))


def new_audit(session_factory, storage, organization_id, user_id, device_id, kind, body, label, *, queued: bool, assessment_pack_id=None):
    family, evidence = PAYLOADS[kind][2:]
    with session_factory.begin() as db:
        artifact_id = uuid4()
        artifact = Artifact(
            artifact_id=artifact_id, organization_id=organization_id,
            original_filename=f"{label}.{kind}",
            storage_reference=storage.write(body, organization_id=organization_id, artifact_id=artifact_id),
            byte_size=len(body), sha256=sha256(body).hexdigest(), encoding="utf-8",
            content_family=family, evidence_type=evidence, status=ArtifactStatus.READY,
            uploaded_by=user_id, source_metadata={"vendor_label": "Runtime proof", "os_label": kind},
        )
        snapshot = Snapshot(
            organization_id=organization_id, device_id=device_id,
            grouping_status=SnapshotGroupingStatus.MANUALLY_CONFIRMED,
            snapshot_hash=calculate_snapshot_hash([artifact.sha256]), artifact_count=1,
            source=SnapshotSource.UPLOAD, status=SnapshotStatus.LOCKED, created_by=user_id,
        )
        db.add(snapshot)
        db.flush()
        artifact.snapshot_id = snapshot.snapshot_id
        db.add(artifact)
        revision = (db.scalar(select(func.max(Audit.revision_number)).where(Audit.device_id == device_id)) or 0) + 1
        audit = Audit(
            organization_id=organization_id, device_id=device_id, snapshot_id=snapshot.snapshot_id,
            revision_number=revision, reevaluation_reason=AuditReevaluationReason.INITIAL,
            status=AuditStatus.QUEUED, selected_frameworks=[], version_refs=({"assessment_pack_version_id": str(assessment_pack_id)} if assessment_pack_id else {}),
            profile_resolution={}, verdict_counts={}, severity_counts={}, coverage={},
            created_by=user_id,
        )
        db.add(audit)
        db.flush()
        job = enqueue_job(db, JobType.AUDIT, audit_id=audit.audit_id, device_id=device_id) if queued else None
        return audit.audit_id, artifact_id, job.job_id if job else None


def wait_for_validation(session_factory, validation_id):
    for _ in range(90):
        with session_factory() as db:
            run = db.get(__import__("app.db.models", fromlist=["MappingValidationRun"]).MappingValidationRun, validation_id)
            if run.status.value in {"passed", "failed"}:
                assert run.status.value == "passed" and run.results.get("passed") is True, run.results
                return
        time.sleep(1)
    raise AssertionError("mapping validation job timed out")


def wait_for_audit(session_factory, audit_id):
    for _ in range(90):
        with session_factory() as db:
            audit = db.get(Audit, audit_id)
            job = db.scalar(select(Job).where(Job.audit_id == audit_id, Job.job_type == JobType.AUDIT))
            if job and job.status in {JobStatus.COMPLETED, JobStatus.FAILED}:
                assert job.status is JobStatus.COMPLETED and audit.status.value.startswith("completed"), job.error_message
                return audit
        time.sleep(1)
    raise AssertionError("audit job timed out")


def wait_for_report(session_factory, report_id):
    for _ in range(90):
        with session_factory() as db:
            report = db.get(Report, report_id)
            if report.status in {ReportStatus.READY, ReportStatus.FAILED}:
                assert report.status is ReportStatus.READY and report.byte_size > 0, report.failure_message
                return
        time.sleep(1)
    raise AssertionError("report job timed out")


def prepare():
    session_factory, storage = factory(), get_artifact_storage()
    for kind in PROFILES:
        slug = f"compose-restart-{RUN_ID}-{kind}"
        organization_id, user_id = bootstrap_admin(session_factory, f"Compose {kind}", slug, f"{slug}@example.invalid", "runtime-proof-password")
        other_id, _ = bootstrap_admin(session_factory, f"Compose {kind} other", f"{slug}-other", f"{slug}-other@example.invalid", "runtime-proof-password")
        with session_factory.begin() as db:
            device = Device(organization_id=organization_id, display_name=f"Compose {kind}")
            db.add(device)
            db.flush()
            device_id = device.device_id
            if kind == "runtime":
                profile_id = PROFILES[kind].split("@", 1)[0]
                raw = {"schema_version":"1.0.0","profile_id":profile_id,"profile_version":"1.0.0","profile_version_id":PROFILES[kind],"vendor":"Fictitious","product_family":"Nebula Edge","os":"NebulaOS","structural_reader":"indentation_cli.v1","evidence_types":["configuration"],"device_classes":["router"],"detection":{"tokens":["Fictitious","NebulaOS"]},"version_constraints":{"supported_major_versions":[1]},"capabilities":["structural_parsing","semantic_interpretation","effective_state_resolution","administrator_training"]}
                publish_runtime_profile(db, organization_id, parse_runtime_profile(json.dumps(raw).encode()), raw)
                print("runtime profile published")
        positive, negative, _, _ = PAYLOADS[kind]
        initial_id, positive_id, _ = new_audit(session_factory, storage, organization_id, user_id, device_id, kind, positive, "initial", queued=False)
        AuditPipelineCoordinator(session_factory, storage).run(initial_id, organization_id)
        with session_factory() as db:
            block = db.scalar(select(UnresolvedBlock).where(UnresolvedBlock.audit_id == initial_id))
            assert block is not None
            admin = db.get(User, user_id)
            mapping = create_mapping(db, admin, mapping_key=f"compose.{RUN_ID}.{kind}", title=f"Compose {kind}", description="restart acceptance", definition=definition(kind), unresolved_block_id=block.unresolved_block_id)
            negative_id = None
            if kind != "cli":
                _, negative_id, _ = new_audit(session_factory, storage, organization_id, user_id, device_id, kind, negative, "negative", queued=False)
            validation, _ = request_validation(db, admin, mapping.mapping_version_id, evidence_artifact_id=positive_id, negative_evidence_artifact_id=negative_id)
            mapping_id, validation_id = mapping.mapping_version_id, validation.validation_run_id
        wait_for_validation(session_factory, validation_id)
        with session_factory() as db:
            admin = db.get(User, user_id)
            approve_mapping(db, admin, mapping_id)
            _, pack = publish_mapping(db, admin, mapping_id)
            pack_id = pack.knowledge_pack_version_id
            assessment_pack_id = None
            if kind == "runtime":
                rule_payload = {"rule_id":"compose.runtime.ssh.enabled","profile_version_ids":[PROFILES[kind]],"canonical_field":FACT,"operator":"equals","expected":True,"title":"Nebula SSH enabled","security_domain":"management","severity":"high","framework_references":[]}
                publish_runtime_rule(db, organization_id, rule_payload)
                catalog_payload = {"schema_version":"1.0.0","pack_key":f"compose.runtime.{RUN_ID}","family":"Fictitious Runtime Framework","name":"Nebula controls","version":1,"source_version":"1","source_url":"https://example.invalid/nebula","profile_version_ids":[PROFILES[kind]],"obligations":[{"obligation_key":"NEB-SSH-1","control_id":"NEB-SSH-1","title":"Nebula SSH","severity":"high","scope":"device","assessment_method":"automatic","implementation_status":"implemented","evaluator_rule_id":"compose.runtime.ssh.enabled","policy_parameters":{}}]}
                catalog = parse_runtime_catalog(json.dumps(catalog_payload).encode(), "nebula.json", profile_lookup=lambda value: profile_for(db, organization_id, value), rule_lookup=lambda rule_id, profile_id: runtime_rule_for(db, organization_id, rule_id, profile_id))
                assessment_pack_id = publish_runtime_catalog(db, organization_id, catalog, "nebula.json").assessment_pack_version_id
                print("runtime rule published\nassessment pack published")
            assert load_active_published_knowledge_pack(db, other_id, PROFILES[kind]) is None
        before_id, _, _ = new_audit(session_factory, storage, organization_id, user_id, device_id, kind, positive, "before-restart", queued=True, assessment_pack_id=assessment_pack_id)
        wait_for_audit(session_factory, before_id)
        with session_factory() as db:
            audit = db.get(Audit, before_id)
            assert audit.version_refs["knowledge_pack_version_id"] == str(pack_id)
    print("prepared", RUN_ID)


def verify():
    session_factory, storage = factory(), get_artifact_storage()
    for kind in PROFILES:
        slug = f"compose-restart-{RUN_ID}-{kind}"
        with session_factory() as db:
            organization = db.scalar(select(Organization).where(Organization.slug == slug))
            user = db.scalar(select(User).where(User.organization_id == organization.organization_id))
            device = db.scalar(select(Device).where(Device.organization_id == organization.organization_id))
            published = list(db.scalars(select(MappingVersion).where(MappingVersion.organization_id == organization.organization_id, MappingVersion.status == "published")))
            assert len(published) == 1
            mapping_id = published[0].mapping_version_id
            pack_id = published[0].knowledge_pack_version_id
            assessment_pack_id = next((item.assessment_pack_version_id for item in db.scalars(select(AssessmentPackVersion).where(AssessmentPackVersion.organization_id == organization.organization_id)) if PROFILES[kind] in item.profile_version_ids), None)
        positive, negative, _, _ = PAYLOADS[kind]
        audit_id, _, _ = new_audit(session_factory, storage, organization.organization_id, user.user_id, device.device_id, kind, positive, "after-restart", queued=True, assessment_pack_id=assessment_pack_id)
        wait_for_audit(session_factory, audit_id)
        missing_id, _, _ = new_audit(session_factory, storage, organization.organization_id, user.user_id, device.device_id, kind, negative, "missing-after-restart", queued=True, assessment_pack_id=assessment_pack_id)
        fail_id = None
        if kind == "runtime":
            fail_id, _, _ = new_audit(session_factory, storage, organization.organization_id, user.user_id, device.device_id, kind, b"! Fictitious NebulaOS version 1.0.0\nnebula-ssh disable\n", "fail-after-restart", queued=True, assessment_pack_id=assessment_pack_id)
            wait_for_audit(session_factory, fail_id)
        wait_for_audit(session_factory, missing_id)
        with session_factory() as db:
            audit = db.get(Audit, audit_id)
            fact = db.scalar(select(SecurityFact).where(SecurityFact.audit_id == audit_id, SecurityFact.field_id == FACT))
            finding = db.scalar(select(Finding).where(Finding.audit_id == audit_id, Finding.rule_id == RULE))
            missing = db.scalar(select(Finding).where(Finding.audit_id == missing_id, Finding.rule_id == RULE))
            assert audit.version_refs["knowledge_pack_version_id"] == str(pack_id)
            assert fact.mapping_version_id == mapping_id
            assert finding.verdict is FindingVerdict.PASS
            assert missing.verdict is FindingVerdict.UNKNOWN
            if kind == "runtime":
                assert audit.profile_resolution["profile_version_id"] == PROFILES[kind]
                result = db.scalar(select(AssessmentResult).where(AssessmentResult.audit_id == audit_id))
                missing_result = db.scalar(select(AssessmentResult).where(AssessmentResult.audit_id == missing_id))
                fail_result = db.scalar(select(AssessmentResult).where(AssessmentResult.audit_id == fail_id))
                assert result.verdict == "pass" and fail_result.verdict == "fail" and missing_result.verdict == "unknown"
                report, _ = create_report(db, user, audit_id)
                report_id = report.report_id
        if kind == "runtime":
            wait_for_report(session_factory, report_id)
            with session_factory() as db:
                report = db.get(Report, report_id)
                assert report.storage_reference and report.sha256 and report.byte_size > 0
                print("report generated")
        with session_factory() as db:
            if kind == "runtime":
                print("PASS confirmed\nFAIL confirmed\nUNKNOWN confirmed\npersisted runtime objects reused")
        print(kind, "PASS", pack_id)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"prepare", "verify"}:
        raise SystemExit("usage: compose_restart_reuse.py prepare|verify")
    {"prepare": prepare, "verify": verify}[sys.argv[1]]()
