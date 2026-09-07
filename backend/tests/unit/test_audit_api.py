from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.models import (
    Artifact,
    Audit,
    AuditReevaluationReason,
    AuditStatus,
    Job,
    JobStatus,
    JobType,
    KnowledgePackRecord,
    KnowledgePackVersionRecord,
    MappingStatus,
    MappingVersion,
    MappingValidationRun,
    UnresolvedBlock,
    Snapshot,
    SnapshotStatus,
    User,
    UserRole,
)
from app.db.models.common import utc_now
from app.db.session import get_db
from app.ingestion.storage import LocalFilesystemArtifactStorage, get_artifact_storage
from app.jobs.errors import JobError
from app.jobs.runner import PRODUCTION_HANDLERS, WorkerRuntime
from app.jobs.service import enqueue_job
from app.main import create_app
from app.training.dsl import MappingDefinition
from app.training.service import approve_mapping, create_mapping, execute_validation, publish_mapping, request_validation


PROFILE_VERSION_ID = "cisco.ios_xe.17@1.0.0"
INCOMPATIBLE_PROFILE_VERSION_ID = "cisco.ios_xe.16@1.0.0"


@pytest.fixture
def audit_context(workflow_factory, auth_settings, tmp_path):
    first = bootstrap_admin(
        workflow_factory, "Audit A", "audit-a", "audit-a@example.invalid", "test-password"
    )
    second = bootstrap_admin(
        workflow_factory, "Audit B", "audit-b", "audit-b@example.invalid", "test-password"
    )
    storage = LocalFilesystemArtifactStorage(tmp_path / "artifacts")
    application = create_app(auth_settings)
    application.dependency_overrides[get_settings] = lambda: auth_settings
    application.dependency_overrides[get_artifact_storage] = lambda: storage

    def session_dependency():
        with workflow_factory() as db:
            yield db

    application.dependency_overrides[get_db] = session_dependency
    with TestClient(application) as client:
        yield client, workflow_factory, application, first, second


def login(client, email="audit-a@example.invalid"):
    response = client.post(
        "/api/v1/auth/login", json={"email": email, "password": "test-password"}
    )
    assert response.status_code == 200


def ready_snapshot(client):
    device = client.post("/api/v1/devices", json={"display_name": "Audit Device"}).json()
    snapshot = client.post(
        f"/api/v1/devices/{device['device_id']}/snapshots", json={}
    ).json()
    artifact = client.post("/api/v1/artifacts/upload", files={
        "file": ("audit.cfg", b"hostname audit\n", "text/plain")
    }).json()
    assert client.post(
        f"/api/v1/snapshots/{snapshot['snapshot_id']}/artifacts/{artifact['artifact_id']}"
    ).status_code == 200
    finalized = client.post(f"/api/v1/snapshots/{snapshot['snapshot_id']}/finalize")
    assert finalized.status_code == 200
    return device, finalized.json(), artifact


def create_audit(client, snapshot_id, **extra):
    return client.post("/api/v1/audits", json={
        "snapshot_id": snapshot_id, "selected_frameworks": ["future-framework"], **extra
    })


def mapping_definition(
    profile_version_ids: list[str], *, command: str = "idle-timeout", target_field_id: str = "management.session.idle_timeout"
) -> MappingDefinition:
    examples = []
    for family, example_command, expected in (
        ("positive", "idle-timeout", True),
        ("alternate_values", "idle-timeout", True),
        ("negative", "hostname", False),
        ("wrong_scope", "idle-timeout", False),
        ("negation", "idle-timeout", True),
        ("conflict", "idle-timeout", True),
        ("regression", "login", False),
    ):
        node = {
            "command": example_command,
            "arguments": ["5", "0"],
            "parent_command": "line" if family != "wrong_scope" else "interface",
            "scope_type": "vty_range",
            "negated": family == "negation",
        }
        examples.append({"family": family, "node": node, "expected_match": expected, "expected_value": 300.0 if expected else None})
    return MappingDefinition.model_validate({
        "profile_applicability": {"profile_version_ids": profile_version_ids},
        "structural_match": {
            "command": command,
            "parent_command": "line",
            "scope_type": "vty_range",
            "arguments": [
                {"operation": "capture", "name": "minutes", "value_type": "integer"},
                {"operation": "capture", "name": "seconds", "value_type": "integer"},
            ],
        },
        "target_field_id": target_field_id,
        "value_extraction": {"operation": "duration_from_parts", "parts": ["minutes", "seconds"], "output_type": "duration"},
        "scope_resolution": {"strategy": "vty_range"},
        "negation_behavior": {"operation": "reset_to_default"},
        "removal_behavior": {"operation": "remove_value"},
        "default_behavior": {"operation": "unknown"},
        "examples": examples,
    })


def ensure_training_tables(db) -> None:
    bind = db.get_bind()
    for table in (
        KnowledgePackRecord.__table__,
        KnowledgePackVersionRecord.__table__,
        MappingVersion.__table__,
        MappingValidationRun.__table__,
        UnresolvedBlock.__table__,
    ):
        table.create(bind=bind, checkfirst=True)


def publish_compatible_pack(
    db,
    admin,
    *,
    mapping_key: str = "iosxe.idle-timeout.compatible",
    command: str = "idle-timeout",
    target_field_id: str = "management.session.idle_timeout",
):
    ensure_training_tables(db)
    mapping = create_mapping(
        db,
        admin,
        mapping_key=mapping_key,
        title="Idle timeout",
        description="Compatible published mapping",
        definition=mapping_definition([PROFILE_VERSION_ID], command=command, target_field_id=target_field_id),
    )
    mapping.status = MappingStatus.PUBLISHED
    mapping.published_at = utc_now()
    pack = KnowledgePackRecord(
        organization_id=admin.organization_id,
        pack_key=mapping_key,
        name="Compatible pack",
    )
    db.add(pack)
    db.flush()
    version = KnowledgePackVersionRecord(
        knowledge_pack_id=pack.knowledge_pack_id,
        organization_id=admin.organization_id,
        version=1,
        previous_knowledge_pack_version_id=None,
        mapping_version_ids=[str(mapping.mapping_version_id)],
        published_by=admin.user_id,
    )
    db.add(version)
    db.flush()
    mapping.knowledge_pack_version_id = version.knowledge_pack_version_id
    db.commit()
    return mapping, version


def publish_incompatible_pack(db, admin, *, mapping_key: str = "iosxe.idle-timeout.incompatible"):
    ensure_training_tables(db)
    mapping = create_mapping(
        db,
        admin,
        mapping_key=mapping_key,
        title="Idle timeout incompatible",
        description="Published mapping for an incompatible pack",
        definition=mapping_definition([INCOMPATIBLE_PROFILE_VERSION_ID]),
    )
    mapping.status = MappingStatus.PUBLISHED
    mapping.published_at = utc_now()
    pack = KnowledgePackRecord(
        organization_id=admin.organization_id,
        pack_key=mapping_key,
        name="Incompatible pack",
    )
    db.add(pack)
    db.flush()
    version = KnowledgePackVersionRecord(
        knowledge_pack_id=pack.knowledge_pack_id,
        organization_id=admin.organization_id,
        version=1,
        previous_knowledge_pack_version_id=None,
        mapping_version_ids=[str(mapping.mapping_version_id)],
        published_by=admin.user_id,
    )
    db.add(version)
    db.flush()
    mapping.knowledge_pack_version_id = version.knowledge_pack_version_id
    db.commit()
    return mapping, version


def seed_completed_source_audit(db, *, organization_id, user_id, device_id, snapshot_id, current_pack_id: UUID | None = None):
    source = Audit(
        organization_id=organization_id,
        device_id=device_id,
        snapshot_id=snapshot_id,
        revision_number=1,
        previous_audit_id=None,
        reevaluation_reason=AuditReevaluationReason.INITIAL,
        status=AuditStatus.COMPLETED_WITH_UNKNOWNS,
        processing_stage=None,
        selected_frameworks=["future-framework"],
        version_refs={
            **({"knowledge_pack_version_id": str(current_pack_id)} if current_pack_id is not None else {}),
            "device_profile_version_id": PROFILE_VERSION_ID,
        },
        profile_resolution={"profile_version_id": PROFILE_VERSION_ID, "resolution_status": "resolved"},
        verdict_counts={"unknown": 1},
        severity_counts={},
        coverage={},
        started_at=utc_now(),
        completed_at=utc_now(),
        created_by=user_id,
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


def count_audit_revisions(db, snapshot_id: UUID) -> int:
    return db.scalar(select(func.count()).select_from(Audit).where(Audit.snapshot_id == snapshot_id))


def count_reevaluation_jobs(db) -> int:
    return db.scalar(select(func.count()).select_from(Job).where(Job.job_type == JobType.RE_EVALUATION))


def test_audit_endpoints_require_authentication(audit_context):
    client = audit_context[0]
    assert client.get("/api/v1/audits").status_code == 401
    assert client.post("/api/v1/audits", json={"snapshot_id": str(uuid4())}).status_code == 401
    assert client.get(f"/api/v1/jobs/{uuid4()}").status_code == 401


def test_create_initial_audit_is_honest_and_does_not_lock_snapshot(audit_context):
    client, _, _, (organization_id, user_id), _ = audit_context
    login(client)
    device, snapshot, _ = ready_snapshot(client)
    response = create_audit(client, snapshot["snapshot_id"])
    assert response.status_code == 201
    body = response.json()
    assert body["organization_id"] == str(organization_id)
    assert body["device_id"] == device["device_id"]
    assert body["snapshot_id"] == snapshot["snapshot_id"]
    assert body["created_by"] == str(user_id)
    assert body["revision_number"] == 1
    assert body["previous_audit_id"] is None
    assert body["audit_batch_id"] is None
    assert body["reevaluation_reason"] == "initial"
    assert body["status"] == "draft" and body["processing_stage"] is None
    assert body["started_at"] is None and body["completed_at"] is None
    assert body["selected_frameworks"] == ["future-framework"]
    assert body["version_refs"] == body["profile_resolution"] == {}
    assert body["verdict_counts"] == body["severity_counts"] == body["coverage"] == {}
    assert body["job"] is None
    assert client.get(f"/api/v1/snapshots/{snapshot['snapshot_id']}").json()["status"] == "ready"
    assert create_audit(client, snapshot["snapshot_id"]).status_code == 409
    listed = client.get("/api/v1/audits").json()
    assert [item["audit_id"] for item in listed] == [body["audit_id"]]
    assert client.get(f"/api/v1/audits/{body['audit_id']}").status_code == 200


def test_create_rejects_protected_fields_and_non_ready_snapshots(audit_context):
    client, factory, *_ = audit_context
    login(client)
    device = client.post("/api/v1/devices", json={"display_name": "Draft"}).json()
    draft = client.post(f"/api/v1/devices/{device['device_id']}/snapshots", json={}).json()
    assert create_audit(client, draft["snapshot_id"]).status_code == 409
    _, ready, _ = ready_snapshot(client)
    assert create_audit(client, ready["snapshot_id"], status="queued").status_code == 422
    for state in (SnapshotStatus.LOCKED, SnapshotStatus.ARCHIVED):
        with factory.begin() as db:
            db.execute(update(Snapshot).where(
                Snapshot.snapshot_id == UUID(ready["snapshot_id"])
            ).values(status=state))
        assert create_audit(client, ready["snapshot_id"]).status_code == 409


def test_run_atomically_locks_snapshot_and_enqueues_truthful_job(audit_context):
    client, factory, *_ = audit_context
    login(client)
    _, snapshot, artifact = ready_snapshot(client)
    audit = create_audit(client, snapshot["snapshot_id"]).json()
    response = client.post(f"/api/v1/audits/{audit['audit_id']}/run")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "queued"
    assert body["processing_stage"] is None
    assert body["started_at"] is None and body["completed_at"] is None
    job = body["job"]
    assert job["job_type"] == "audit" and job["status"] == "queued"
    assert job["progress"] == 0 and job["attempt_count"] == 0
    assert job["stage"] is None and job["started_at"] is None
    assert client.get(f"/api/v1/snapshots/{snapshot['snapshot_id']}").json()["status"] == "locked"
    assert client.patch(
        f"/api/v1/snapshots/{snapshot['snapshot_id']}", json={"label": "changed"}
    ).status_code == 409
    assert client.delete(
        f"/api/v1/snapshots/{snapshot['snapshot_id']}/artifacts/{artifact['artifact_id']}"
    ).status_code == 409
    repeated = client.post(f"/api/v1/audits/{audit['audit_id']}/run")
    assert repeated.status_code == 409
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Job).where(
            Job.audit_id == UUID(audit["audit_id"])
        )) == 1


def test_queue_failure_rolls_back_audit_and_snapshot(audit_context, monkeypatch):
    client, factory, _, *_ = audit_context
    login(client)
    _, snapshot, _ = ready_snapshot(client)
    audit = create_audit(client, snapshot["snapshot_id"]).json()

    def fail_enqueue(*_args, **_kwargs):
        raise JobError("private queue detail")

    monkeypatch.setattr("app.audit.service.enqueue_job", fail_enqueue)
    response = client.post(f"/api/v1/audits/{audit['audit_id']}/run")
    assert response.status_code == 503
    assert "private" not in response.text
    with factory() as db:
        persisted_audit = db.get(Audit, UUID(audit["audit_id"]))
        persisted_snapshot = db.get(Snapshot, UUID(snapshot["snapshot_id"]))
        assert persisted_audit.status == AuditStatus.DRAFT
        assert persisted_snapshot.status == SnapshotStatus.READY
        assert db.scalar(select(func.count()).select_from(Job).where(
            Job.audit_id == persisted_audit.audit_id
        )) == 0


def test_audit_and_job_retrieval_are_tenant_scoped_and_payload_hidden(audit_context):
    client, factory, *_ = audit_context
    login(client)
    _, snapshot, _ = ready_snapshot(client)
    audit = create_audit(client, snapshot["snapshot_id"]).json()
    queued = client.post(f"/api/v1/audits/{audit['audit_id']}/run").json()
    job_id = queued["job"]["job_id"]
    own_job = client.get(f"/api/v1/jobs/{job_id}")
    assert own_job.status_code == 200
    assert "payload" not in own_job.json()
    with factory.begin() as db:
        system_job_id = enqueue_job(
            db, JobType.SYSTEM_NOOP, payload={"secret": "must-not-be-exposed"}
        ).job_id
    assert client.get(f"/api/v1/jobs/{system_job_id}").status_code == 404
    client.cookies.clear()
    login(client, "audit-b@example.invalid")
    assert client.get(f"/api/v1/audits/{audit['audit_id']}").status_code == 404
    assert client.post(f"/api/v1/audits/{audit['audit_id']}/run").status_code == 404
    assert client.get(f"/api/v1/jobs/{job_id}").status_code == 404
    assert client.get("/api/v1/audits").json() == []


def test_current_worker_leaves_created_audit_job_queued(audit_context):
    client, factory, *_ = audit_context
    login(client)
    _, snapshot, _ = ready_snapshot(client)
    audit = create_audit(client, snapshot["snapshot_id"]).json()
    job_id = UUID(client.post(f"/api/v1/audits/{audit['audit_id']}/run").json()["job"]["job_id"])
    runtime = WorkerRuntime(factory, handlers=PRODUCTION_HANDLERS, poll_interval_seconds=1.0)
    assert JobType.AUDIT not in runtime.supported_job_types
    assert runtime.run_iteration() is False
    with factory() as db:
        job = db.get(Job, job_id)
        assert job.status == JobStatus.QUEUED
        assert job.attempt_count == 0 and job.started_at is None


def test_analyst_cannot_start_reevaluation(audit_context):
    client, factory, _, (_, user_id), _ = audit_context
    login(client)
    _, snapshot, _ = ready_snapshot(client)
    audit = create_audit(client, snapshot["snapshot_id"]).json()
    with factory.begin() as db:
        db.get(User, user_id).role = UserRole.ANALYST
    response = client.post(f"/api/v1/audits/{audit['audit_id']}/re-evaluate", json={"knowledge_pack_version_id": str(uuid4())})
    assert response.status_code == 403


def test_reevaluation_eligibility_hides_cross_tenant_and_missing_audits(audit_context):
    client, _, _, _, _ = audit_context
    login(client)
    _, snapshot, _ = ready_snapshot(client)
    audit = create_audit(client, snapshot["snapshot_id"]).json()
    client.cookies.clear(); login(client, "audit-b@example.invalid")
    for audit_id in (audit["audit_id"], str(uuid4())):
        assert client.get(f"/api/v1/audits/{audit_id}/reevaluation-eligibility").status_code == 404
        assert client.post(f"/api/v1/audits/{audit_id}/re-evaluate", json={"knowledge_pack_version_id": str(uuid4())}).status_code == 404


def test_nonterminal_audit_is_not_eligible_and_creates_no_revision(audit_context):
    client, factory, _, _, _ = audit_context
    login(client)
    _, snapshot, _ = ready_snapshot(client)
    audit = create_audit(client, snapshot["snapshot_id"]).json()
    eligibility = client.get(f"/api/v1/audits/{audit['audit_id']}/reevaluation-eligibility")
    assert eligibility.status_code == 200
    assert eligibility.json()["eligible"] is False and eligibility.json()["reason"] == "source_audit_not_completed"
    rejected = client.post(f"/api/v1/audits/{audit['audit_id']}/re-evaluate", json={"knowledge_pack_version_id": str(uuid4())})
    assert rejected.status_code == 409 and rejected.json()["detail"]["code"] == "reevaluation_unavailable"
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Audit).where(Audit.snapshot_id == UUID(snapshot["snapshot_id"]))) == 1


def test_pre_publication_mapping_is_excluded_from_eligibility_and_re_evaluation(audit_context):
    client, factory, _, (_, user_id), _ = audit_context
    login(client)
    device, snapshot, _ = ready_snapshot(client)
    with factory() as db:
        admin = db.get(User, user_id)
        organization_id = admin.organization_id
        source = seed_completed_source_audit(
            db,
            organization_id=organization_id,
            user_id=admin.user_id,
            device_id=UUID(device["device_id"]),
            snapshot_id=UUID(snapshot["snapshot_id"]),
        )
        _published, pack = publish_compatible_pack(db, admin)
        draft = create_mapping(
            db,
            admin,
            mapping_key="iosxe.idle-timeout.draft",
            title="Draft mapping",
            description="Pre-publication mapping that must stay invisible",
            definition=mapping_definition([PROFILE_VERSION_ID]),
        )
        source_id = source.audit_id
        pack_id = pack.knowledge_pack_version_id
        draft_id = draft.mapping_version_id
    with factory() as db:
        before_revisions = count_audit_revisions(db, UUID(snapshot["snapshot_id"]))
        before_jobs = count_reevaluation_jobs(db)
    eligibility = client.get(f"/api/v1/audits/{source_id}/reevaluation-eligibility")
    assert eligibility.status_code == 200
    body = eligibility.json()
    assert body["eligible"] is True
    assert [item["knowledge_pack_version_id"] for item in body["candidates"]] == [str(pack_id)]
    with factory() as db:
        packs = list(db.scalars(select(KnowledgePackVersionRecord).where(KnowledgePackVersionRecord.organization_id == organization_id)))
        assert not any(str(draft_id) in item.mapping_version_ids for item in packs)
    rejected = client.post(
        f"/api/v1/audits/{source_id}/re-evaluate",
        json={"knowledge_pack_version_id": str(draft_id)},
    )
    assert rejected.status_code == 422
    assert rejected.json()["detail"]["code"] == "knowledge_pack_ineligible"
    with factory() as db:
        assert count_audit_revisions(db, UUID(snapshot["snapshot_id"])) == before_revisions
        assert count_reevaluation_jobs(db) == before_jobs


def test_invalid_target_uuid_is_rejected_even_with_a_real_candidate(audit_context):
    client, factory, _, (_, user_id), _ = audit_context
    login(client)
    device, snapshot, _ = ready_snapshot(client)
    with factory() as db:
        admin = db.get(User, user_id)
        source = seed_completed_source_audit(
            db,
            organization_id=admin.organization_id,
            user_id=admin.user_id,
            device_id=UUID(device["device_id"]),
            snapshot_id=UUID(snapshot["snapshot_id"]),
        )
        published, _pack = publish_compatible_pack(db, admin, mapping_key="iosxe.idle-timeout.real-candidate")
        source_id = source.audit_id
        published_id = published.knowledge_pack_version_id
    eligibility = client.get(f"/api/v1/audits/{source_id}/reevaluation-eligibility")
    assert eligibility.status_code == 200
    assert eligibility.json()["eligible"] is True
    assert [item["knowledge_pack_version_id"] for item in eligibility.json()["candidates"]] == [str(published_id)]
    with factory() as db:
        before_revisions = count_audit_revisions(db, UUID(snapshot["snapshot_id"]))
        before_jobs = count_reevaluation_jobs(db)
    rejected = client.post(
        f"/api/v1/audits/{source_id}/re-evaluate",
        json={"knowledge_pack_version_id": str(uuid4())},
    )
    assert rejected.status_code == 422
    assert rejected.json()["detail"]["code"] == "knowledge_pack_ineligible"
    with factory() as db:
        assert count_audit_revisions(db, UUID(snapshot["snapshot_id"])) == before_revisions
        assert count_reevaluation_jobs(db) == before_jobs


def test_incompatible_profile_pack_is_excluded_and_rejected(audit_context):
    client, factory, _, (_, user_id), _ = audit_context
    login(client)
    device, snapshot, _ = ready_snapshot(client)
    with factory() as db:
        admin = db.get(User, user_id)
        source = seed_completed_source_audit(
            db,
            organization_id=admin.organization_id,
            user_id=admin.user_id,
            device_id=UUID(device["device_id"]),
            snapshot_id=UUID(snapshot["snapshot_id"]),
        )
        compatible, _ = publish_compatible_pack(db, admin, mapping_key="iosxe.idle-timeout.compatible")
        incompatible, _ = publish_incompatible_pack(db, admin, mapping_key="iosxe.idle-timeout.incompatible")
        source_id = source.audit_id
        compatible_id = compatible.knowledge_pack_version_id
        incompatible_id = incompatible.knowledge_pack_version_id
    eligibility = client.get(f"/api/v1/audits/{source_id}/reevaluation-eligibility")
    assert eligibility.status_code == 200
    candidate_ids = [item["knowledge_pack_version_id"] for item in eligibility.json()["candidates"]]
    assert candidate_ids == [str(compatible_id)]
    assert str(incompatible_id) not in candidate_ids
    with factory() as db:
        before_revisions = count_audit_revisions(db, UUID(snapshot["snapshot_id"]))
        before_jobs = count_reevaluation_jobs(db)
    rejected = client.post(
        f"/api/v1/audits/{source_id}/re-evaluate",
        json={"knowledge_pack_version_id": str(incompatible_id)},
    )
    assert rejected.status_code == 422
    assert rejected.json()["detail"]["code"] == "knowledge_pack_ineligible"
    with factory() as db:
        assert count_audit_revisions(db, UUID(snapshot["snapshot_id"])) == before_revisions
        assert count_reevaluation_jobs(db) == before_jobs


def test_same_current_pack_is_excluded_from_eligibility_and_rejected(audit_context):
    client, factory, _, (_, user_id), _ = audit_context
    login(client)
    device, snapshot, _ = ready_snapshot(client)
    with factory() as db:
        admin = db.get(User, user_id)
        current, _ = publish_compatible_pack(db, admin, mapping_key="iosxe.idle-timeout.current")
        source = seed_completed_source_audit(
            db,
            organization_id=admin.organization_id,
            user_id=admin.user_id,
            device_id=UUID(device["device_id"]),
            snapshot_id=UUID(snapshot["snapshot_id"]),
            current_pack_id=current.knowledge_pack_version_id,
        )
        newer, _ = publish_compatible_pack(
            db,
            admin,
            mapping_key="iosxe.idle-timeout.current-v2",
            command="exec-timeout",
        )
        source_id = source.audit_id
        current_id = current.knowledge_pack_version_id
        newer_id = newer.knowledge_pack_version_id
    eligibility = client.get(f"/api/v1/audits/{source_id}/reevaluation-eligibility")
    assert eligibility.status_code == 200
    candidate_ids = [item["knowledge_pack_version_id"] for item in eligibility.json()["candidates"]]
    assert str(current_id) not in candidate_ids
    assert candidate_ids == [str(newer_id)]
    with factory() as db:
        before_revisions = count_audit_revisions(db, UUID(snapshot["snapshot_id"]))
        before_jobs = count_reevaluation_jobs(db)
    rejected = client.post(
        f"/api/v1/audits/{source_id}/re-evaluate",
        json={"knowledge_pack_version_id": str(current_id)},
    )
    assert rejected.status_code == 422
    assert rejected.json()["detail"]["code"] == "knowledge_pack_ineligible"
    with factory() as db:
        assert count_audit_revisions(db, UUID(snapshot["snapshot_id"])) == before_revisions
        assert count_reevaluation_jobs(db) == before_jobs


def test_invalid_source_evidence_blocks_eligibility_and_re_evaluation(audit_context):
    client, factory, _, (_, user_id), _ = audit_context
    login(client)
    device, snapshot, _artifact = ready_snapshot(client)
    with factory() as db:
        admin = db.get(User, user_id)
        organization_id = admin.organization_id
        source = seed_completed_source_audit(
            db,
            organization_id=organization_id,
            user_id=admin.user_id,
            device_id=UUID(device["device_id"]),
            snapshot_id=UUID(snapshot["snapshot_id"]),
        )
        candidate, _ = publish_compatible_pack(db, admin, mapping_key="iosxe.idle-timeout.evidence")
        source_id = source.audit_id
        candidate_id = candidate.knowledge_pack_version_id
        db.execute(update(Snapshot).where(
            Snapshot.snapshot_id == UUID(snapshot["snapshot_id"])
        ).values(artifact_count=snapshot["artifact_count"] + 1))
        db.commit()
    eligibility = client.get(f"/api/v1/audits/{source_id}/reevaluation-eligibility")
    assert eligibility.status_code == 200
    body = eligibility.json()
    assert body["eligible"] is False
    assert body["reason"] == "source_evidence_unavailable"
    assert body["candidates"] == []
    with factory() as db:
        before_revisions = count_audit_revisions(db, UUID(snapshot["snapshot_id"]))
        before_jobs = count_reevaluation_jobs(db)
        before_snapshot_count = db.scalar(select(func.count()).select_from(Snapshot).where(Snapshot.organization_id == organization_id))
        before_artifact_count = db.scalar(select(func.count()).select_from(Artifact).where(Artifact.snapshot_id == UUID(snapshot["snapshot_id"])))
    rejected = client.post(
        f"/api/v1/audits/{source_id}/re-evaluate",
        json={"knowledge_pack_version_id": str(candidate_id)},
    )
    assert rejected.status_code == 409
    assert rejected.json()["detail"]["code"] == "reevaluation_unavailable"
    with factory() as db:
        assert count_audit_revisions(db, UUID(snapshot["snapshot_id"])) == before_revisions
        assert count_reevaluation_jobs(db) == before_jobs
        assert db.scalar(select(func.count()).select_from(Snapshot).where(Snapshot.organization_id == organization_id)) == before_snapshot_count
        assert db.scalar(select(func.count()).select_from(Artifact).where(Artifact.snapshot_id == UUID(snapshot["snapshot_id"]))) == before_artifact_count
