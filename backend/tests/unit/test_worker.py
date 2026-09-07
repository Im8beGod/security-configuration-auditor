import logging
from threading import Event
from uuid import uuid4

from sqlalchemy import event
from sqlalchemy.exc import OperationalError

from app.db.models import Job, JobStatus, JobType
from app.jobs.handlers.pdf_generation import handle_pdf_generation
from app.jobs.handlers.mapping_validation import handle_mapping_validation
from app.jobs.handlers.reevaluation import handle_reevaluation
from app.jobs.handlers.system_noop import handle_system_noop
from app.jobs.runner import PRODUCTION_HANDLERS, WorkerRuntime
from app.jobs.service import enqueue_job


def test_production_handlers_are_explicit_and_noop_is_side_effect_free():
    job_id = uuid4()
    assert handle_system_noop(job_id) is None
    assert PRODUCTION_HANDLERS == {JobType.SYSTEM_NOOP: handle_system_noop, JobType.PDF_GENERATION: handle_pdf_generation, JobType.MAPPING_VALIDATION: handle_mapping_validation, JobType.RE_EVALUATION: handle_reevaluation}


def test_production_runtime_waits_when_only_unsupported_jobs_exist(job_factory):
    with job_factory.begin() as db:
        job_id = enqueue_job(db, JobType.AUDIT).job_id
    waits = []
    shutdown = Event()

    def wait(interval):
        waits.append(interval)
        shutdown.set()
        return True

    runtime = WorkerRuntime(
        job_factory, handlers=PRODUCTION_HANDLERS, poll_interval_seconds=1.25,
        shutdown_event=shutdown, wait=wait,
    )
    assert runtime.supported_job_types == frozenset({JobType.SYSTEM_NOOP, JobType.PDF_GENERATION, JobType.MAPPING_VALIDATION, JobType.RE_EVALUATION})
    runtime.run_forever()
    assert waits == [1.25]
    with job_factory() as db:
        job = db.get(Job, job_id)
        assert job.status == JobStatus.QUEUED and job.attempt_count == 0


def test_iteration_filters_claim_commits_closes_then_calls_handler(
    job_factory, monkeypatch
):
    with job_factory.begin() as db:
        audit_id = enqueue_job(db, JobType.AUDIT).job_id
        noop_id = enqueue_job(db, JobType.SYSTEM_NOOP).job_id

    close_count = 0
    original_close = job_factory.class_.close

    def tracked_close(session):
        nonlocal close_count
        close_count += 1
        return original_close(session)

    monkeypatch.setattr(job_factory.class_, "close", tracked_close)
    observed = []

    def test_handler(job_id):
        assert close_count >= 1
        with job_factory.begin() as db:
            job = db.get(Job, job_id)
            observed.append((job.job_id, job.status, job.attempt_count))

    runtime = WorkerRuntime(
        job_factory,
        handlers={JobType.SYSTEM_NOOP: test_handler},
        poll_interval_seconds=1.0,
    )
    assert runtime.run_iteration() is True
    assert observed == [(noop_id, JobStatus.PROCESSING, 1)]
    assert close_count >= 2
    with job_factory() as db:
        assert db.get(Job, audit_id).status == JobStatus.QUEUED
        assert db.get(Job, audit_id).attempt_count == 0
        completed = db.get(Job, noop_id)
        assert completed.status == JobStatus.COMPLETED
        assert completed.progress == 100
        assert completed.attempt_count == 1
        assert completed.started_at is not None
        assert completed.completed_at is not None
        assert completed.error_code is None and completed.error_message is None


def test_handler_failure_is_sanitized_and_persisted_in_fresh_session(
    job_factory, caplog
):
    with job_factory.begin() as db:
        job_id = enqueue_job(db, JobType.SYSTEM_NOOP).job_id

    def failing_handler(_job_id):
        raise RuntimeError("password=not-for-logs\ntraceback-like-secret")

    runtime = WorkerRuntime(
        job_factory,
        handlers={JobType.SYSTEM_NOOP: failing_handler},
        poll_interval_seconds=1.0,
    )
    with caplog.at_level(logging.ERROR, logger="app.jobs.runner"):
        assert runtime.run_iteration() is True

    with job_factory() as db:
        failed = db.get(Job, job_id)
        assert failed.status == JobStatus.FAILED
        assert failed.progress == 0
        assert failed.attempt_count == 1
        assert failed.started_at is not None
        assert failed.completed_at is not None
        assert failed.error_code == "handler_failed"
        assert failed.error_message == "Job handler execution failed"
    assert "password=" not in caplog.text
    assert "traceback-like-secret" not in caplog.text


def test_claim_failure_rolls_back_closes_logs_safely_and_loop_continues(
    job_factory, monkeypatch, caplog
):
    import app.jobs.runner as runner_module

    rollbacks = 0
    closes = 0

    @event.listens_for(job_factory.class_, "after_rollback")
    def tracked_rollback(_session):
        nonlocal rollbacks
        rollbacks += 1

    original_close = job_factory.class_.close

    def tracked_close(session):
        nonlocal closes
        closes += 1
        return original_close(session)

    monkeypatch.setattr(job_factory.class_, "close", tracked_close)
    calls = 0

    def failing_then_idle(_db, allowed_job_types=None):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OperationalError("statement containing password", {}, Exception("secret"))
        return None

    monkeypatch.setattr(runner_module, "claim_next_job", failing_then_idle)
    waits = 0

    def wait(_interval):
        nonlocal waits
        waits += 1
        return waits == 2

    runtime = WorkerRuntime(
        job_factory, handlers={JobType.SYSTEM_NOOP: lambda _job_id: None},
        poll_interval_seconds=1.0, wait=wait,
    )
    try:
        with caplog.at_level(logging.ERROR, logger="app.jobs.runner"):
            runtime.run_forever()
    finally:
        event.remove(job_factory.class_, "after_rollback", tracked_rollback)
    assert calls == 2 and waits == 2
    assert rollbacks == 1 and closes == 2
    assert "database claim failed" in caplog.text.lower()
    assert "password" not in caplog.text.lower()
    assert "secret" not in caplog.text.lower()


def test_shutdown_prevents_subsequent_claim(job_factory):
    with job_factory.begin() as db:
        job_id = enqueue_job(db, JobType.SYSTEM_NOOP).job_id
    shutdown = Event()
    runtime = WorkerRuntime(
        job_factory, handlers={JobType.SYSTEM_NOOP: lambda _job_id: None},
        poll_interval_seconds=1.0, shutdown_event=shutdown,
    )
    runtime.request_shutdown()
    assert runtime.run_iteration() is False
    with job_factory() as db:
        job = db.get(Job, job_id)
        assert job.status == JobStatus.QUEUED and job.attempt_count == 0


def test_runtime_rejects_busy_poll_intervals(job_factory):
    import pytest

    with pytest.raises(ValueError):
        WorkerRuntime(job_factory, handlers={}, poll_interval_seconds=0.05)
    with pytest.raises(ValueError):
        WorkerRuntime(job_factory, handlers={}, poll_interval_seconds=float("nan"))
