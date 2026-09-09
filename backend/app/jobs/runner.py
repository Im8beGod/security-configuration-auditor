import logging
import math
import os
import socket
from collections.abc import Callable, Mapping
from threading import Event, Thread
from types import MappingProxyType
from uuid import UUID, uuid4

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.db.session import get_session_factory
from app.jobs.enums import JobType
from app.ingestion.storage import create_artifact_storage
from app.jobs.handlers import AuditJobHandler, handle_mapping_validation, handle_pdf_generation, handle_reevaluation, handle_system_noop
from app.jobs.errors import InvalidJobTransitionError, JobLeaseLostError
from app.jobs.service import (
    claim_next_job,
    complete_job,
    fail_job,
    heartbeat_job,
    recover_stale_jobs,
)


logger = logging.getLogger(__name__)
JobHandler = Callable[[UUID], None]
PRODUCTION_HANDLERS: Mapping[JobType, JobHandler] = MappingProxyType(
    {
        JobType.SYSTEM_NOOP: handle_system_noop,
        JobType.PDF_GENERATION: handle_pdf_generation,
        JobType.MAPPING_VALIDATION: handle_mapping_validation,
        JobType.RE_EVALUATION: handle_reevaluation,
    }
)
HANDLER_FAILURE_CODE = "handler_failed"
HANDLER_FAILURE_MESSAGE = "Job handler execution failed"


class WorkerRuntime:
    """Persistent queue runner with short-lived claim transactions."""

    def __init__(
        self,
        factory: sessionmaker[Session],
        *,
        handlers: Mapping[JobType, JobHandler],
        poll_interval_seconds: float,
        lease_seconds: float = 60.0,
        heartbeat_interval_seconds: float = 15.0,
        lease_owner: str | None = None,
        shutdown_event: Event | None = None,
        wait: Callable[[float], bool] | None = None,
    ) -> None:
        if not math.isfinite(poll_interval_seconds) or poll_interval_seconds < 0.1:
            raise ValueError("Worker poll interval must be at least 0.1 seconds")
        if not math.isfinite(lease_seconds) or not 0 < lease_seconds <= 3600:
            raise ValueError("Worker job lease must be between 0 and 3600 seconds")
        if not math.isfinite(heartbeat_interval_seconds) or not 0 < heartbeat_interval_seconds < lease_seconds:
            raise ValueError("Worker heartbeat interval must be positive and shorter than the job lease")
        if any(not isinstance(job_type, JobType) for job_type in handlers):
            raise ValueError("Worker handlers must use explicit JobType keys")
        self._factory = factory
        self._handlers = dict(handlers)
        self._poll_interval_seconds = poll_interval_seconds
        self._lease_seconds = lease_seconds
        self._heartbeat_interval_seconds = heartbeat_interval_seconds
        self._lease_owner = lease_owner or _new_lease_owner()
        if not self._lease_owner.strip() or len(self._lease_owner) > 128:
            raise ValueError("Worker lease owner must contain 1 to 128 characters")
        self._shutdown_event = shutdown_event or Event()
        self._wait = wait or self._shutdown_event.wait

    @property
    def supported_job_types(self) -> frozenset[JobType]:
        return frozenset(self._handlers)

    @property
    def lease_owner(self) -> str:
        return self._lease_owner

    def request_shutdown(self) -> None:
        self._shutdown_event.set()

    def run_iteration(self) -> bool:
        """Claim and dispatch at most one supported job; return whether one ran."""
        if self._shutdown_event.is_set() or not self._handlers:
            return False

        with self._factory.begin() as db:
            recovered = recover_stale_jobs(db)
        if recovered:
            logger.warning("Recovered %d expired worker lease(s)", len(recovered))

        # Commit and close the claim Session before future handler work begins.
        with self._factory.begin() as db:
            job = claim_next_job(
                db,
                allowed_job_types=self.supported_job_types,
                lease_owner=self._lease_owner,
                lease_seconds=self._lease_seconds,
            )
            if job is None:
                return False
            job_id, job_type = job.job_id, job.job_type

        heartbeat_stop = Event()
        ownership_lost = Event()
        heartbeat_thread = Thread(
            target=self._heartbeat_loop,
            args=(job_id, heartbeat_stop, ownership_lost),
            name=f"job-heartbeat-{job_id}",
            daemon=True,
        )
        heartbeat_thread.start()
        handler_failed = False
        try:
            self._handlers[job_type](job_id)
        except Exception:
            handler_failed = True
            logger.error("Job handler failed for job %s (%s)", job_id, job_type.value)
        finally:
            heartbeat_stop.set()
            heartbeat_thread.join()

        try:
            with self._factory.begin() as db:
                if handler_failed:
                    fail_job(
                        db,
                        job_id,
                        lease_owner=self._lease_owner,
                        error_code=HANDLER_FAILURE_CODE,
                        error_message=HANDLER_FAILURE_MESSAGE,
                    )
                else:
                    complete_job(db, job_id, lease_owner=self._lease_owner)
        except (InvalidJobTransitionError, JobLeaseLostError):
            logger.warning("Job lease ownership lost before terminal update: %s (%s)", job_id, job_type.value)
        else:
            if handler_failed:
                logger.info("Job failed: %s (%s)", job_id, job_type.value)
            else:
                logger.info("Job completed: %s (%s)", job_id, job_type.value)
        return True

    def _heartbeat_loop(
        self, job_id: UUID, stop_event: Event, ownership_lost: Event
    ) -> None:
        """Renew one handler's lease with independent sessions until it returns."""
        while not stop_event.wait(self._heartbeat_interval_seconds):
            try:
                with self._factory.begin() as db:
                    heartbeat_job(
                        db,
                        job_id,
                        lease_owner=self._lease_owner,
                        lease_seconds=self._lease_seconds,
                    )
            except (InvalidJobTransitionError, JobLeaseLostError):
                ownership_lost.set()
                logger.warning("Job lease ownership lost during heartbeat: %s", job_id)
                return
            except SQLAlchemyError:
                logger.warning("Job heartbeat database error; will retry: %s", job_id)

    def run_forever(self) -> None:
        logger.info(
            "Worker started; supported job types: %s",
            ",".join(sorted(job_type.value for job_type in self.supported_job_types))
            or "none",
        )
        try:
            while not self._shutdown_event.is_set():
                try:
                    claimed = self.run_iteration()
                except SQLAlchemyError:
                    logger.error("Worker database claim failed; retrying after poll interval")
                    claimed = False
                if not claimed and self._wait(self._poll_interval_seconds):
                    self.request_shutdown()
        finally:
            logger.info("Worker stopped")


def create_worker_runtime(settings: Settings | None = None) -> WorkerRuntime:
    runtime_settings = settings or get_settings()
    factory = get_session_factory()
    handlers = dict(PRODUCTION_HANDLERS)
    handlers[JobType.AUDIT] = AuditJobHandler(
        factory, create_artifact_storage(runtime_settings)
    )
    return WorkerRuntime(
        factory,
        handlers=handlers,
        poll_interval_seconds=runtime_settings.worker_poll_interval_seconds,
        lease_seconds=runtime_settings.worker_job_lease_seconds,
        heartbeat_interval_seconds=runtime_settings.worker_heartbeat_interval_seconds,
    )


def _new_lease_owner() -> str:
    hostname = socket.gethostname().replace(" ", "-")[:64] or "worker"
    return f"{hostname}:{os.getpid()}:{uuid4().hex}"[:128]
