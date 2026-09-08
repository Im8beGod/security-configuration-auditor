import logging
import math
from collections.abc import Callable, Mapping
from threading import Event
from types import MappingProxyType
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.db.session import get_session_factory
from app.jobs.enums import JobType
from app.ingestion.storage import create_artifact_storage
from app.jobs.handlers import AuditJobHandler, handle_mapping_validation, handle_pdf_generation, handle_reevaluation, handle_system_noop
from app.jobs.service import claim_next_job, complete_job, fail_job


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
        shutdown_event: Event | None = None,
        wait: Callable[[float], bool] | None = None,
    ) -> None:
        if not math.isfinite(poll_interval_seconds) or poll_interval_seconds < 0.1:
            raise ValueError("Worker poll interval must be at least 0.1 seconds")
        if any(not isinstance(job_type, JobType) for job_type in handlers):
            raise ValueError("Worker handlers must use explicit JobType keys")
        self._factory = factory
        self._handlers = dict(handlers)
        self._poll_interval_seconds = poll_interval_seconds
        self._shutdown_event = shutdown_event or Event()
        self._wait = wait or self._shutdown_event.wait

    @property
    def supported_job_types(self) -> frozenset[JobType]:
        return frozenset(self._handlers)

    def request_shutdown(self) -> None:
        self._shutdown_event.set()

    def run_iteration(self) -> bool:
        """Claim and dispatch at most one supported job; return whether one ran."""
        if self._shutdown_event.is_set() or not self._handlers:
            return False

        # Commit and close the claim Session before future handler work begins.
        with self._factory.begin() as db:
            job = claim_next_job(db, allowed_job_types=self.supported_job_types)
            if job is None:
                return False
            job_id, job_type = job.job_id, job.job_type

        try:
            self._handlers[job_type](job_id)
        except Exception:
            logger.error("Job handler failed for job %s (%s)", job_id, job_type.value)
            with self._factory.begin() as db:
                fail_job(
                    db,
                    job_id,
                    error_code=HANDLER_FAILURE_CODE,
                    error_message=HANDLER_FAILURE_MESSAGE,
                )
        else:
            with self._factory.begin() as db:
                complete_job(db, job_id)
            logger.info("Job completed: %s (%s)", job_id, job_type.value)
        return True

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
    )
