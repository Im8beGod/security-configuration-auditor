from uuid import UUID
from app.db.models import Job
from app.db.session import get_session_factory
from app.reporting.service import fail_report, generate_report, mark_generating
from app.reporting.storage import get_report_storage

def handle_pdf_generation(job_id: UUID) -> None:
    factory = get_session_factory()
    with factory() as db:
        job = db.get(Job, job_id)
        report_id = UUID(job.payload["report_id"]) if job else None
    if report_id is None: raise ValueError("Report job payload is invalid")
    try:
        with factory.begin() as db:
            mark_generating(db, report_id)
        with factory.begin() as db:
            generate_report(db, report_id, get_report_storage())
    except Exception:
        with factory.begin() as db:
            fail_report(db, report_id)
        raise
