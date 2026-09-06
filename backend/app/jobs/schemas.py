from app.audit.schemas import JobSummary


class JobResponse(JobSummary):
    """Safe product-facing Job status without internal payload data."""
