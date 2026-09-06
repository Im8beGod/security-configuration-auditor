class JobError(Exception):
    """Base error for controlled job-domain failures."""


class JobNotFoundError(JobError):
    """A requested job does not exist."""


class InvalidJobTransitionError(JobError):
    """A job cannot make the requested lifecycle transition."""
