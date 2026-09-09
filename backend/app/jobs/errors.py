class JobError(Exception):
    """Base error for controlled job-domain failures."""


class JobNotFoundError(JobError):
    """A requested job does not exist."""


class InvalidJobTransitionError(JobError):
    """A job cannot make the requested lifecycle transition."""


class JobLeaseLostError(JobError):
    """A job lease is no longer owned and cannot be mutated."""
