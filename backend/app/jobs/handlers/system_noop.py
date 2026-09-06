from uuid import UUID


def handle_system_noop(job_id: UUID) -> None:
    """Complete harmlessly; this handler exists only to verify job dispatch."""
    del job_id
