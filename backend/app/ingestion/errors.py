class IngestionError(Exception):
    """A controlled, client-safe ingestion failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class IngestionInfrastructureError(IngestionError):
    """A sanitized storage or persistence failure."""
