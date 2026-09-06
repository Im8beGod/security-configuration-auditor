class SnapshotWorkflowError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class SnapshotNotFoundError(SnapshotWorkflowError):
    pass


class SnapshotConflictError(SnapshotWorkflowError):
    pass


class SnapshotValidationError(SnapshotWorkflowError):
    pass
