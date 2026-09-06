class AuditWorkflowError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class AuditNotFoundError(AuditWorkflowError):
    pass


class AuditConflictError(AuditWorkflowError):
    pass


class AuditValidationError(AuditWorkflowError):
    pass


class AuditInfrastructureError(AuditWorkflowError):
    pass
