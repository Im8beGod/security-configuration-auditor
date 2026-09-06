class InterpretationWorkflowError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class InterpretationNotFoundError(InterpretationWorkflowError):
    pass


class InterpretationValidationError(InterpretationWorkflowError):
    pass


class InterpretationInfrastructureError(InterpretationWorkflowError):
    pass
