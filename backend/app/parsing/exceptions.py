class StructuralParsingError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class StructuralReaderNotFoundError(StructuralParsingError):
    pass


class ArtifactNotParseableError(StructuralParsingError):
    pass


class ParsingInfrastructureError(StructuralParsingError):
    pass
