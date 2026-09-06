from collections.abc import Mapping
from types import MappingProxyType
from typing import Protocol

from app.parsing.models import StructuralIR, StructuralParseRequest
from app.parsing.readers.indentation_cli import (
    INDENTATION_CLI_READER_ID,
    IndentationCliReader,
)


class StructuralReader(Protocol):
    reader_id: str

    def parse(self, request: StructuralParseRequest) -> StructuralIR: ...


INDENTATION_CLI_READER = IndentationCliReader()
READER_REGISTRY: Mapping[str, StructuralReader] = MappingProxyType({
    INDENTATION_CLI_READER_ID: INDENTATION_CLI_READER,
})
