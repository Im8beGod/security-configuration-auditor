from collections.abc import Mapping
from types import MappingProxyType
from typing import Protocol

from app.parsing.models import StructuralIR, StructuralParseRequest
from app.parsing.readers.indentation_cli import (
    INDENTATION_CLI_READER_ID,
    IndentationCliReader,
)
from app.parsing.readers.fortios_cli import FORTIOS_CLI_READER_ID, FortiosCliReader
from app.parsing.readers.xml_tree import XML_TREE_READER_ID, XmlTreeReader


class StructuralReader(Protocol):
    reader_id: str

    def parse(self, request: StructuralParseRequest) -> StructuralIR: ...


INDENTATION_CLI_READER = IndentationCliReader()
READER_REGISTRY: Mapping[str, StructuralReader] = MappingProxyType({
    INDENTATION_CLI_READER_ID: INDENTATION_CLI_READER,
    FORTIOS_CLI_READER_ID: FortiosCliReader(),
    XML_TREE_READER_ID: XmlTreeReader(),
})
