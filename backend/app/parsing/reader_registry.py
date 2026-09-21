import re
from collections.abc import Iterator, Mapping
from types import MappingProxyType
from typing import Protocol

from app.parsing.models import StructuralIR, StructuralParseRequest
from app.parsing.readers.indentation_cli import (
    INDENTATION_CLI_READER_ID,
    IndentationCliReader,
)
from app.parsing.readers.fortios_cli import FORTIOS_CLI_READER_ID, FortiosCliReader
from app.parsing.readers.xml_tree import XML_TREE_READER_ID, XmlTreeReader
from app.parsing.readers.json_tree import JSON_TREE_READER_ID, JsonTreeReader


class StructuralReader(Protocol):
    reader_id: str

    def parse(self, request: StructuralParseRequest) -> StructuralIR: ...


class StructuralReaderRegistry(Mapping[str, StructuralReader]):
    """Immutable registry whose keys include the structural reader version."""

    _ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*\.v[1-9][0-9]*$")

    def __init__(self, readers: tuple[StructuralReader, ...]) -> None:
        by_id: dict[str, StructuralReader] = {}
        for reader in readers:
            if not self._ID_PATTERN.fullmatch(reader.reader_id):
                raise ValueError("Structural reader identity is malformed")
            if reader.reader_id in by_id and by_id[reader.reader_id] is not reader:
                raise ValueError("Structural reader version content conflicts")
            by_id[reader.reader_id] = reader
        self._by_id = MappingProxyType(by_id)

    def __getitem__(self, reader_id: str) -> StructuralReader:
        return self._by_id[reader_id]

    def __iter__(self) -> Iterator[str]:
        return iter(self._by_id)

    def __len__(self) -> int:
        return len(self._by_id)


INDENTATION_CLI_READER = IndentationCliReader()
READER_REGISTRY = StructuralReaderRegistry((
    INDENTATION_CLI_READER,
    FortiosCliReader(),
    XmlTreeReader(),
    JsonTreeReader(),
))
