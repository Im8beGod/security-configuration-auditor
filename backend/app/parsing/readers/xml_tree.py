from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re
from xml.etree import ElementTree

from app.parsing.models import ArtifactProvenance, StructuralParseRequest


XML_TREE_READER_ID = "xml_tree.v1"
MAX_XML_INPUT_CHARACTERS = 2 * 1024 * 1024
MAX_XML_DEPTH = 64
MAX_XML_NODES = 20_000
MAX_XML_TEXT = 16 * 1024


@dataclass(frozen=True)
class XmlNode:
    node_id: str
    path: tuple[str, ...]
    tag: str
    attributes: tuple[tuple[str, str], ...]
    text: str | None
    parent_id: str | None
    order: int
    source: ArtifactProvenance


@dataclass(frozen=True)
class XmlStructuralIR:
    reader_id: str
    source: ArtifactProvenance
    nodes: tuple[XmlNode, ...]
    diagnostics: tuple[str, ...]
    truncated: bool = False


class XmlTreeReader:
    reader_id = XML_TREE_READER_ID

    def parse(self, request: StructuralParseRequest) -> XmlStructuralIR:
        content = request.content[:MAX_XML_INPUT_CHARACTERS]
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY|ELEMENT|ATTLIST)\b|\b(?:SYSTEM|PUBLIC)\s+['\"]", content[:MAX_XML_INPUT_CHARACTERS], re.IGNORECASE):
            raise ValueError("XML DTD and entity declarations are not supported")
        if len(request.content) > MAX_XML_INPUT_CHARACTERS:
            raise ValueError("XML input exceeds the bounded size limit")
        try:
            root = ElementTree.fromstring(content)
        except ElementTree.ParseError as error:
            raise ValueError("Malformed XML evidence") from error
        nodes: list[XmlNode] = []
        truncated = False

        def visit(element: ElementTree.Element, parent_id: str | None, path: tuple[str, ...], depth: int) -> None:
            nonlocal truncated
            if len(nodes) >= MAX_XML_NODES or depth > MAX_XML_DEPTH:
                truncated = True
                return
            if element.text and len(element.text) > MAX_XML_TEXT:
                truncated = True
                text = element.text[:MAX_XML_TEXT]
            else:
                text = element.text.strip() if element.text and element.text.strip() else None
            order = len(nodes) + 1
            node_id = "xmln_" + sha256(f"{request.source.artifact_id}|{path}|{order}".encode()).hexdigest()[:32]
            node = XmlNode(node_id, path, element.tag, tuple(sorted(element.attrib.items())), text, parent_id, order, request.source)
            nodes.append(node)
            occurrences: dict[str, int] = {}
            for child in list(element):
                occurrences[child.tag] = occurrences.get(child.tag, 0) + 1
                visit(child, node_id, path + (f"{child.tag}[{occurrences[child.tag]}]",), depth + 1)

        visit(root, None, (f"{root.tag}[1]",), 0)
        return XmlStructuralIR(self.reader_id, request.source, tuple(nodes), (), truncated or request.input_truncated)
