from __future__ import annotations

from io import StringIO
import re

from app.parsing.ir_builder import IRBuilder
from app.parsing.models import (
    ConfigNodeKind,
    ParseStatus,
    StructuralIR,
    StructuralParseRequest,
)
from app.parsing.tokenizer import measure_indentation, tokenize_statement


INDENTATION_CLI_READER_ID = "indentation_cli.v1"
MAX_INPUT_CHARACTERS = 2 * 1024 * 1024
MAX_SOURCE_LINES = 50_000
MAX_LINE_CHARACTERS = 16 * 1024
MAX_NODE_COUNT = 20_000
MAX_DEPTH = 64
MAX_OPAQUE_BLOCK_LINES = 4096

BANNER_PREFIX = re.compile(r"^banner(?:\s|$)", re.IGNORECASE)
CERTIFICATE_CHAIN_PREFIX = re.compile(
    r"^crypto\s+pki\s+certificate\s+chain(?:\s|$)", re.IGNORECASE
)


class IndentationCliReader:
    reader_id = INDENTATION_CLI_READER_ID

    def parse(self, request: StructuralParseRequest) -> StructuralIR:
        lines, content_truncated = _bounded_lines(request.content)
        truncated = request.input_truncated or content_truncated
        builder = IRBuilder(
            reader_id=self.reader_id,
            source=request.source,
            max_depth=MAX_DEPTH,
            max_nodes=MAX_NODE_COUNT,
        )
        if request.input_truncated:
            builder.add_diagnostic(
                "artifact_byte_limit",
                "Artifact content was truncated at the structural parsing byte limit",
            )
        if content_truncated:
            builder.add_diagnostic(
                "input_limit",
                "Configuration input exceeded structural parsing limits",
            )

        index = 0
        while index < len(lines):
            if builder.node_limit_reached:
                builder.add_diagnostic(
                    "node_limit",
                    "Configuration node count was bounded",
                    source_start=index + 1,
                )
                truncated = True
                break

            original_line = lines[index]
            stripped = original_line.strip()
            if not stripped:
                index += 1
                continue

            if stripped.startswith("!"):
                builder.reset_context()
                raw_text, line_truncated = _bounded_line(original_line)
                builder.add_node(
                    raw_text=raw_text,
                    command=None,
                    arguments=(),
                    indent=0,
                    source_start=index + 1,
                    source_end=index + 1,
                    negated=False,
                    kind=ConfigNodeKind.COMMENT,
                    parse_status=(ParseStatus.PARTIAL if line_truncated else ParseStatus.PARSED),
                    comments=(stripped[1:].lstrip(),),
                    force_root=True,
                    can_parent=False,
                )
                if line_truncated:
                    _line_limit_diagnostic(builder, index + 1)
                    truncated = True
                index += 1
                continue

            indentation = measure_indentation(original_line)
            if BANNER_PREFIX.match(stripped):
                end_index, raw_text, delimiter, complete, block_truncated = _scan_banner(
                    lines, index
                )
                tokens = tokenize_statement(original_line)
                status = ParseStatus.OPAQUE if complete and not block_truncated else ParseStatus.PARTIAL
                arguments = tokens.arguments
                if delimiter is not None and delimiter not in arguments:
                    arguments = arguments + (delimiter,)
                builder.add_node(
                    raw_text=raw_text,
                    command="banner",
                    arguments=arguments,
                    indent=indentation.columns,
                    source_start=index + 1,
                    source_end=end_index + 1,
                    negated=False,
                    kind=ConfigNodeKind.OPAQUE,
                    parse_status=status,
                    can_parent=False,
                )
                if not complete:
                    builder.add_diagnostic(
                        "unterminated_banner",
                        "Banner delimiter was not found within bounded input",
                        source_start=index + 1,
                        source_end=end_index + 1,
                    )
                if block_truncated:
                    builder.add_diagnostic(
                        "opaque_block_limit",
                        "Opaque banner block exceeded structural parsing limits",
                        source_start=index + 1,
                        source_end=end_index + 1,
                    )
                    truncated = True
                index = end_index + 1
                if not complete:
                    break
                continue

            if CERTIFICATE_CHAIN_PREFIX.match(stripped):
                end_index, raw_text, complete, block_truncated = _scan_certificate_block(
                    lines, index
                )
                tokens = tokenize_statement(original_line)
                builder.add_node(
                    raw_text=raw_text,
                    command=tokens.command,
                    arguments=tokens.arguments,
                    indent=indentation.columns,
                    source_start=index + 1,
                    source_end=end_index + 1,
                    negated=tokens.negated,
                    kind=ConfigNodeKind.OPAQUE,
                    parse_status=(
                        ParseStatus.OPAQUE
                        if complete and not block_truncated
                        else ParseStatus.PARTIAL
                    ),
                    can_parent=False,
                )
                if not complete:
                    builder.add_diagnostic(
                        "unterminated_opaque_block",
                        "Opaque certificate block terminator was not found within bounded input",
                        source_start=index + 1,
                        source_end=end_index + 1,
                    )
                if block_truncated:
                    builder.add_diagnostic(
                        "opaque_block_limit",
                        "Opaque certificate block exceeded structural parsing limits",
                        source_start=index + 1,
                        source_end=end_index + 1,
                    )
                    truncated = True
                index = end_index + 1
                if not complete:
                    break
                continue

            raw_text, line_truncated = _bounded_line(original_line)
            tokens = tokenize_statement(raw_text)
            status = ParseStatus.PARSED
            if tokens.command is None:
                status = ParseStatus.UNRESOLVED
            if indentation.mixed or line_truncated:
                status = ParseStatus.PARTIAL
            if indentation.mixed:
                builder.add_diagnostic(
                    "mixed_indentation",
                    "Mixed tabs and spaces were normalized to indentation columns",
                    source_start=index + 1,
                    source_end=index + 1,
                )
            if line_truncated:
                _line_limit_diagnostic(builder, index + 1)
                truncated = True
            builder.add_node(
                raw_text=raw_text,
                command=tokens.command,
                arguments=tokens.arguments,
                indent=indentation.columns,
                source_start=index + 1,
                source_end=index + 1,
                negated=tokens.negated,
                kind=ConfigNodeKind.STATEMENT,
                parse_status=status,
            )
            index += 1

        return builder.build(truncated=truncated)


def _bounded_lines(content: str) -> tuple[list[str], bool]:
    bounded_content = content[:MAX_INPUT_CHARACTERS]
    truncated = len(content) > len(bounded_content)
    lines: list[str] = []
    for line in StringIO(bounded_content):
        if len(lines) >= MAX_SOURCE_LINES:
            truncated = True
            break
        lines.append(line.rstrip("\r\n"))
    if bounded_content and not lines:
        lines.append(bounded_content)
    return lines, truncated


def _bounded_line(line: str) -> tuple[str, bool]:
    return line[:MAX_LINE_CHARACTERS], len(line) > MAX_LINE_CHARACTERS


def _line_limit_diagnostic(builder: IRBuilder, source_line: int) -> None:
    builder.add_diagnostic(
        "line_limit",
        "Source line exceeded the structural parsing line limit",
        source_start=source_line,
        source_end=source_line,
    )


def _banner_delimiter(stripped: str) -> tuple[str | None, str]:
    parts = stripped.split(None, 2)
    if len(parts) < 3 or not parts[2]:
        return None, ""
    payload = parts[2]
    delimiter = payload[:2] if payload.startswith("^") and len(payload) >= 2 else payload[0]
    return delimiter, payload[len(delimiter):]


def _scan_banner(
    lines: list[str], start_index: int
) -> tuple[int, str, str | None, bool, bool]:
    delimiter, opening_remainder = _banner_delimiter(lines[start_index].strip())
    raw_lines = [_bounded_line(lines[start_index])[0]]
    block_truncated = len(lines[start_index]) > MAX_LINE_CHARACTERS
    if delimiter is None:
        end_limit = min(len(lines), start_index + MAX_OPAQUE_BLOCK_LINES)
        for index in range(start_index + 1, end_limit):
            bounded, line_truncated = _bounded_line(lines[index])
            raw_lines.append(bounded)
            block_truncated = block_truncated or line_truncated
        end_index = max(start_index, end_limit - 1)
        return end_index, "\n".join(raw_lines), None, False, (
            block_truncated or end_limit < len(lines)
        )
    if delimiter in opening_remainder:
        return start_index, raw_lines[0], delimiter, True, block_truncated

    end_limit = min(len(lines), start_index + MAX_OPAQUE_BLOCK_LINES)
    for index in range(start_index + 1, end_limit):
        bounded, line_truncated = _bounded_line(lines[index])
        raw_lines.append(bounded)
        block_truncated = block_truncated or line_truncated
        if delimiter in lines[index]:
            return index, "\n".join(raw_lines), delimiter, True, block_truncated
    end_index = max(start_index, end_limit - 1)
    return end_index, "\n".join(raw_lines), delimiter, False, (
        block_truncated or end_limit < len(lines)
    )


def _scan_certificate_block(
    lines: list[str], start_index: int
) -> tuple[int, str, bool, bool]:
    raw_lines = [_bounded_line(lines[start_index])[0]]
    block_truncated = len(lines[start_index]) > MAX_LINE_CHARACTERS
    end_limit = min(len(lines), start_index + MAX_OPAQUE_BLOCK_LINES)
    for index in range(start_index + 1, end_limit):
        bounded, line_truncated = _bounded_line(lines[index])
        raw_lines.append(bounded)
        block_truncated = block_truncated or line_truncated
        if lines[index].strip().lower() == "quit":
            return index, "\n".join(raw_lines), True, block_truncated
    end_index = max(start_index, end_limit - 1)
    return end_index, "\n".join(raw_lines), False, (
        block_truncated or end_limit < len(lines)
    )
