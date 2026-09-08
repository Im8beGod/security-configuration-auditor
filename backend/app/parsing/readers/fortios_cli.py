from __future__ import annotations

from io import StringIO

from app.parsing.ir_builder import IRBuilder
from app.parsing.models import ConfigNodeKind, ParseStatus, StructuralIR, StructuralParseRequest
from app.parsing.tokenizer import tokenize_statement


FORTIOS_CLI_READER_ID = "fortios_cli.v1"
MAX_INPUT_CHARACTERS = 2 * 1024 * 1024
MAX_SOURCE_LINES = 50_000
MAX_LINE_CHARACTERS = 16 * 1024


class FortiosCliReader:
    reader_id = FORTIOS_CLI_READER_ID

    def parse(self, request: StructuralParseRequest) -> StructuralIR:
        content = request.content[:MAX_INPUT_CHARACTERS]
        lines = list(StringIO(content))[:MAX_SOURCE_LINES]
        truncated = request.input_truncated or len(request.content) > len(content) or len(lines) < content.count("\n")
        builder = IRBuilder(reader_id=self.reader_id, source=request.source, max_depth=16, max_nodes=20_000)
        config_depth = 0
        edit_depth = 0
        in_config = False
        in_edit = False
        for line_number, raw_line in enumerate(lines, start=1):
            raw = raw_line.rstrip("\r\n")[:MAX_LINE_CHARACTERS]
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            tokens = tokenize_statement(stripped)
            command = tokens.command
            if command is None:
                builder.add_node(raw_text=raw, command=None, arguments=(), indent=0,
                                 source_start=line_number, source_end=line_number,
                                 negated=tokens.negated, kind=ConfigNodeKind.STATEMENT,
                                 parse_status=ParseStatus.UNRESOLVED)
                continue
            if command == "config":
                config_depth = 0 if not in_config else 1
                in_config, in_edit = True, False
                builder.add_node(raw_text=raw, command=command, arguments=tokens.arguments,
                                 indent=config_depth, source_start=line_number, source_end=line_number,
                                 negated=False, kind=ConfigNodeKind.STATEMENT,
                                 parse_status=ParseStatus.PARSED, can_parent=True)
                continue
            if command == "edit" and in_config:
                in_edit = True
                edit_depth = config_depth + 1
                builder.add_node(raw_text=raw, command=command, arguments=tokens.arguments,
                                 indent=edit_depth, source_start=line_number, source_end=line_number,
                                 negated=False, kind=ConfigNodeKind.STATEMENT,
                                 parse_status=ParseStatus.PARSED, can_parent=True)
                continue
            if command == "next" and in_edit:
                in_edit = False
                builder.add_node(raw_text=raw, command=command, arguments=(), indent=edit_depth,
                                 source_start=line_number, source_end=line_number,
                                 negated=False, kind=ConfigNodeKind.STATEMENT,
                                 parse_status=ParseStatus.PARSED, can_parent=False)
                continue
            if command == "end":
                in_config, in_edit = False, False
                builder.add_node(raw_text=raw, command=command, arguments=(), indent=0,
                                 source_start=line_number, source_end=line_number,
                                 negated=False, kind=ConfigNodeKind.STATEMENT,
                                 parse_status=ParseStatus.PARSED, force_root=True, can_parent=False)
                continue
            if command in {"set", "unset"} and in_config:
                builder.add_node(raw_text=raw, command=command, arguments=tokens.arguments,
                                 indent=(edit_depth + 1 if in_edit else config_depth + 1),
                                 source_start=line_number, source_end=line_number,
                                 negated=command == "unset", kind=ConfigNodeKind.STATEMENT,
                                 parse_status=ParseStatus.PARSED)
                continue
            builder.add_node(raw_text=raw, command=command, arguments=tokens.arguments,
                             indent=0, source_start=line_number, source_end=line_number,
                             negated=tokens.negated, kind=ConfigNodeKind.STATEMENT,
                             parse_status=ParseStatus.UNRESOLVED, can_parent=False)
        return builder.build(truncated=truncated)
