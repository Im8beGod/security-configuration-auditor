from dataclasses import dataclass
import re


TOKEN_PATTERN = re.compile(r"\S+")


@dataclass(frozen=True)
class Indentation:
    columns: int
    mixed: bool


@dataclass(frozen=True)
class TokenizedStatement:
    command: str | None
    arguments: tuple[str, ...]
    negated: bool


def measure_indentation(line: str, *, tab_width: int = 8) -> Indentation:
    columns = 0
    saw_space = False
    saw_tab = False
    for character in line:
        if character == " ":
            columns += 1
            saw_space = True
        elif character == "\t":
            columns += tab_width - (columns % tab_width)
            saw_tab = True
        else:
            break
    return Indentation(columns=columns, mixed=saw_space and saw_tab)


def tokenize_statement(raw_text: str) -> TokenizedStatement:
    tokens = tuple(TOKEN_PATTERN.findall(raw_text.strip()))
    if not tokens:
        return TokenizedStatement(command=None, arguments=(), negated=False)
    if tokens[0].lower() == "no":
        if len(tokens) == 1:
            return TokenizedStatement(command=None, arguments=(), negated=True)
        return TokenizedStatement(
            command=tokens[1].lower(),
            arguments=tokens[2:],
            negated=True,
        )
    return TokenizedStatement(
        command=tokens[0].lower(),
        arguments=tokens[1:],
        negated=False,
    )
