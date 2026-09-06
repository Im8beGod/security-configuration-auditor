import re
from pathlib import PurePosixPath, PureWindowsPath
from urllib.parse import unquote


CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


def normalize_filename(filename: str | None) -> str:
    """Return bounded display metadata with all path meaning removed."""

    candidate = unquote(filename or "unnamed-upload").replace("\\", "/")
    candidate = PurePosixPath(PureWindowsPath(candidate).name).name
    candidate = CONTROL_CHARACTERS.sub("_", candidate).strip()
    if candidate in {"", ".", ".."}:
        candidate = "unnamed-upload"
    return candidate[:255]


def normalize_mime_type(mime_type: str | None) -> str | None:
    if mime_type is None:
        return None
    normalized = CONTROL_CHARACTERS.sub("", mime_type).strip().lower()
    return normalized[:255] or None
