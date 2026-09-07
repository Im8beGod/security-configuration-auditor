from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from app.security_model import FIELD_REGISTRY
from app.training.dsl import MappingDefinition


MAX_AI_TEXT = 2048
_SECRET = re.compile(r"(?i)\b(password|secret|token|community|private[-_ ]?key)\b\s*[:= ]\s*\S+")
_INJECTION = re.compile(r"(?i)(ignore (all |the )?(previous|prior) instructions|system prompt|developer message|jailbreak)")


class MappingSuggestion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    definition: MappingDefinition
    description: str = Field(min_length=1, max_length=2048)
    confidence: float = Field(ge=0, le=1)
    similar_mapping_refs: list[str] = Field(default_factory=list, max_length=20)
    provider_metadata: dict[str, str] = Field(default_factory=dict)


class AISuggestionProvider(Protocol):
    def suggest_mapping(self, context: AISuggestionContext) -> MappingSuggestion:
        ...


class AISuggestionUnavailable(RuntimeError):
    pass


class DisabledAISuggestionProvider:
    def suggest_mapping(self, context: AISuggestionContext) -> MappingSuggestion:
        del context
        raise AISuggestionUnavailable("AI mapping suggestions are disabled")


class DeterministicFakeSuggestionProvider:
    """Explicitly injected test/development provider; never selected in production."""

    def __init__(self, suggestion: MappingSuggestion | dict[str, Any]) -> None:
        self._suggestion = suggestion
        self.last_context: AISuggestionContext | None = None

    def suggest_mapping(self, context: AISuggestionContext) -> MappingSuggestion:
        self.last_context = context
        return self._suggestion if isinstance(self._suggestion, MappingSuggestion) else MappingSuggestion.model_validate(self._suggestion)


def sanitized_context(raw_text: str, surrounding_context: str, profile_version_id: str | None, candidate_fields: list[str], similar: list[dict[str, Any]]) -> AISuggestionContext:
    return AISuggestionContext(
        unresolved_text=_sanitize(raw_text),
        surrounding_context=_sanitize(surrounding_context),
        profile_version_id=profile_version_id,
        candidate_fields=tuple(item for item in candidate_fields if item in FIELD_REGISTRY),
        similar_published_mappings=tuple(similar[:10]),
    )


def _sanitize(value: str) -> str:
    minimized = _SECRET.sub(lambda match: f"{match.group(1)} [REDACTED]", value[:MAX_AI_TEXT])
    return _INJECTION.sub("[UNTRUSTED_INSTRUCTION_REDACTED]", minimized)


@dataclass(frozen=True)
class AISuggestionContext:
    unresolved_text: str
    surrounding_context: str
    profile_version_id: str | None
    candidate_fields: tuple[str, ...]
    similar_published_mappings: tuple[dict[str, Any], ...]
