from typing import Any
from pydantic import BaseModel, Field
class RemediationPreviewRequest(BaseModel): parameters: dict[str, Any] = Field(default_factory=dict)
