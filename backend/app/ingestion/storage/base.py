from abc import ABC, abstractmethod
from uuid import UUID


class ArtifactStorageError(Exception):
    """Base error for controlled artifact-storage failures."""


class InvalidStorageReferenceError(ArtifactStorageError):
    """A logical reference is malformed or escapes the storage root."""


class ArtifactNotFoundError(ArtifactStorageError):
    """No artifact bytes exist for a valid logical reference."""


class ArtifactAlreadyExistsError(ArtifactStorageError):
    """An immutable artifact target already contains evidence."""


class ArtifactStorage(ABC):
    """Storage boundary for immutable raw artifact bytes."""

    @abstractmethod
    def write(self, data: bytes, *, organization_id: UUID, artifact_id: UUID) -> str:
        """Store bytes once and return a backend-independent logical reference."""

    @abstractmethod
    def read(self, storage_reference: str) -> bytes:
        """Return bytes for a validated logical reference."""

    @abstractmethod
    def exists(self, storage_reference: str) -> bool:
        """Report whether bytes exist for a validated logical reference."""

    @abstractmethod
    def delete(self, storage_reference: str) -> None:
        """Delete bytes addressed by a validated reference for compensation only."""
