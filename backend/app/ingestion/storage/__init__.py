from functools import lru_cache

from app.core.config import Settings, get_settings
from app.ingestion.storage.base import (
    ArtifactAlreadyExistsError,
    ArtifactNotFoundError,
    ArtifactStorage,
    ArtifactStorageError,
    InvalidStorageReferenceError,
)
from app.ingestion.storage.local import LocalFilesystemArtifactStorage


def create_artifact_storage(settings: Settings) -> ArtifactStorage:
    return LocalFilesystemArtifactStorage(settings.artifact_storage_path)


@lru_cache
def get_artifact_storage() -> ArtifactStorage:
    """Construct the configured backend without touching the filesystem."""
    return create_artifact_storage(get_settings())


__all__ = [
    "ArtifactAlreadyExistsError",
    "ArtifactNotFoundError",
    "ArtifactStorage",
    "ArtifactStorageError",
    "InvalidStorageReferenceError",
    "LocalFilesystemArtifactStorage",
    "create_artifact_storage",
    "get_artifact_storage",
]
