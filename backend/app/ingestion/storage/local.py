import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import tempfile
from uuid import UUID

from app.ingestion.storage.base import (
    ArtifactAlreadyExistsError,
    ArtifactNotFoundError,
    ArtifactStorage,
    ArtifactStorageError,
    InvalidStorageReferenceError,
)


class LocalFilesystemArtifactStorage(ArtifactStorage):
    """Immutable local storage rooted at one configured private directory."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        # Resolution is read-only; the root is created lazily by write().
        self._resolved_root = self.root.resolve(strict=False)

    @staticmethod
    def storage_reference(organization_id: UUID, artifact_id: UUID) -> str:
        return f"organizations/{organization_id}/artifacts/{artifact_id}"

    def write(self, data: bytes, *, organization_id: UUID, artifact_id: UUID) -> str:
        if not isinstance(data, bytes):
            raise TypeError("Artifact data must be bytes")
        reference = self.storage_reference(organization_id, artifact_id)
        target = self._resolve_reference(reference)
        temporary_path: Path | None = None
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            # Re-resolve after directory creation to detect a pre-existing symlink.
            target = self._resolve_reference(reference)
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=target.parent, prefix=f".{artifact_id}.",
                suffix=".tmp", delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                temporary.write(data)
                temporary.flush()
                os.fsync(temporary.fileno())
            # A hard link publishes the completed same-filesystem file atomically.
            # Unlike replace/rename, link fails if immutable evidence already exists.
            os.link(temporary_path, target)
        except FileExistsError:
            raise ArtifactAlreadyExistsError("Artifact bytes already exist") from None
        except InvalidStorageReferenceError:
            raise
        except OSError:
            raise ArtifactStorageError("Unable to store artifact bytes") from None
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass
        return reference

    def read(self, storage_reference: str) -> bytes:
        target = self._resolve_reference(storage_reference)
        try:
            if not target.is_file():
                raise ArtifactNotFoundError("Artifact bytes were not found")
            return target.read_bytes()
        except ArtifactNotFoundError:
            raise
        except OSError:
            raise ArtifactStorageError("Unable to read artifact bytes") from None

    def read_prefix(self, storage_reference: str, max_bytes: int) -> bytes:
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
            raise ValueError("max_bytes must be a positive integer")
        target = self._resolve_reference(storage_reference)
        try:
            if not target.is_file():
                raise ArtifactNotFoundError("Artifact bytes were not found")
            with target.open("rb") as artifact_file:
                return artifact_file.read(max_bytes)
        except ArtifactNotFoundError:
            raise
        except OSError:
            raise ArtifactStorageError("Unable to read artifact bytes") from None

    def exists(self, storage_reference: str) -> bool:
        target = self._resolve_reference(storage_reference)
        try:
            return target.is_file()
        except OSError:
            raise ArtifactStorageError("Unable to inspect artifact bytes") from None

    def delete(self, storage_reference: str) -> None:
        target = self._resolve_reference(storage_reference)
        try:
            target.unlink(missing_ok=True)
        except OSError:
            raise ArtifactStorageError("Unable to delete artifact bytes") from None

    def _resolve_reference(self, storage_reference: str) -> Path:
        if not isinstance(storage_reference, str) or not storage_reference:
            raise InvalidStorageReferenceError("Invalid artifact storage reference")
        windows_path = PureWindowsPath(storage_reference)
        posix_path = PurePosixPath(storage_reference)
        if (
            "\\" in storage_reference
            or windows_path.drive
            or windows_path.is_absolute()
            or posix_path.is_absolute()
            or storage_reference != posix_path.as_posix()
        ):
            raise InvalidStorageReferenceError("Invalid artifact storage reference")
        parts = posix_path.parts
        if len(parts) != 4 or parts[0] != "organizations" or parts[2] != "artifacts":
            raise InvalidStorageReferenceError("Invalid artifact storage reference")
        try:
            organization_id = UUID(parts[1])
            artifact_id = UUID(parts[3])
        except (ValueError, AttributeError):
            raise InvalidStorageReferenceError("Invalid artifact storage reference") from None
        if str(organization_id) != parts[1] or str(artifact_id) != parts[3]:
            raise InvalidStorageReferenceError("Invalid artifact storage reference")

        try:
            target = self._resolved_root.joinpath(*parts).resolve(strict=False)
        except (OSError, RuntimeError):
            raise InvalidStorageReferenceError("Invalid artifact storage reference") from None
        if not target.is_relative_to(self._resolved_root):
            raise InvalidStorageReferenceError("Invalid artifact storage reference")
        return target
