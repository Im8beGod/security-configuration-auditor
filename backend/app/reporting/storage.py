import os
import tempfile
from abc import ABC, abstractmethod
from functools import lru_cache
from pathlib import Path, PurePosixPath
from uuid import UUID

from app.core.config import Settings, get_settings


class ReportStorageError(Exception): pass
class ReportNotFoundError(ReportStorageError): pass
class InvalidReportReferenceError(ReportStorageError): pass
class ReportAlreadyExistsError(ReportStorageError): pass


class ReportStorage(ABC):
    @abstractmethod
    def write(self, data: bytes, *, organization_id: UUID, report_id: UUID) -> str: ...
    @abstractmethod
    def read(self, reference: str) -> bytes: ...
    @abstractmethod
    def delete(self, reference: str) -> None: ...


class LocalFilesystemReportStorage(ReportStorage):
    def __init__(self, root: Path):
        self.root = Path(root)
        self._root = self.root.resolve(strict=False)

    @staticmethod
    def storage_reference(organization_id: UUID, report_id: UUID) -> str:
        return f"organizations/{organization_id}/reports/{report_id}.pdf"

    def _path(self, reference: str) -> Path:
        path = PurePosixPath(reference)
        if path.is_absolute() or "\\" in reference or len(path.parts) != 4 or path.parts[0] != "organizations" or path.parts[2] != "reports" or not path.parts[3].endswith(".pdf"):
            raise InvalidReportReferenceError("Invalid report storage reference")
        try:
            UUID(path.parts[1]); UUID(path.parts[3][:-4])
            target = self._root.joinpath(*path.parts).resolve(strict=False)
        except (ValueError, OSError, RuntimeError):
            raise InvalidReportReferenceError("Invalid report storage reference") from None
        if not target.is_relative_to(self._root): raise InvalidReportReferenceError("Invalid report storage reference")
        return target

    def write(self, data: bytes, *, organization_id: UUID, report_id: UUID) -> str:
        if not isinstance(data, bytes): raise TypeError("Report data must be bytes")
        reference = self.storage_reference(organization_id, report_id)
        target = self._path(reference); target.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="wb", dir=target.parent, prefix=f".{report_id}.", suffix=".tmp", delete=False) as stream:
                temporary = Path(stream.name); stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.link(temporary, target)
        except FileExistsError: raise ReportAlreadyExistsError("Report already exists") from None
        except OSError: raise ReportStorageError("Unable to store report") from None
        finally:
            if temporary: temporary.unlink(missing_ok=True)
        return reference

    def read(self, reference: str) -> bytes:
        try: return self._path(reference).read_bytes()
        except FileNotFoundError: raise ReportNotFoundError("Report bytes were not found") from None
        except OSError: raise ReportStorageError("Unable to read report") from None

    def delete(self, reference: str) -> None:
        try: self._path(reference).unlink(missing_ok=True)
        except OSError: raise ReportStorageError("Unable to delete report") from None


def create_report_storage(settings: Settings) -> ReportStorage: return LocalFilesystemReportStorage(settings.report_storage_path)

@lru_cache
def get_report_storage() -> ReportStorage: return create_report_storage(get_settings())
