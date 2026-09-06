import os
from importlib import import_module
from pathlib import Path, PurePosixPath
from uuid import uuid4

import pytest

from app.core.config import Settings
from app.ingestion.storage import (
    ArtifactAlreadyExistsError,
    ArtifactNotFoundError,
    ArtifactStorage,
    InvalidStorageReferenceError,
    LocalFilesystemArtifactStorage,
    create_artifact_storage,
)


def test_reference_is_deterministic_logical_and_identity_separated(tmp_path):
    storage = LocalFilesystemArtifactStorage(tmp_path / "private-artifacts")
    organization_id, other_organization_id = uuid4(), uuid4()
    artifact_id, other_artifact_id = uuid4(), uuid4()
    expected = f"organizations/{organization_id}/artifacts/{artifact_id}"

    assert storage.storage_reference(organization_id, artifact_id) == expected
    assert storage.storage_reference(organization_id, artifact_id) == expected
    assert storage.storage_reference(organization_id, other_artifact_id) != expected
    assert storage.storage_reference(other_organization_id, artifact_id) != expected
    assert PurePosixPath(expected).is_absolute() is False
    assert str(tmp_path) not in expected
    # Original filenames cannot affect placement because the storage API never accepts one.
    assert "original_filename" not in storage.write.__annotations__


@pytest.mark.parametrize("data", [b"", b"\x00\xff\x10binary\r\nbytes"])
def test_write_read_exists_round_trip_and_lazy_directories(tmp_path, data):
    root = tmp_path / "not-created-yet"
    storage = LocalFilesystemArtifactStorage(root)
    assert not root.exists()
    reference = storage.write(data, organization_id=uuid4(), artifact_id=uuid4())
    assert root.is_dir()
    assert storage.exists(reference)
    assert storage.read(reference) == data
    assert (root / Path(*PurePosixPath(reference).parts)).is_file()


def test_distinct_artifacts_and_immutable_overwrite(tmp_path):
    storage = LocalFilesystemArtifactStorage(tmp_path)
    organization_id, first_id, second_id = uuid4(), uuid4(), uuid4()
    first = storage.write(b"original", organization_id=organization_id, artifact_id=first_id)
    second = storage.write(b"different", organization_id=organization_id, artifact_id=second_id)
    assert first != second
    with pytest.raises(ArtifactAlreadyExistsError):
        storage.write(b"replacement", organization_id=organization_id, artifact_id=first_id)
    assert storage.read(first) == b"original"
    assert not list((tmp_path / "organizations" / str(organization_id) / "artifacts").glob("*.tmp"))


def test_bounded_prefix_read_never_returns_more_than_requested(tmp_path):
    storage = LocalFilesystemArtifactStorage(tmp_path)
    reference = storage.write(b"0123456789", organization_id=uuid4(), artifact_id=uuid4())
    assert storage.read_prefix(reference, 4) == b"0123"
    assert storage.read(reference) == b"0123456789"
    with pytest.raises(ValueError):
        storage.read_prefix(reference, 0)


@pytest.mark.parametrize("reference", [
    "../secret", "../../outside", "/absolute/path",
    r"C:\Windows\System32\something", r"\\server\share\file",
    "organizations//00000000-0000-0000-0000-000000000000/artifacts/00000000-0000-0000-0000-000000000000",
    "organizations/00000000-0000-0000-0000-000000000000/artifacts/../secret",
])
def test_unsafe_references_are_rejected_for_read_and_exists(tmp_path, reference):
    storage = LocalFilesystemArtifactStorage(tmp_path)
    with pytest.raises(InvalidStorageReferenceError):
        storage.read(reference)
    with pytest.raises(InvalidStorageReferenceError):
        storage.exists(reference)


def test_missing_reference_has_controlled_semantics(tmp_path):
    storage = LocalFilesystemArtifactStorage(tmp_path)
    reference = storage.storage_reference(uuid4(), uuid4())
    assert storage.exists(reference) is False
    with pytest.raises(ArtifactNotFoundError):
        storage.read(reference)


def test_delete_is_idempotent_and_reference_validated(tmp_path):
    storage = LocalFilesystemArtifactStorage(tmp_path)
    reference = storage.write(b"temporary", organization_id=uuid4(), artifact_id=uuid4())
    storage.delete(reference)
    storage.delete(reference)
    assert storage.exists(reference) is False
    with pytest.raises(InvalidStorageReferenceError):
        storage.delete("../outside")


def test_resolution_failure_is_a_controlled_reference_error(tmp_path, monkeypatch):
    storage = LocalFilesystemArtifactStorage(tmp_path)
    reference = storage.storage_reference(uuid4(), uuid4())
    monkeypatch.setattr(Path, "resolve", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("simulated symlink loop")
    ))
    with pytest.raises(InvalidStorageReferenceError):
        storage.read(reference)


def test_symlink_escape_is_rejected_when_supported(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "outside"
    organization_id, artifact_id = uuid4(), uuid4()
    link = root / "organizations" / str(organization_id)
    outside.mkdir()
    (outside / "artifacts").mkdir()
    (outside / "artifacts" / str(artifact_id)).write_bytes(b"outside")
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"Symlink creation unavailable on this platform: {exc}")
    storage = LocalFilesystemArtifactStorage(root)
    reference = storage.storage_reference(organization_id, artifact_id)
    with pytest.raises(InvalidStorageReferenceError):
        storage.read(reference)
    with pytest.raises(InvalidStorageReferenceError):
        storage.exists(reference)


def test_provider_uses_configured_root_without_creating_it(tmp_path, auth_settings: Settings):
    configured_root = tmp_path / "configured" / "artifacts"
    settings = auth_settings.model_copy(update={"artifact_storage_path": configured_root})
    storage = create_artifact_storage(settings)
    assert isinstance(storage, ArtifactStorage)
    assert isinstance(storage, LocalFilesystemArtifactStorage)
    assert storage.root == configured_root
    assert not configured_root.exists()

    storage_package = import_module("app.ingestion.storage")
    storage_package.get_artifact_storage.cache_clear()
    original_get_settings = storage_package.get_settings
    storage_package.get_settings = lambda: settings
    try:
        provided = storage_package.get_artifact_storage()
        assert isinstance(provided, ArtifactStorage)
        assert provided.root == configured_root
        assert storage_package.get_artifact_storage() is provided
        assert not configured_root.exists()
    finally:
        storage_package.get_artifact_storage.cache_clear()
        storage_package.get_settings = original_get_settings
