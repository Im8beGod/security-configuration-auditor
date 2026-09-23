import json
from uuid import UUID

import pytest

from app.db.models import ArtifactEvidenceType
from app.profile_resolution.evidence import EvidenceDocument, SnapshotEvidence
from app.profile_resolution.resolver import resolve_profile
from app.profile_resolution.runtime import RuntimeProfileError, parse_runtime_profile


def _manifest(**overrides):
    data = {
        "schema_version": "1.0.0", "profile_id": "acme.netos.1", "profile_version": "1.0.0",
        "profile_version_id": "acme.netos.1@1.0.0", "vendor": "Acme", "product_family": "Edge",
        "os": "NetOS", "structural_reader": "indentation_cli.v1",
        "evidence_types": ["configuration"], "device_classes": ["router"],
        "detection": {"tokens": ["Acme", "NetOS"]},
        "version_constraints": {"supported_major_versions": [1]},
        "capabilities": ["structural_parsing", "semantic_interpretation", "effective_state_resolution", "administrator_training"],
    }
    data.update(overrides)
    return json.dumps(data).encode()


def test_runtime_profile_resolves_only_explicit_matching_version_evidence():
    profile = parse_runtime_profile(_manifest())
    document = EvidenceDocument(UUID(int=1), UUID(int=2), UUID(int=3), UUID(int=4), ArtifactEvidenceType.CONFIGURATION,
                                "acme.txt", "a" * 64, {}, "Acme NetOS version 1.2.3\nfeature secure", 40, False)
    result = resolve_profile(SnapshotEvidence(UUID(int=2), UUID(int=3), UUID(int=4), (document,), (), 32), runtime_manifests=(profile,))
    assert result.selected_profile_version_id == profile.profile_version_id


def test_runtime_profile_rejects_unsafe_reader_and_never_matches_without_version():
    with pytest.raises(RuntimeProfileError):
        parse_runtime_profile(_manifest(structural_reader="python.eval"))
    profile = parse_runtime_profile(_manifest())
    document = EvidenceDocument(UUID(int=1), UUID(int=2), UUID(int=3), UUID(int=4), ArtifactEvidenceType.CONFIGURATION,
                                "acme.txt", "a" * 64, {}, "Acme NetOS", 10, False)
    result = resolve_profile(SnapshotEvidence(UUID(int=2), UUID(int=3), UUID(int=4), (document,), (), 11), runtime_manifests=(profile,))
    assert result.selected_profile_version_id != profile.profile_version_id


def test_runtime_profile_accepts_only_declared_known_canonical_fields():
    profile = parse_runtime_profile(_manifest(canonical_fields=["management.remote.ssh.enabled"]))
    assert profile.coverage_manifest["canonical_fields"] == ("management.remote.ssh.enabled",)
    with pytest.raises(RuntimeProfileError):
        parse_runtime_profile(_manifest(canonical_fields=["not.a.canonical.field"]))
