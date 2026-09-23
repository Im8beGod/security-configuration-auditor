import json
import os
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import sessionmaker

from app.db.engine import create_database_engine
from app.db.models import ArtifactEvidenceType, Organization
from app.core.config import get_settings
from app.profile_resolution.evidence import EvidenceDocument, SnapshotEvidence
from app.profile_resolution.resolver import resolve_profile
from app.profile_resolution.runtime import parse_runtime_profile, publish_runtime_profile, runtime_profiles


pytestmark = pytest.mark.skipif(os.environ.get("SIH_RUNTIME_PROFILE_POSTGRES_TEST") != "1", reason="Set SIH_RUNTIME_PROFILE_POSTGRES_TEST=1 with PostgreSQL available")


def test_runtime_profile_persists_and_is_reused_from_a_fresh_session():
    engine = create_database_engine(get_settings())
    connection = engine.connect()
    outer = connection.begin()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False)
    profile_id = f"runtime.acme.{uuid4().hex[:8]}"
    raw = {"schema_version": "1.0.0", "profile_id": profile_id, "profile_version": "1.0.0", "profile_version_id": f"{profile_id}@1.0.0", "vendor": "Acme", "product_family": "Edge", "os": "NetOS", "structural_reader": "indentation_cli.v1", "evidence_types": ["configuration"], "device_classes": ["router"], "detection": {"tokens": ["Acme", "NetOS"]}, "version_constraints": {"supported_major_versions": [1]}, "capabilities": ["structural_parsing", "semantic_interpretation", "effective_state_resolution", "administrator_training"]}
    try:
        with factory.begin() as db:
            organization = Organization(name="Runtime profile", slug=f"runtime-profile-{uuid4().hex[:10]}")
            db.add(organization); db.flush()
            organization_id = organization.organization_id
            profile = parse_runtime_profile(json.dumps(raw).encode())
            publish_runtime_profile(db, organization_id, profile, raw)
        with factory.begin() as db:
            profiles = runtime_profiles(db, organization_id)
            document = EvidenceDocument(UUID(int=1), organization_id, UUID(int=3), UUID(int=4), ArtifactEvidenceType.CONFIGURATION, "acme.txt", "a" * 64, {}, "Acme NetOS version 1.2.3", 23, False)
            result = resolve_profile(SnapshotEvidence(UUID(int=3), organization_id, UUID(int=4), (document,), (), 23), runtime_manifests=profiles)
            assert result.selected_profile_version_id == profile.profile_version_id
    finally:
        outer.rollback(); connection.close(); engine.dispose()
