import json
import os
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import sessionmaker

from app.assessment_packs.catalog import import_external_catalog
from app.cli.bootstrap_admin import bootstrap_admin
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import AssessmentObligation


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_PHASE5_POSTGRES_TEST") != "1",
    reason="Set SIH_PHASE5_POSTGRES_TEST=1 with PostgreSQL available",
)


def test_external_iso_catalog_import_is_versioned_manual_only_and_provenanced():
    engine = create_database_engine(get_settings())
    connection = engine.connect()
    outer = connection.begin()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False)
    try:
        assert connection.scalar(text("select version_num from alembic_version")) == "20260922_0024"
        organization_id, _ = bootstrap_admin(
            factory, "P5 Import", f"p5-{uuid4().hex}",
            f"p5-{uuid4().hex}@example.invalid", "test-only-password",
        )
        payload = json.dumps({
            "schema_version": "1.0.0", "framework": "iso",
            "catalog_id": "licensed-iso", "name": "Licensed ISO control register",
            "source_version": "2022", "source_url": "https://example.invalid/iso.json",
            "profile_version_ids": ["cisco.ios_xe.17@1.0.0"],
            "controls": [
                {"control_id": "A.8.15", "title": "Logging", "severity": "not_assigned", "scope": "organization", "implementation_status": "manual"},
                {"control_id": "A.8.16", "title": "Monitoring", "severity": "not_assigned", "scope": "organization", "implementation_status": "unimplemented"},
            ],
        }, sort_keys=True).encode()
        with factory.begin() as db:
            pack, counts = import_external_catalog(db, organization_id, payload, "iso.json")
            rows = list(db.scalars(select(AssessmentObligation).where(
                AssessmentObligation.assessment_pack_version_id == pack.assessment_pack_version_id,
            )))
            assert counts == {"manual": 1, "unimplemented": 1}
            assert pack.version == 1 and pack.content_digest == rows[0].source_digest
            assert all(row.evaluator_rule_id is None and row.assessment_method == "manual" for row in rows)
            assert all(row.source_url == "https://example.invalid/iso.json" for row in rows)
            assert {row.implementation_status for row in rows} == {"manual", "unimplemented"}
    finally:
        outer.rollback()
        connection.close()
        engine.dispose()
