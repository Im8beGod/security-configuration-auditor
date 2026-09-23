"""Opt-in PostgreSQL proof for immutable runtime rule versions."""

import os
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError

from app.compliance.runtime_rules import publish_runtime_rule
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.models import Organization, RuntimeRuleVersion
from app.db.session import create_session_factory


pytestmark = pytest.mark.skipif(
    os.environ.get("SIH_RUNTIME_RULE_POSTGRES_TEST") != "1",
    reason="Set SIH_RUNTIME_RULE_POSTGRES_TEST=1 with PostgreSQL available",
)


def test_runtime_rule_versions_are_db_immutable_and_append_only():
    engine = create_database_engine(get_settings())
    factory = create_session_factory(engine)
    try:
        with factory.begin() as db:
            org = Organization(name="Rule immutability", slug=f"immut-{uuid4().hex[:12]}")
            db.add(org); db.flush()
            profile_version_id = "cisco.ios_xe.17@1.0.0"
            rule_key = f"immut.ssh.{uuid4().hex[:8]}"
            rule = publish_runtime_rule(db, org.organization_id, {"rule_id": rule_key, "profile_version_ids": [profile_version_id], "canonical_field": "management.remote.ssh.enabled", "operator": "equals", "expected": True, "title": "SSH", "security_domain": "management", "severity": "high", "framework_references": []})
            assert rule.version == 1
            rule_id = rule.runtime_rule_version_id
        with factory.begin() as db:
            with pytest.raises(DatabaseError, match="immutable"):
                db.execute(text("UPDATE runtime_rule_versions SET title='changed' WHERE runtime_rule_version_id=:id").bindparams(id=rule_id))
        with factory.begin() as db:
            rule = db.scalar(select(RuntimeRuleVersion).where(RuntimeRuleVersion.rule_id == rule_key))
            with pytest.raises(DatabaseError, match="immutable"):
                db.execute(text("DELETE FROM runtime_rule_versions WHERE runtime_rule_version_id=:id").bindparams(id=rule.runtime_rule_version_id))
        with factory.begin() as db:
            rule = db.scalar(select(RuntimeRuleVersion).where(RuntimeRuleVersion.rule_id == rule_key))
            second = publish_runtime_rule(db, rule.organization_id, {"rule_id": rule_key, "profile_version_ids": [profile_version_id], "canonical_field": "management.remote.ssh.enabled", "operator": "equals", "expected": False, "title": "SSH v2", "security_domain": "management", "severity": "high", "framework_references": []})
            assert second.version == 2
            assert db.scalar(text("SELECT count(*) FROM runtime_rule_versions WHERE rule_id=:rule_id").bindparams(rule_id=rule_key)) == 2
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260924_0027"
    finally:
        engine.dispose()
