from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

import app.db.models  # noqa: F401
from app.db.base import Base, NAMING_CONVENTION


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_CONFIG_PATH = REPOSITORY_ROOT / "database" / "alembic.ini"
MIGRATIONS_PATH = REPOSITORY_ROOT / "database" / "migrations"
BASELINE_REVISION = "20260906_0001"
CURRENT_REVISION = "20260906_0002"
STEP_3_6_REVISION = "20260906_0003"
STEP_3_9_REVISION = "20260906_0004"
STEP_5C_REVISION = "20260907_0005"
STEP_6A_REVISION = "20260907_0006"
STEP_7_1_REVISION = "20260907_0007"
STEP_9_1_REVISION = "20260907_0008"
STEP_9_2_REVISION = "20260907_0009"
STEP_10A_REVISION = "20260907_0010"
STEP_11_1_REVISION = "20260908_0011"
ASSESSMENT_PACK_REVISION = "20260908_0012"
PROFILE_MANIFEST_REVISION = "20260908_0013"
NIST_PACK_REVISION = "20260909_0014"
DISA_PACK_REVISION = "20260909_0015"
CIS_PACK_REVISION = "20260909_0016"
ISO_ALIGNMENT_REVISION = "20260909_0017"


def get_script_directory() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(str(ALEMBIC_CONFIG_PATH)))


def test_alembic_script_location_resolves_from_repository_config() -> None:
    script = get_script_directory()

    assert Path(script.dir).resolve() == MIGRATIONS_PATH.resolve()


def test_migration_history_extends_parentless_baseline() -> None:
    script = get_script_directory()
    revisions = list(script.walk_revisions())

    assert script.get_heads() == [ISO_ALIGNMENT_REVISION]
    assert len(revisions) == 17
    expected = [ISO_ALIGNMENT_REVISION, CIS_PACK_REVISION, DISA_PACK_REVISION, NIST_PACK_REVISION, PROFILE_MANIFEST_REVISION, ASSESSMENT_PACK_REVISION, STEP_11_1_REVISION, STEP_10A_REVISION, STEP_9_2_REVISION, STEP_9_1_REVISION, STEP_7_1_REVISION, STEP_6A_REVISION, STEP_5C_REVISION, STEP_3_9_REVISION, STEP_3_6_REVISION, CURRENT_REVISION, BASELINE_REVISION]
    assert [item.revision for item in revisions] == expected
    assert revisions[0].down_revision == CIS_PACK_REVISION
    assert revisions[-1].down_revision is None


def test_canonical_metadata_has_identity_tables_and_naming_convention() -> None:
    assert set(Base.metadata.tables) == {
        "artifacts", "audits", "devices", "effective_states", "findings", "jobs", "organizations", "security_facts",
        "snapshots", "users", "remediation_procedures", "reports", "unresolved_blocks",
        "mapping_versions", "mapping_validation_runs", "knowledge_packs", "knowledge_pack_versions",
        "assessment_pack_versions", "assessment_obligations", "audit_assessments", "assessment_results", "profile_manifest_versions", "profile_resolution_decisions"
    }
    assert dict(Base.metadata.naming_convention) == NAMING_CONVENTION
