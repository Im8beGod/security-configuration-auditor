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


def get_script_directory() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(str(ALEMBIC_CONFIG_PATH)))


def test_alembic_script_location_resolves_from_repository_config() -> None:
    script = get_script_directory()

    assert Path(script.dir).resolve() == MIGRATIONS_PATH.resolve()


def test_migration_history_extends_parentless_baseline() -> None:
    script = get_script_directory()
    revisions = list(script.walk_revisions())

    assert script.get_heads() == [STEP_9_2_REVISION]
    assert len(revisions) == 9
    assert revisions[0].revision == STEP_9_2_REVISION
    assert revisions[0].down_revision == STEP_9_1_REVISION
    assert revisions[1].revision == STEP_9_1_REVISION
    assert revisions[1].down_revision == STEP_7_1_REVISION
    assert revisions[2].revision == STEP_7_1_REVISION
    assert revisions[2].down_revision == STEP_6A_REVISION
    assert revisions[3].revision == STEP_6A_REVISION
    assert revisions[3].down_revision == STEP_5C_REVISION
    assert revisions[4].revision == STEP_5C_REVISION
    assert revisions[4].down_revision == STEP_3_9_REVISION
    assert revisions[5].revision == STEP_3_9_REVISION
    assert revisions[5].down_revision == STEP_3_6_REVISION
    assert revisions[6].revision == STEP_3_6_REVISION
    assert revisions[6].down_revision == CURRENT_REVISION
    assert revisions[7].revision == CURRENT_REVISION
    assert revisions[7].down_revision == BASELINE_REVISION
    assert revisions[8].revision == BASELINE_REVISION
    assert revisions[8].down_revision is None


def test_canonical_metadata_has_identity_tables_and_naming_convention() -> None:
    assert set(Base.metadata.tables) == {
        "artifacts", "audits", "devices", "effective_states", "findings", "jobs", "organizations", "security_facts",
        "snapshots", "users", "remediation_procedures"
    }
    assert dict(Base.metadata.naming_convention) == NAMING_CONVENTION
