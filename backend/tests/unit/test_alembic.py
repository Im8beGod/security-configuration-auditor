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


def get_script_directory() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(str(ALEMBIC_CONFIG_PATH)))


def test_alembic_script_location_resolves_from_repository_config() -> None:
    script = get_script_directory()

    assert Path(script.dir).resolve() == MIGRATIONS_PATH.resolve()


def test_migration_history_extends_parentless_baseline() -> None:
    script = get_script_directory()
    revisions = list(script.walk_revisions())

    assert script.get_heads() == [STEP_3_9_REVISION]
    assert len(revisions) == 4
    assert revisions[0].revision == STEP_3_9_REVISION
    assert revisions[0].down_revision == STEP_3_6_REVISION
    assert revisions[1].revision == STEP_3_6_REVISION
    assert revisions[1].down_revision == CURRENT_REVISION
    assert revisions[2].revision == CURRENT_REVISION
    assert revisions[2].down_revision == BASELINE_REVISION
    assert revisions[3].revision == BASELINE_REVISION
    assert revisions[3].down_revision is None


def test_canonical_metadata_has_identity_tables_and_naming_convention() -> None:
    assert set(Base.metadata.tables) == {
        "artifacts", "audits", "devices", "jobs", "organizations", "snapshots", "users"
    }
    assert dict(Base.metadata.naming_convention) == NAMING_CONVENTION
