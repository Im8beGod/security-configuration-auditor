from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.db.engine import get_engine


def check_database_connection(engine: Engine | None = None) -> bool:
    """Execute a minimal query and propagate any connection error."""

    database_engine = engine or get_engine()
    with database_engine.connect() as connection:
        return connection.execute(text("SELECT 1")).scalar_one() == 1
