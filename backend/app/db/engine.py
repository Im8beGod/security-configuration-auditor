from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from app.core.config import Settings, get_settings


def create_database_engine(settings: Settings) -> Engine:
    """Build an engine without opening a database connection."""

    return create_engine(settings.database_url, pool_pre_ping=True)


@lru_cache
def get_engine() -> Engine:
    """Return the process-wide SQLAlchemy engine."""

    return create_database_engine(get_settings())
