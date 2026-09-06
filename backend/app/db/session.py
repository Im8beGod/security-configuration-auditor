from collections.abc import Generator
from functools import lru_cache

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.engine import get_engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Build the shared factory used to create independent sessions."""

    return sessionmaker(
        bind=engine,
        class_=Session,
        autocommit=False,
        autoflush=False,
    )


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    """Return the process-wide session factory."""

    return create_session_factory(get_engine())


def get_db() -> Generator[Session, None, None]:
    """Yield one request-scoped session and always close it afterward."""

    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()
