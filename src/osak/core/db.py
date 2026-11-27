"""Synchronous SQLAlchemy database setup.

The core deliberately exposes a synchronous session factory.  Ingestion, API
request handlers and Alembic can all use the same transaction semantics without
requiring an async driver in local deployments.
"""

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from osak.core.settings import get_settings


class Base(DeclarativeBase):
    """Declarative base for all OSAK-owned tables."""


def _engine_options(database_url: str) -> dict[str, Any]:
    if database_url.startswith("sqlite"):
        options: dict[str, Any] = {"connect_args": {"check_same_thread": False}}
        if database_url in {"sqlite:///:memory:", "sqlite+pysqlite:///:memory:"}:
            options["poolclass"] = StaticPool
        return options
    return {"pool_pre_ping": True}


def create_database_engine(database_url: str | None = None) -> Engine:
    """Create an engine for *database_url* or the configured URL."""

    url = database_url or get_settings().database_url
    # ``postgres://`` is still common in deployment secrets, while SQLAlchemy
    # requires an explicit driver for psycopg 3 in this project.
    if url.startswith("postgres://"):
        url = "postgresql+psycopg://" + url.removeprefix("postgres://")
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url.removeprefix("postgresql://")
    return create_engine(url, future=True, **_engine_options(url))


engine = create_database_engine()
SessionLocal = sessionmaker(
    bind=engine,
    class_=Session,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def configure_database(database_url: str) -> None:
    """Rebind the shared session factory, primarily for tests and CLI commands."""

    global engine
    engine.dispose()
    engine = create_database_engine(database_url)
    SessionLocal.configure(bind=engine)


@contextmanager
def session_scope(*, isolation_level: str | None = None) -> Generator[Session, None, None]:
    """Yield a session and commit it, rolling back on failure.

    ``REPEATABLE READ`` is used by the dataset exporter on PostgreSQL so its
    multi-table streaming read cannot mix rows committed by concurrent source
    polls.  SQLite keeps its normal transaction behavior for local tests.
    """

    session = SessionLocal()
    try:
        if isolation_level and session.get_bind().dialect.name == "postgresql":
            session.connection(execution_options={"isolation_level": isolation_level})
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
