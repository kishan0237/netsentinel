"""Database setup: engine, sessions, declarative base, table init.

Uses DATABASE_URL (Supabase Postgres in production, SQLite for local dev/tests).
"""

import os
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# Treat empty-string env vars (e.g. Render env var left blank) as unset
DATABASE_URL = os.getenv("DATABASE_URL") or "sqlite:///./netsentinel.db"
AUTO_CREATE_TABLES = os.getenv("AUTO_CREATE_TABLES", "true").lower() != "false"

IS_SQLITE = DATABASE_URL.startswith("sqlite")

# sqlite needs this for FastAPI's thread-per-request model; check_same_thread
# is a sqlite-only argument so it must not be passed to postgres.
connect_args = {"check_same_thread": False} if IS_SQLITE else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,  # survive Supabase pooler disconnects
    pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
    max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),
)

if IS_SQLITE:

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, connection_record):  # pragma: no cover
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    """Declarative base shared by all models."""


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create tables if they do not exist.

    In production, prefer running supabase/migrations/0001_init.sql in the
    Supabase SQL editor; create_all is idempotent and safe either way.
    """
    from app.backend.database import models  # noqa: F401  (registers all models)

    Base.metadata.create_all(bind=engine)
