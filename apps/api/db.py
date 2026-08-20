"""Database engine and session for the consumer API."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from models import Base

#: SQLite by default so a developer, and CI, can run the API with nothing
#: installed. Production sets a Postgres URL.
DATABASE_URL = os.getenv("AIPROTECT_DATABASE_URL", "sqlite:///./aiprotect.db")

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, future=True, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    """Bring the database up to the current schema, via Alembic.

    This used to be `create_all`, with a note saying real migrations would
    arrive with the first schema change that had to preserve data. They have.

    `create_all` creates MISSING TABLES and nothing else -- it will not add a
    column to a table that already exists, and it does not complain. So the
    service starts, reports healthy, and then errors on the first query that
    touches the new column. That is the dishonest-health shape in the one
    place where the fix is a data migration rather than a restart.

    Alembic is invoked in-process rather than as a container command so that
    "the service started" and "the schema is current" cannot come apart.
    """
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent / "alembic.ini"))
    cfg.set_main_option("script_location", str(Path(__file__).resolve().parent / "migrations"))
    # The URL the SERVICE uses, not whatever alembic.ini might say -- one
    # source, so a migration cannot be applied to a database nobody serves.
    cfg.set_main_option("sqlalchemy.url", DATABASE_URL)
    command.upgrade(cfg, "head")


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
