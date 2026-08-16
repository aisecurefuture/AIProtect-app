"""Database engine and session for the consumer API."""

from __future__ import annotations

import os
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
    """Create tables. Real migrations arrive with the first schema change that
    has to preserve customer data; until then this is honest about being a
    create_all."""
    Base.metadata.create_all(engine)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
