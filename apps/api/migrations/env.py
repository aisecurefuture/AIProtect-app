"""Alembic environment for the consumer API.

The database URL comes from the SAME place the service reads it
(`AIPROTECT_DATABASE_URL`, via db.py) rather than from alembic.ini. Two
sources for one URL is how a migration gets applied to a database nobody is
serving from, and reported as a success.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# apps/api uses flat imports (`import models`), so it has to be importable.
API_DIR = Path(__file__).resolve().parent.parent
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

from models import Base  # noqa: E402

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# A URL set by the CALLER wins. `init_db()` and the schema tests both build a
# Config and set it explicitly, and an env.py that overrode them would migrate
# a different database than the one they asked about -- which is how a test
# reports a clean schema for a file nobody is using, and how `init_db` on a
# Postgres deployment could quietly touch a local SQLite file instead.
if not config.get_main_option("sqlalchemy.url", None):
    config.set_main_option(
        "sqlalchemy.url",
        os.getenv("AIPROTECT_DATABASE_URL", "sqlite:///./aiprotect.db"),
    )

target_metadata = Base.metadata


def _common_kwargs():
    return {
        "target_metadata": target_metadata,
        # SQLite cannot ALTER most things in place. Batch mode rewrites the
        # table instead, so the same revision works on SQLite (dev, CI) and
        # Postgres (production) without a second code path.
        "render_as_batch": True,
        "compare_type": True,
        "compare_server_default": True,
    }


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        **_common_kwargs(),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, **_common_kwargs())
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
