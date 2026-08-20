"""models.py and the migrations must describe the same schema.

THE FAILURE THIS CATCHES
========================
Adding a column to `models.py` and forgetting the revision. Nothing complains:

  * every test builds its database with `Base.metadata.create_all`, straight
    from the models, so the whole suite passes
  * a fresh deploy runs the migrations, gets a table WITHOUT the column, starts
    cleanly, and reports healthy
  * the first request that touches the column is the first anyone hears of it

That is the same shape as every other defect this codebase is careful about --
a check that passed without covering what it claimed -- except the blast radius
is production data rather than one request.

WHAT THIS DOES
==============
Builds a database from the MIGRATIONS, then asks Alembic to diff it against
the MODELS. Any difference at all is a missing revision. This is the same
comparison `alembic revision --autogenerate` uses, so if this fails the fix is
usually to run exactly that and commit the result.

Deliberately NOT `create_all` on both sides -- that would compare the models
with themselves and pass forever.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

API = Path(__file__).resolve().parent.parent           # apps/api
sys.path.insert(0, str(API))

from alembic import command  # noqa: E402
from alembic.autogenerate import compare_metadata  # noqa: E402
from alembic.config import Config  # noqa: E402
from alembic.migration import MigrationContext  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

from models import Base  # noqa: E402


def _alembic_config(url: str) -> Config:
    cfg = Config(str(API / "alembic.ini"))
    cfg.set_main_option("script_location", str(API / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


class TheMigrationsProduceTheModels(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.url = f"sqlite:///{self._tmp.name}"

    def tearDown(self):
        os.unlink(self._tmp.name)

    def test_upgrading_from_empty_gives_exactly_the_models(self):
        """THE CORE PROPERTY. Run the migrations, diff against the models,
        expect nothing."""
        command.upgrade(_alembic_config(self.url), "head")

        engine = create_engine(self.url, future=True)
        with engine.connect() as conn:
            ctx = MigrationContext.configure(
                conn,
                opts={"compare_type": True, "compare_server_default": True},
            )
            diff = compare_metadata(ctx, Base.metadata)

        self.assertEqual(
            diff, [],
            "The migrations and models.py disagree. Usually this means a "
            "model changed without a revision -- run:\n"
            "  cd apps/api && alembic revision --autogenerate -m 'what changed'\n"
            f"Differences: {diff}",
        )

    def test_migrating_twice_is_a_no_op(self):
        """An upgrade that is already applied must not fail or re-run. init_db
        calls this on EVERY start."""
        cfg = _alembic_config(self.url)
        command.upgrade(cfg, "head")
        command.upgrade(cfg, "head")          # must not raise

        engine = create_engine(self.url, future=True)
        with engine.connect() as conn:
            ctx = MigrationContext.configure(conn)
            self.assertIsNotNone(
                ctx.get_current_revision(),
                "no alembic_version after upgrade -- the database is not stamped",
            )

    def test_the_protection_settings_columns_actually_land(self):
        """Named explicitly: these are the columns whose absence prompted
        migrations in the first place, and the ones the extension and agent
        both read."""
        command.upgrade(_alembic_config(self.url), "head")
        engine = create_engine(self.url, future=True)
        from sqlalchemy import inspect

        cols = {c["name"] for c in inspect(engine).get_columns("subscriptions")}
        self.assertIn("fail_mode", cols)
        self.assertIn("deep_inspection", cols)


class ThereIsExactlyOneHead(unittest.TestCase):
    def test_no_branched_history(self):
        """Two heads means two people generated a revision from the same
        parent, and `upgrade head` becomes ambiguous."""
        from alembic.script import ScriptDirectory

        heads = ScriptDirectory.from_config(
            _alembic_config("sqlite:///:memory:")
        ).get_heads()
        self.assertEqual(
            len(heads), 1,
            f"{len(heads)} migration heads: {heads}. Merge them with "
            "`alembic merge`.",
        )


if __name__ == "__main__":
    unittest.main()
