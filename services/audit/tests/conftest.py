"""Hermetic database for the audit suite.

WHY THIS FILE EXISTS
--------------------
``services/audit/main.py`` has the same shape as agent-identity: DATABASE_URL is
read at import time (:29) and the engine is built two lines later (:109) with a
Postgres default. ``create_engine`` imports the DBAPI eagerly, so importing this
service needs psycopg2 -- which is in the service image and not on a dev machine.

This suite did not LOOK broken, and that is the interesting part. Run alone it
was a collection error::

    $ python3 -m pytest -q services/audit/tests/test_batch_chain.py
    ERROR services/audit/tests/test_batch_chain.py     (No module named 'psycopg2')

Run repo-wide it collected fine -- because ``services/policy/tests/conftest.py``
assigns DATABASE_URL to a sqlite URL, conftest files load before any test module,
and audit's main.py then read POLICY's value. The suite was importable only as a
side effect of an unrelated service's test configuration, and only when that
service was part of the same run.

That is a dependency nobody declared and nobody could see: reorder the run,
deselect policy, or fix policy's conftest to be properly scoped, and audit stops
collecting. It gets its own value here so it stands on its own.

ASSIGNED, NOT setdefault(), and a distinct database name per service -- see
services/agent-identity/tests/conftest.py for the full reasoning on both.
"""

import os

os.environ["DATABASE_URL"] = (
    "sqlite:///file:audit_test_shared?mode=memory&cache=shared&uri=true"
)
