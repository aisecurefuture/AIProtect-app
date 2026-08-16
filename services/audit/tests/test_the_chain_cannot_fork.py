"""Two concurrent appends for one tenant must not both link to the same record.

FOUND 2026-08-12, in a spec rather than in code.

``docs/specs/pilot-capacity-model.md:349`` states that the per-tenant write path
"serialises by database constraint (``uq_audit_chain_link``,
``uq_audit_chain_genesis``, both scoped to ``tenant_id``), with collision retry
and jittered backoff up to 8 attempts, then a fail-closed 503" -- and derives a
100-150 appends/s planning ceiling for the 800-seat pilot from it.

A repo-wide grep for ``uq_audit_chain`` returned that one sentence and nothing
else. ``__table_args__`` held two ``Index()`` entries and no ``UniqueConstraint``;
there was no ``IntegrityError`` handler anywhere in the service. The control was
documented, costed, and never built, and a capacity number was derived from a
constraint that did not exist.

WHY A FORK IS THE WORST KIND OF BUG HERE. ``ingest_event`` reads
``_latest_tenant_event`` and then inserts, with no lock between. Two concurrent
appends both read the same predecessor and both set ``prev_event_id`` to it. The
result is two branches -- and **each branch verifies perfectly**: every
signature is intact, every ``prev_signature`` matches a real record, and
``/integrity/verify`` reports valid for both. Nothing in the system can see that
one of two concurrent events is now unreachable from the chain head. An audit
trail that silently drops records while reporting them all valid is worse than
one that admits it cannot check.

It went unnoticed because until 2026-08-12 nothing ever wrote to this table.
Fixing url-trust-gate's 422 made real concurrent writes possible for the first
time, so the latent defect became reachable in the same session -- in the wrong
order, which the spec had explicitly warned about.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SVC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_SVC))

import main as audit  # noqa: E402


class TheConstraintsExist(unittest.TestCase):
    """Pinned against the model, so the spec can never again describe a
    constraint the schema does not have."""

    def setUp(self):
        self.args = audit.AuditEventModel.__table_args__

    def test_the_link_constraint_is_declared(self):
        from sqlalchemy import UniqueConstraint
        names = {
            a.name for a in self.args
            if isinstance(a, UniqueConstraint)
        }
        self.assertIn(
            "uq_audit_chain_link", names,
            "uq_audit_chain_link is named in docs/specs/pilot-capacity-model.md "
            "and is not in the schema. Two concurrent appends will fork the "
            "chain and both branches will verify.",
        )

    def test_the_link_constraint_is_scoped_to_the_tenant(self):
        from sqlalchemy import UniqueConstraint
        con = next(a for a in self.args
                   if isinstance(a, UniqueConstraint) and a.name == "uq_audit_chain_link")
        cols = [c.name for c in con.columns]
        self.assertEqual(
            sorted(cols), ["prev_event_id", "tenant_id"],
            f"uq_audit_chain_link covers {cols}. Without tenant_id it would "
            f"serialise every tenant against every other; without "
            f"prev_event_id it constrains nothing.",
        )

    def test_the_genesis_constraint_exists_and_is_partial(self):
        """Postgres treats NULLs as DISTINCT in a unique index, so the link
        constraint alone permits unlimited records that each claim
        prev_event_id IS NULL -- unlimited tenants' worth of 'first' record."""
        from sqlalchemy import Index
        idx = next(
            (a for a in self.args
             if isinstance(a, Index) and a.name == "uq_audit_chain_genesis"),
            None,
        )
        self.assertIsNotNone(idx, "uq_audit_chain_genesis is missing")
        self.assertTrue(idx.unique, "uq_audit_chain_genesis is not UNIQUE")
        self.assertTrue(
            idx.dialect_options.get("postgresql", {}).get("where") is not None,
            "uq_audit_chain_genesis has no partial WHERE clause, so it would "
            "allow only ONE record per tenant in total, not one genesis record",
        )


class TheRetryPathIsReal(unittest.TestCase):
    """A constraint without a retry turns a routine race into a 500."""

    def test_ingest_retries_on_integrity_error(self):
        import ast
        src = Path(audit.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        handlers = [
            h for n in ast.walk(tree) if isinstance(n, ast.Try)
            for h in n.handlers
            if isinstance(h.type, ast.Name) and h.type.id == "IntegrityError"
        ]
        self.assertTrue(
            handlers,
            "nothing catches IntegrityError, so the new constraint converts a "
            "routine concurrent append into an unhandled 500",
        )

    def test_it_fails_closed_rather_than_reporting_success(self):
        import ast
        src = Path(audit.__file__).read_text(encoding="utf-8")
        self.assertIn(
            "503", src,
            "exhausted retries must fail closed. Returning success for an event "
            "that was not stored is the defect class this service is repeatedly "
            "audited for.",
        )

    def test_backoff_is_jittered(self):
        """Without jitter, two colliding writers sleep identical durations and
        collide again every round — a livelock that reads as contention."""
        values = {audit._chain_backoff_seconds(3) for _ in range(50)}
        self.assertGreater(
            len(values), 1,
            "backoff is deterministic, so two racers will resynchronise on "
            "every retry and exhaust all attempts",
        )

    def test_backoff_is_bounded(self):
        for attempt in range(1, 20):
            with self.subTest(attempt=attempt):
                self.assertLessEqual(
                    audit._chain_backoff_seconds(attempt), audit._CHAIN_BACKOFF_CAP_S)


class TheForkIsActuallyPrevented(unittest.TestCase):
    """The behavioural test: force the race by hand and check the outcome."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        audit.app.dependency_overrides[audit.verify_api_key] = lambda: None
        cls.ctx = TestClient(audit.app)
        cls.client = cls.ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.ctx.__exit__(None, None, None)
        audit.app.dependency_overrides.clear()

    def _post(self, tenant):
        return self.client.post("/events", json={
            "trace_id": "t", "tenant_id": tenant,
            "agent_id": "ag", "event_type": "ai_request",
        })

    def test_sequential_appends_form_one_unbroken_chain(self):
        tenant = "chain-seq"
        ids = [self._post(tenant).json()["event_id"] for _ in range(5)]
        db = audit.SessionLocal()
        try:
            rows = db.query(audit.AuditEventModel).filter(
                audit.AuditEventModel.tenant_id == tenant).all()
            prevs = [r.prev_event_id for r in rows]
            self.assertEqual(
                len(prevs), len(set(prevs)),
                "two records share a predecessor — the chain has forked",
            )
            self.assertEqual(
                sum(1 for p in prevs if p is None), 1,
                "more than one record claims to be the tenant's first",
            )
            self.assertEqual(len(ids), 5)
        finally:
            db.close()

    def test_a_second_genesis_for_one_tenant_is_refused(self):
        """The direct attack on uq_audit_chain_genesis: insert a second record
        claiming prev_event_id IS NULL for a tenant that already has one."""
        tenant = "chain-genesis"
        self._post(tenant)
        db = audit.SessionLocal()
        try:
            row = audit.AuditEventModel(
                event_id="evt_forged_genesis", trace_id="t", span_id="s",
                tenant_id=tenant, agent_id="ag", event_type="ai_request",
                outcome="success", latency_ms=0, cost_usd=0.0,
                timestamp=audit.datetime.now(audit.timezone.utc),
                signature="k2:deadbeef", prev_event_id=None, prev_signature=None,
            )
            db.add(row)
            from sqlalchemy.exc import IntegrityError
            with self.assertRaises(
                IntegrityError,
                msg="a second genesis record was accepted, so a tenant's chain "
                    "can be given a competing root that verifies on its own",
            ):
                db.commit()
        finally:
            db.rollback()
            db.close()


if __name__ == "__main__":
    unittest.main()
