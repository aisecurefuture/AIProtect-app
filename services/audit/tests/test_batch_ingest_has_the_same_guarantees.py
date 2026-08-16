"""Whatever POST /events guarantees, POST /events/batch must guarantee too.

FOUND 2026-08-12, while wiring the proxy to write audit events -- which would
have used the batch endpoint.

The genesis-signature defect was fixed in ingest_event earlier the same day and
LEFT IN PLACE in ingest_batch, twenty lines away, in identical code. So was the
new `detail` field: the batch handler built its model without it, meaning
evidence sent in a batch was discarded while the endpoint reported it stored.

And the unique constraint added hours earlier made a third defect reachable:
each event was wrapped in `except Exception: log`, then `db.commit()` ran once
at the end. After an IntegrityError a SQLAlchemy session is in a failed state,
so that final commit raises PendingRollbackError and EVERY event in the batch is
lost -- after the handler has already logged each one individually as fine.

The pattern worth naming: a fix applied to one of two sibling code paths is
half a fix, and the untouched sibling is the one nobody re-reads. These tests
assert the two endpoints agree, so the next such fix cannot be half-applied.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SVC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_SVC))

import main as audit  # noqa: E402


def _event(tenant, eid, **extra):
    body = {
        "event_id": eid, "trace_id": "tr", "tenant_id": tenant,
        "agent_id": "ag", "event_type": "ai_request",
    }
    body.update(extra)
    return body


class BatchMatchesSingle(unittest.TestCase):

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

    def _rows(self, tenant):
        db = audit.SessionLocal()
        try:
            return db.query(audit.AuditEventModel).filter(
                audit.AuditEventModel.tenant_id == tenant).all()
        finally:
            db.close()

    def test_a_batch_genesis_row_is_written_with_its_chain_pointers(self):
        """A behavioural check that does not depend on the database's timezone
        handling.

        The first version of this test recomputed the expected signature from
        the STORED row and compared. It failed — but not for the reason it
        claimed: SQLite returns naive datetimes, so the recomputed payload
        serialises `timestamp` differently from the one the handler signed, and
        the assertion measured that artifact rather than the genesis defect.
        A test that fails for the wrong reason is as misleading as one that
        passes for the wrong reason.

        The signing property is pinned structurally by
        TheBatchGenesisBranchReSigns below; this asserts what is observable
        here — that the row lands with its pointers set.
        """
        tenant = "batch-genesis"
        r = self.client.post("/events/batch", json={
            "events": [_event(tenant, "evt_bg1")]})
        self.assertEqual(r.status_code, 202, r.text)
        rows = self._rows(tenant)
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0].prev_event_id)
        self.assertIsNotNone(rows[0].signature, "the genesis row is unsigned")
        self.assertIsNotNone(rows[0].chain_hash, "the genesis row has no chain hash")

    def test_batch_preserves_detail(self):
        tenant = "batch-detail"
        self.client.post("/events/batch", json={"events": [
            _event(tenant, "evt_bd1", detail={"canonical_url": "https://x.test"})]})
        rows = self._rows(tenant)
        self.assertEqual(
            (rows[0].detail or {}).get("canonical_url"), "https://x.test",
            "evidence sent in a batch was dropped while the endpoint reported "
            "it stored",
        )

    def test_a_batch_forms_one_unbroken_chain(self):
        tenant = "batch-chain"
        self.client.post("/events/batch", json={"events": [
            _event(tenant, f"evt_bc{i}") for i in range(5)]})
        rows = self._rows(tenant)
        self.assertEqual(len(rows), 5)
        prevs = [r.prev_event_id for r in rows]
        self.assertEqual(len(prevs), len(set(prevs)), "the batch forked the chain")
        self.assertEqual(
            sum(1 for p in prevs if p is None), 1,
            "more than one record in the batch claims to be the tenant's first",
        )

    def test_a_duplicate_event_id_does_not_lose_the_rest(self):
        tenant = "batch-partial"
        self.client.post("/events/batch", json={"events": [_event(tenant, "evt_dup")]})
        r = self.client.post("/events/batch", json={"events": [
            _event(tenant, "evt_dup"),          # duplicate
            _event(tenant, "evt_ok1"),
            _event(tenant, "evt_ok2"),
        ]})
        body = r.json()
        ids = {row.event_id for row in self._rows(tenant)}
        self.assertIn("evt_ok1", ids, f"a good event was lost with the bad one: {body}")
        self.assertIn("evt_ok2", ids, f"a good event was lost with the bad one: {body}")

    def test_a_chain_collision_does_not_take_the_batch_down(self):
        """Defect 3, exercised properly.

        The duplicate-event_id test above does NOT reach this path: a duplicate
        is caught by an explicit query before any flush, so no IntegrityError
        occurs and the SAVEPOINT is never used. Removing the savepoint left that
        test green — the sabotage run proved it, which is why this one exists.

        So a REAL collision is forced. A competing record is inserted directly,
        claiming the current head as its predecessor and back-dated so it is not
        itself the head. The batch then reads that same head, tries to claim it
        too, and collides on uq_audit_chain_link — exactly what a concurrent
        writer produces in production.
        """
        from datetime import timedelta
        tenant = "batch-collide"
        self.client.post("/events/batch", json={"events": [_event(tenant, "evt_head")]})
        head = self._rows(tenant)[0]

        db = audit.SessionLocal()
        try:
            db.add(audit.AuditEventModel(
                event_id="evt_competitor", trace_id="tr", span_id="sp",
                tenant_id=tenant, agent_id="ag", event_type="ai_request",
                outcome="success", latency_ms=0, cost_usd=0.0,
                timestamp=head.timestamp - timedelta(minutes=5),   # not the head
                signature="k2:competitor", prev_event_id=head.event_id,
                prev_signature=head.signature,
            ))
            db.commit()
        finally:
            db.close()

        body = self.client.post("/events/batch", json={"events": [
            _event(tenant, "evt_after1"),
            _event(tenant, "evt_after2"),
        ]}).json()

        ids = {row.event_id for row in self._rows(tenant)}
        self.assertIn("evt_head", ids, f"the pre-existing head was lost: {body}")
        self.assertIn(
            "evt_competitor", ids,
            f"a committed record disappeared when a later batch collided with "
            f"it — the batch's failure rolled back more than its own work: {body}",
        )
        self.assertTrue(
            body["stored"] >= 1 or body["failed"],
            f"the batch neither stored nor reported anything: {body}",
        )

    def test_failures_are_reported_not_just_counted(self):
        tenant = "batch-report"
        self.client.post("/events/batch", json={"events": [_event(tenant, "evt_r1")]})
        body = self.client.post("/events/batch", json={"events": [
            _event(tenant, "evt_r1"), _event(tenant, "evt_r2")]}).json()
        self.assertIn(
            "failed", body,
            "the response says how many stored and nothing about which failed "
            "or why — indistinguishable from silent loss",
        )
        self.assertTrue(body["failed"], body)
        self.assertEqual(body["failed"][0]["event_id"], "evt_r1")
        self.assertTrue(body["failed"][0].get("error"), body["failed"][0])


class TheTwoEndpointsCannotDrift(unittest.TestCase):
    """Structural guard against the next half-applied fix."""

    def setUp(self):
        import ast
        self.tree = ast.parse(Path(audit.__file__).read_text(encoding="utf-8"))

    def _fn(self, name):
        import ast
        return next(n for n in ast.walk(self.tree)
                    if isinstance(n, ast.FunctionDef) and n.name == name)

    def test_both_paths_write_detail(self):
        import ast
        for name in ("_ingest_one", "ingest_batch"):
            with self.subTest(fn=name):
                kws = {
                    k.arg for n in ast.walk(self._fn(name))
                    if isinstance(n, ast.Call) for k in n.keywords if k.arg
                }
                self.assertIn(
                    "detail", kws,
                    f"{name} builds AuditEventModel without detail, so evidence "
                    f"sent through it is silently discarded",
                )

    def test_the_batch_genesis_branch_re_signs(self):
        """The defect itself, pinned in the source.

        Over the AST, because the surrounding comments in main.py explain the
        genesis bug at length and name _sign_event repeatedly — a substring
        search would match the explanation and pass while the call was gone.
        """
        import ast
        fn = self._fn("ingest_batch")
        branch = next(
            (n for n in ast.walk(fn)
             if isinstance(n, ast.If) and n.orelse
             and any(
                 isinstance(t, ast.Subscript)
                 and isinstance(t.slice, ast.Constant)
                 and t.slice.value == "prev_event_id"
                 for stmt in n.orelse if isinstance(stmt, ast.Assign)
                 for t in stmt.targets
             )),
            None,
        )
        self.assertIsNotNone(branch, "genesis branch not found in ingest_batch")
        signs = [
            n for n in ast.walk(ast.Module(body=branch.orelse, type_ignores=[]))
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name) and n.func.id == "_sign_event"
        ]
        self.assertGreaterEqual(
            len(signs), 1,
            "ingest_batch's genesis branch attaches prev_event_id and "
            "prev_signature without re-signing, so the first record of every "
            "tenant written through this endpoint can never verify — the exact "
            "defect fixed in ingest_event and left here",
        )

    def test_both_paths_handle_chain_contention(self):
        import ast
        for name in ("ingest_event", "ingest_batch"):
            with self.subTest(fn=name):
                caught = [
                    h for n in ast.walk(self._fn(name)) if isinstance(n, ast.Try)
                    for h in n.handlers
                    if isinstance(h.type, ast.Name) and h.type.id == "IntegrityError"
                ]
                self.assertTrue(
                    caught,
                    f"{name} does not handle IntegrityError, so a chain "
                    f"collision becomes an unhandled failure",
                )


if __name__ == "__main__":
    unittest.main()
