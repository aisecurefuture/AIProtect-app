"""Every evidence write the URL Trust Gate has ever made was rejected.

MEASURED 2026-08-12: production ``audit_events`` held ZERO rows for every
tenant, ever. This writer was one of the three reasons.

    services/url-trust-gate/evidence.py   body = {"kind": "url-trust-gate",
                                                  "data": payload}
    services/audit/main.py                trace_id: str      <- required
                                          agent_id: str      <- required
                                          event_type: str    <- required

None of the three has a default, so FastAPI rejected the body with 422 before
the handler ran -- on every attempt, since the code was written. The writer
treats 4xx as unretryable, logs a warning, and returns None; the gate then
answers **200 with evidence_id: null**. So the URL Trust Gate reported success
and stored nothing, and the only trace was a log line nobody was reading.

WHY THE OBVIOUS FIX WOULD HAVE BEEN WORSE, AND WHY THIS FILE TESTS WHAT IT DOES.
Adding just the three required fields makes the POST return 201 -- and
pydantic's default ``extra='ignore'`` then silently discards ``kind`` and
``data``. Measured directly::

    AuditEvent(trace_id=..., agent_id=..., event_type=...,
               data={...}, kind=..., evidence_id=...).model_dump()
    -> extra fields survive?  NO — silently dropped

That would have replaced a loud 422 with a silent evidence loss behind a
success code: no canonical URL, no scores, no IOCs, no decision, no redirect
chain. Strictly worse than the bug, and invisible. So ``detail`` was added to
AuditEvent as a DECLARED field -- which also means the evidence is covered by
the record's signature, because an audit record whose evidence is unsigned is
not evidence.

These tests drive the REAL audit service, not a mock of it. A mock would have
been perfectly happy with the broken body for as long as this code has existed;
that is precisely how the bug survived.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path

_GATE = Path(__file__).resolve().parents[1]              # services/url-trust-gate
_REPO = _GATE.parent.parent
sys.path.insert(0, str(_GATE))
sys.path.insert(0, str(_REPO / "libs" / "cyberarmor-core"))

import evidence as gate_evidence  # noqa: E402


def _load_audit_main():
    """Load services/audit/main.py under a unique name.

    Both services ship a module called ``main``. Importing by name would
    resolve to whichever directory sits earlier on sys.path — a coin flip that
    would make this test assert against the wrong service's schema, which is
    the exact class of mistake it exists to catch.
    """
    # A UNIQUELY NAMED DATABASE, SET UNCONDITIONALLY, THEN RESTORED.
    #
    # This was os.environ.setdefault(...), which meant that if any suite
    # earlier in a repo-wide run had already set DATABASE_URL, this module
    # bound the audit engine to THAT database and shared its lifetime. A
    # shared-cache in-memory SQLite lives only while a connection is held, so
    # when this module's client closed, the other suite's database went with
    # it and control-plane's corpus manifest tests failed with
    # "sqlite3.ProgrammingError: Cannot operate on a closed database" —
    # a failure in a service this change does not touch, from a test file that
    # passed on its own. Found by sabotage-adjacent cross-suite runs, not by
    # this file's own results.
    #
    # Restoring the previous value afterwards matters as much as setting it:
    # the engine is built during exec_module, so by the time we put the old
    # value back, this module already owns its own database and nobody else's
    # configuration has been changed.
    prior_db = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = (
        "sqlite:///file:utg_evidence_audit?mode=memory&cache=shared&uri=true"
    )
    os.environ.setdefault("CYBERARMOR_AUDIT_SIGNING_KEY", "test-signing-key")
    path = _REPO / "services" / "audit" / "main.py"
    spec = importlib.util.spec_from_file_location("cyberarmor_audit_main", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cyberarmor_audit_main"] = mod
    try:
        spec.loader.exec_module(mod)
    finally:
        if prior_db is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = prior_db
    return mod


audit = _load_audit_main()


def _record(**overrides) -> gate_evidence.EvidenceRecord:
    base = dict(
        request_id="req-abc",
        tenant_id="t1",
        source="proxy",
        user_id="user-1",
        app_id="app-1",
        agent_id="agent-7",
        canonical_url="https://example.test/phish",
        url_fingerprint="fp-deadbeef",
        redirect_chain=["https://a.test", "https://example.test/phish"],
        content_hash="ch-1",
        screenshot_hash="sh-1",
        scores={"reputation": 0.91, "content": 0.4},
        iocs=[{"type": "domain", "value": "example.test"}],
        decision={"action": "block", "reason": "known_phish", "risk_score": 0.91},
        crawled=True,
        detonated=False,
        recorded_at="2026-08-12T00:00:00Z",
    )
    base.update(overrides)
    return gate_evidence.EvidenceRecord(**base)


def _body(rec):
    from dataclasses import asdict
    payload = {"evidence_id": "ev-1", **asdict(rec)}
    return gate_evidence._as_audit_event("ev-1", rec, payload)


class TheBodyIsAcceptedByTheRealSchema(unittest.TestCase):
    """The 422, pinned against the actual model rather than a copy of it."""

    def test_the_new_body_validates(self):
        audit.AuditEvent(**_body(_record()))   # raises if it would 422

    def test_the_old_body_would_have_been_rejected(self):
        """Pins that this was a real defect, not a refactor. If this ever stops
        raising, AuditEvent grew defaults for its required fields and the
        original bug would now pass silently."""
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            audit.AuditEvent(kind="url-trust-gate", data={"anything": 1})

    def test_a_record_with_no_agent_still_validates(self):
        """agent_id is Optional on EvidenceRecord and REQUIRED on AuditEvent.
        A URL fetched by something unattributable is the case that matters
        most, and it is exactly the one a missing fallback would drop."""
        body = _body(_record(agent_id=None, user_id=None, request_id=None))
        ev = audit.AuditEvent(**body)
        self.assertTrue(ev.agent_id, "agent_id empty — this write would 422")
        self.assertTrue(ev.trace_id, "trace_id empty — nothing to correlate on")


class TheEvidenceSurvivesTheRoundTrip(unittest.TestCase):
    """Validation is not the goal; keeping the evidence is."""

    def test_the_url_and_findings_reach_the_model(self):
        ev = audit.AuditEvent(**_body(_record()))
        self.assertEqual(ev.detail["canonical_url"], "https://example.test/phish")
        self.assertEqual(ev.detail["scores"]["reputation"], 0.91)
        self.assertEqual(ev.detail["iocs"][0]["value"], "example.test")
        self.assertEqual(ev.detail["redirect_chain"][-1], "https://example.test/phish")
        self.assertEqual(ev.detail["evidence_id"], "ev-1")

    def test_no_evidence_field_is_silently_lost(self):
        """Enumerated from the dataclass itself, so a new EvidenceRecord field
        cannot be added without either travelling or failing this test."""
        from dataclasses import fields
        ev = audit.AuditEvent(**_body(_record()))
        carried = set(ev.detail)
        for f in fields(gate_evidence.EvidenceRecord):
            with self.subTest(field=f.name):
                self.assertIn(
                    f.name, carried,
                    f"EvidenceRecord.{f.name} reaches the audit service nowhere. "
                    f"pydantic drops unknown keys silently, so this would vanish "
                    f"behind a 201.",
                )

    def test_the_decision_is_also_promoted_to_a_declared_field(self):
        """detail is the safety net, not the interface. A verdict buried only
        in a JSON blob cannot be queried, so it also lands in policy_decision
        and outcome where the rest of the platform can read it."""
        ev = audit.AuditEvent(**_body(_record()))
        self.assertEqual(ev.outcome, "block")
        self.assertEqual(ev.policy_decision.decision, "block")
        self.assertEqual(ev.policy_decision.reason_code, "known_phish")
        self.assertAlmostEqual(ev.policy_decision.risk_score, 0.91)
        self.assertEqual(ev.action.target_system, "https://example.test/phish")


class ItActuallyLandsAndVerifies(unittest.TestCase):
    """The full seam: POST to the real service, read it back, verify it."""

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

    def _stored_row(self, event_id):
        db = audit.SessionLocal()
        try:
            return db.query(audit.AuditEventModel).filter(
                audit.AuditEventModel.event_id == event_id).first()
        finally:
            db.close()

    def _require_tz_preserving_db(self):
        """The two verification tests below cannot run on a naive-datetime DB.

        SQLite discards tzinfo, so _sign_event serialises the timestamp as
        "...+00:00" and verification rebuilds "..." — different bytes, and
        NOTHING verifies regardless of this change. Documented in
        services/audit/tests/test_the_first_record_of_a_tenant_is_not_reported_
        as_tampered.py; production Postgres is UTC and round-trips identically.
        Skipping rather than asserting, so a red test here is never mistaken
        for a defect in the evidence mapping — which is what this file measures.
        """
        row = self._stored_row(
            self.client.post("/events", json=_body(_record())).json()["event_id"])
        if not (row and row.timestamp and row.timestamp.tzinfo):
            self.skipTest(
                "this database returns naive datetimes, so signature "
                "verification cannot succeed here for any record. Run against "
                "Postgres to exercise signing end to end."
            )

    def test_the_write_is_accepted_and_the_evidence_is_stored(self):
        resp = self.client.post("/events", json=_body(_record()))
        self.assertEqual(
            resp.status_code, 201,
            f"the evidence write was rejected: {resp.status_code} {resp.text[:300]}",
        )
        row = self._stored_row(resp.json()["event_id"])
        self.assertIsNotNone(row, "the service acked a write that stored nothing")
        self.assertEqual(
            (row.detail or {}).get("canonical_url"), "https://example.test/phish",
            "the record landed but the evidence did not — this is the silent "
            "loss that adding only the required fields would have produced",
        )
        self.assertEqual((row.detail or {}).get("scores", {}).get("reputation"), 0.91)

    def test_the_old_body_is_still_rejected_by_the_running_service(self):
        resp = self.client.post("/events", json={"kind": "url-trust-gate",
                                                 "data": {"anything": 1}})
        self.assertEqual(resp.status_code, 422, resp.text[:200])

    def test_the_stored_record_verifies(self):
        """Evidence in an unsigned field would be evidence nobody can rely on.
        detail is declared, so it is inside the signature."""
        self._require_tz_preserving_db()
        created = self.client.post("/events", json=_body(_record())).json()
        body = self.client.get(f"/integrity/verify/{created['event_id']}").json()
        self.assertTrue(body["valid"], body)

    def test_tampering_with_the_evidence_breaks_the_signature(self):
        """The property that makes detail worth having. Rewrite the stored URL
        directly in the database and the record must stop verifying."""
        self._require_tz_preserving_db()
        created = self.client.post("/events", json=_body(_record())).json()
        db = audit.SessionLocal()
        try:
            row = db.query(audit.AuditEventModel).filter(
                audit.AuditEventModel.event_id == created["event_id"]).first()
            row.detail = {**(row.detail or {}), "canonical_url": "https://harmless.test"}
            db.commit()
        finally:
            db.close()
        body = self.client.get(f"/integrity/verify/{created['event_id']}").json()
        self.assertFalse(
            body["valid"],
            "the evidence was rewritten and the record still verifies — detail "
            "is outside the signed payload, so the stored URL proves nothing",
        )


class TheWriterActuallySendsTheMappedBody(unittest.TestCase):
    """What EvidenceWriter.write() puts on the wire, not what a helper returns.

    THIS CLASS EXISTS BECAUSE THE REST OF THE FILE DID NOT CATCH A SABOTAGE.
    Every other test calls _as_audit_event directly, so reverting the CALL SITE
    in write() back to the broken ``{"kind": ..., "data": ...}`` left all of
    them green. A mapper nobody calls is worth nothing, and testing the mapper
    is not testing the writer.

    So the transport is intercepted and the real body is inspected.
    """

    def _capture(self, record):
        import asyncio
        captured = {}

        class _Resp:
            status_code = 201
            text = ""

        class _FakeClient:
            def __init__(self, *a, **k): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def post(self, url, json=None, headers=None):
                captured["url"] = url
                captured["json"] = json
                return _Resp()

        real = gate_evidence.httpx.AsyncClient
        gate_evidence.httpx.AsyncClient = _FakeClient
        try:
            writer = gate_evidence.EvidenceWriter(
                audit_url="http://audit:8011", audit_secret="s")
            asyncio.run(writer.write(record))
        finally:
            gate_evidence.httpx.AsyncClient = real
        return captured

    def test_the_body_the_writer_sends_validates_against_the_real_schema(self):
        sent = self._capture(_record())
        self.assertIn("json", sent, "the writer never issued a POST")
        audit.AuditEvent(**sent["json"])      # raises if this would 422

    def test_the_body_the_writer_sends_carries_the_evidence(self):
        sent = self._capture(_record())
        detail = sent["json"].get("detail") or {}
        self.assertEqual(detail.get("canonical_url"), "https://example.test/phish")
        self.assertEqual(detail.get("iocs", [{}])[0].get("value"), "example.test")

    def test_it_posts_to_the_events_endpoint(self):
        sent = self._capture(_record())
        self.assertTrue(str(sent.get("url", "")).endswith("/events"), sent.get("url"))


class TheFeedbackPathReadsTheResponse(unittest.TestCase):
    """The second call site, and the worse of the two.

    /feedback did ``await client.post(...)`` and threw the response away. Its
    ``except Exception`` therefore caught transport failures only -- a 422,
    which is what every one of these writes returned, passed as success, and
    the endpoint answered ``{"status": "accepted"}`` regardless. Its docstring
    claimed the failure was counted in Prometheus: true for a dropped socket,
    false for the failure that was actually happening, every time.

    Asserted over the AST. The replacement comment in main.py explains all of
    this in prose and names status_code, so a substring search would match the
    explanation and pass while the code went back to discarding the response --
    the exact way a test in this repo went vacuous before.
    """

    @classmethod
    def setUpClass(cls):
        import ast
        cls.tree = ast.parse((_GATE / "main.py").read_text(encoding="utf-8"))
        cls.fn = next(
            (n for n in ast.walk(cls.tree)
             if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef))
             and "feedback" in n.name),
            None,
        )

    def test_the_feedback_handler_exists(self):
        self.assertIsNotNone(self.fn, "no feedback handler found; test is stale")

    def test_the_audit_response_status_is_actually_COMPARED(self):
        """A mere reference to status_code is not enough, and this test learned
        that the hard way: its first version asserted the attribute appeared
        anywhere in the function, and passed when the guard was sabotaged to
        ``if False:`` — because status_code was still named in the log line
        INSIDE the dead block. The status must take part in a comparison."""
        import ast
        compared = []
        for node in ast.walk(self.fn):
            if not isinstance(node, ast.Compare):
                continue
            for side in [node.left, *node.comparators]:
                if isinstance(side, ast.Attribute) and side.attr == "status_code":
                    compared.append(node)
        self.assertTrue(
            compared,
            "the feedback handler never COMPARES the audit response status, so "
            "a rejected write is indistinguishable from a stored one and the "
            "analyst's correction is lost silently",
        )

    def test_the_required_audit_fields_are_sent(self):
        import ast
        keys = {
            n.value for n in ast.walk(self.fn)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
        }
        for required in ("trace_id", "agent_id", "event_type"):
            with self.subTest(field=required):
                self.assertIn(
                    required, keys,
                    f"{required} is not sent; AuditEvent requires it with no "
                    f"default, so this write returns 422 every time",
                )

    def test_the_feedback_payload_travels_in_a_declared_field(self):
        import ast
        keys = {
            n.value for n in ast.walk(self.fn)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
        }
        self.assertIn(
            "detail", keys,
            "the feedback body does not use the declared detail field, so "
            "pydantic drops it and the analyst's correction is discarded "
            "behind a 201",
        )


if __name__ == "__main__":
    unittest.main()
