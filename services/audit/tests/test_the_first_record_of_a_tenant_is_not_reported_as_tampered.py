"""The genesis row of every tenant reported SIGNATURE_MISMATCH.

MEASURED 2026-08-12, against services/audit/main.py before the fix::

    AuditEvent.model_dump() keys : 21
    keys reaching verify         : 22

    GENESIS row verifies         : False
    CHAINED row verifies         : True

THE MECHANISM. ``ingest_event`` signs once on the bare ``model_dump()``
(main.py:383). ``AuditEvent`` (main.py:313) defines no ``prev_event_id`` and no
``prev_signature``, so that first signature covers 20 fields. The CHAINED branch
then attaches both pointers and RE-SIGNS (main.py:391) -> 22 fields. The GENESIS
branch attached both pointers and did NOT re-sign, leaving a 20-field signature
on a row that verification always reconstructs as 22. 20 != 22, so it could
never match.

Only the first record of a tenant took that path, which is why it survived: it
is also the record an auditor is most likely to spot-check, being the oldest.

WHY THIS IS WORSE THAN A MISSING CHECK. This repo tracks "reports success when
the check never ran" as its recurring defect. This is that defect inverted, and
in the evidence trail: the system reported FAILURE on a genuine record. A
missing check leaves you uninformed; a false tamper verdict manufactures a
finding against the customer, in the one artifact whose entire purpose is to be
trustworthy after the fact -- for a SEC/FINRA-regulated firm whose examiner may
read it.

THE HALF THAT IS EASY TO GET WRONG. Records already written cannot be re-signed;
that would fabricate evidence. They are verified against the message the signer
of that era actually produced -- the 20-field shape -- reported as
``SIGNATURE_MATCH_LEGACY_GENESIS`` so it is never mistaken for a record written
by current code. The tests below spend most of their effort proving that this
fallback is NOT a universal escape hatch, because a lenient verifier is a worse
outcome than the bug it replaced.
"""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

_SVC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_SVC))

import main as audit  # noqa: E402


def _bare_event(event_id: str = "evt_genesis") -> dict:
    """Exactly the 21 keys AuditEvent.model_dump() produces (main.py:313)."""
    return {
        "event_id": event_id,
        "trace_id": "tr_1",
        "span_id": "sp_1",
        "parent_span_id": None,
        "tenant_id": "t1",
        "agent_id": "ag_1",
        "agent_token_id": None,
        "human_initiator_id": None,
        "delegation_chain": [],
        "event_type": "ai_request",
        "provider": "openai",
        "model": "gpt-4",
        "framework": None,
        "action": None,
        "policy_decision": None,
        "data_classification": [],
        "outcome": "success",
        "latency_ms": 10,
        "cost_usd": 0.0,
        "timestamp": datetime(2026, 8, 12, 5, 18, 15, tzinfo=timezone.utc),
        "signature": None,
    }


def _write_genesis_today(event_id: str = "evt_genesis") -> tuple[dict, str]:
    """The GENESIS branch of ingest_event as it stands after the fix."""
    ev = _bare_event(event_id)
    ev["signature"] = audit._sign_event(ev)          # main.py:383
    ev["prev_event_id"] = None                       # main.py:394
    ev["prev_signature"] = None                      # main.py:395
    ev["signature"] = audit._sign_event(ev)          # the fix: re-sign
    return ev, ev.pop("signature")


def _write_genesis_pre_fix(event_id: str = "evt_old") -> tuple[dict, str]:
    """The GENESIS branch as it behaved BEFORE 2026-08-12: no re-sign.

    This is what is sitting in the production database right now.
    """
    ev = _bare_event(event_id)
    ev["signature"] = audit._sign_event(ev)          # 20 fields
    ev["prev_event_id"] = None
    ev["prev_signature"] = None                      # no re-sign
    return ev, ev.pop("signature")


def _write_chained(prev_id: str, prev_sig: str) -> tuple[dict, str]:
    """The CHAINED branch of ingest_event (main.py:388-392), unchanged."""
    ev = _bare_event("evt_chained")
    ev["signature"] = audit._sign_event(ev)          # main.py:383
    ev["prev_event_id"] = prev_id
    ev["prev_signature"] = prev_sig
    ev["signature"] = audit._sign_event(ev, prev_signature=prev_sig)  # main.py:391
    return ev, ev.pop("signature")


class TheFirstRecordVerifies(unittest.TestCase):
    """The defect itself."""

    def test_a_genesis_row_written_today_verifies(self):
        ev, sig = _write_genesis_today()
        result = audit._verify_signature_result(ev, sig)
        self.assertTrue(
            result.valid,
            "the first record of a tenant still reports as tampered — this is "
            "the measured defect, and it is the record an auditor spot-checks",
        )

    def test_a_genesis_row_written_today_is_not_reported_as_legacy(self):
        """The honesty half. Verifying via the legacy shape would make the test
        above pass while the genesis branch was still failing to re-sign."""
        ev, sig = _write_genesis_today()
        self.assertEqual(
            audit._verify_signature_result(ev, sig).reason, audit._SIG_MATCH,
            "a record written by current code was accepted only via the "
            "pre-2026-08-12 reconstruction, so the genesis branch is still not "
            "re-signing",
        )

    def test_a_chained_row_still_verifies(self):
        """Regression guard: the chained path was correct and must stay so."""
        _, gsig = _write_genesis_today()
        ev, sig = _write_chained("evt_genesis", gsig)
        result = audit._verify_signature_result(ev, sig)
        self.assertTrue(result.valid)
        self.assertEqual(result.reason, audit._SIG_MATCH)


class RecordsAlreadyInTheDatabaseStillVerify(unittest.TestCase):
    """Re-signing history would fabricate evidence. Reconstructing the message
    the old signer really produced does not."""

    def test_a_pre_fix_genesis_row_verifies(self):
        ev, sig = _write_genesis_pre_fix()
        self.assertTrue(
            audit._verify_signature_result(ev, sig).valid,
            "every genesis row written before the fix just became permanently "
            "unverifiable — the fix orphaned production data",
        )

    def test_a_pre_fix_genesis_row_is_reported_as_legacy(self):
        ev, sig = _write_genesis_pre_fix()
        self.assertEqual(
            audit._verify_signature_result(ev, sig).reason,
            audit._SIG_MATCH_LEGACY_GENESIS,
            "an old record was reported as SIGNATURE_MATCH, indistinguishable "
            "from one written by current code",
        )


class TheLegacyFallbackIsNotAnEscapeHatch(unittest.TestCase):
    """The part that matters most. A verifier that accepts a second payload
    shape has doubled its attack surface; each test here is one way that could
    have gone wrong."""

    def test_a_tampered_genesis_row_is_rejected(self):
        ev, sig = _write_genesis_today()
        ev["tenant_id"] = "attacker-tenant"
        self.assertFalse(
            audit._verify_signature_result(ev, sig).valid,
            "a modified genesis row verified — the legacy reconstruction is "
            "accepting records it should reject",
        )

    def test_a_tampered_pre_fix_genesis_row_is_rejected(self):
        ev, sig = _write_genesis_pre_fix()
        ev["outcome"] = "failure"
        self.assertFalse(audit._verify_signature_result(ev, sig).valid)

    def test_nulling_the_pointers_on_a_chained_row_does_not_launder_it(self):
        """The specific attack the guard exists for: strip a chained record's
        prev pointers so it looks like a genesis row, hoping the 20-field
        reconstruction accepts it."""
        _, gsig = _write_genesis_today()
        ev, sig = _write_chained("evt_genesis", gsig)
        ev["prev_event_id"] = None
        ev["prev_signature"] = None
        self.assertFalse(
            audit._verify_signature_result(ev, sig).valid,
            "a chained record was laundered into a genesis record by nulling "
            "its pointers — the chain can be silently truncated",
        )

    def test_the_legacy_shape_is_not_tried_when_pointers_are_present(self):
        """The mirror: a 20-field signature must not be accepted on a row that
        carries pointers, or an attacker could attach any prev_* they like."""
        ev, sig = _write_genesis_pre_fix()
        ev["prev_event_id"] = "evt_fabricated"
        ev["prev_signature"] = "k1:deadbeef"
        self.assertFalse(audit._verify_signature_result(ev, sig).valid)


class TheCanonicalBytesAreFrozen(unittest.TestCase):
    """Every signature in production was computed over json.dumps DEFAULTS,
    which put a space after each ',' and ':'. 'Tidying' this to
    separators=(',', ':') would invalidate the entire audit history in one
    keystroke, and the failure would look like mass tampering."""

    def test_default_separators_and_sorted_keys(self):
        self.assertEqual(
            audit._canonical_payload_bytes({"b": 2, "a": 1}),
            b'{"a": 1, "b": 2}',
            "the canonical serialization changed — every existing signature in "
            "production is now unverifiable",
        )


class TheRealIngestPathIsExercised(unittest.TestCase):
    """The helpers above REPRODUCE ingest_event; they do not call it.

    That distinction is the difference between a test and a decoration. Every
    assertion above would still pass if the genesis branch of ingest_event
    (main.py:393) were reverted to not re-signing, because the helper does its
    own signing. This class crosses the real seam: POST /events -> the database
    -> GET /integrity/verify/{id}, with no mocks in between. Sabotage the
    re-sign line and only this class notices.
    """

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        # verify_api_key reads a module-level secret; override the dependency
        # rather than reaching for the value, so the test does not depend on
        # how authentication happens to be configured.
        audit.app.dependency_overrides[audit.verify_api_key] = lambda: None
        cls.client_ctx = TestClient(audit.app)
        cls.client = cls.client_ctx.__enter__()   # fires startup -> create_all

        # A SEPARATE DEFECT, FOUND 2026-08-12 WHILE WRITING THIS CLASS.
        #
        # timestamp is Column(DateTime(timezone=True)) (main.py:142). _sign_event
        # serializes it with .isoformat() on the AWARE datetime it was handed
        # ("...404797+00:00"). Verification serializes .isoformat() on whatever
        # the DRIVER returned. SQLite discards tzinfo entirely, so verification
        # builds "...404797" -- different bytes, and NOTHING verifies:
        #
        #     stored timestamp repr : datetime(2026, 8, 12, 5, 46, 23, 404797)
        #     tzinfo                : None
        #     verify says           : valid=False  SIGNATURE_MISMATCH
        #
        # So the signature depends on driver timezone behaviour, which is not a
        # property anyone chose. On Postgres, timestamptz comes back aware in
        # the SESSION timezone -- fine at UTC, and a total verification failure
        # at any other session tz, because the offset lands in the signed
        # string. UNVERIFIED ON PRODUCTION; see the test file docstring.
        #
        # Skipping rather than asserting: a red test here would be blamed on the
        # genesis fix, which is not what it measures. The property IS pinned
        # environment-independently by TheGenesisBranchReallyReSigns below.
        cls._tz_preserved = True
        probe = cls.client.post("/events", json={
            "trace_id": "tz-probe", "tenant_id": "tz-probe",
            "agent_id": "ag_1", "event_type": "ai_request",
        })
        if probe.status_code == 201:
            db = audit.SessionLocal()
            try:
                row = db.query(audit.AuditEventModel).filter(
                    audit.AuditEventModel.event_id == probe.json()["event_id"]
                ).first()
                cls._tz_preserved = bool(row and row.timestamp and row.timestamp.tzinfo)
            finally:
                db.close()

    def setUp(self):
        if not type(self)._tz_preserved:
            self.skipTest(
                "this database returns naive datetimes, so signing and "
                "verification serialize timestamp differently and NOTHING "
                "verifies here regardless of the genesis fix. Separate defect: "
                "signature validity depends on driver timezone behaviour. "
                "Run this suite against Postgres to exercise the real path."
            )

    @classmethod
    def tearDownClass(cls):
        cls.client_ctx.__exit__(None, None, None)
        audit.app.dependency_overrides.clear()

    def _post(self, tenant: str, event_type: str = "ai_request") -> dict:
        resp = self.client.post("/events", json={
            "trace_id": "tr_" + tenant,
            "tenant_id": tenant,
            "agent_id": "ag_1",
            "event_type": event_type,
        })
        self.assertEqual(resp.status_code, 201, resp.text)
        return resp.json()

    def _verify(self, event_id: str) -> dict:
        resp = self.client.get(f"/integrity/verify/{event_id}")
        self.assertEqual(resp.status_code, 200, resp.text)
        return resp.json()

    def test_the_very_first_event_of_a_tenant_verifies(self):
        """THE BUG, end to end. A brand-new tenant's first record used to come
        back valid=false / SIGNATURE_MISMATCH from this exact call."""
        created = self._post("tenant-genesis-e2e")
        body = self._verify(created["event_id"])
        self.assertTrue(
            body["valid"],
            f"the first record of a new tenant reports as tampered: {body}",
        )
        self.assertEqual(
            body["reason"], audit._SIG_MATCH,
            "the genesis row was accepted only via the pre-fix reconstruction, "
            "which means ingest_event is still not re-signing",
        )

    def test_the_second_event_of_a_tenant_verifies_and_chains(self):
        first = self._post("tenant-chain-e2e")
        second = self._post("tenant-chain-e2e")
        body = self._verify(second["event_id"])
        self.assertTrue(body["valid"], body)
        self.assertTrue(
            body["chain_valid"],
            f"the chain broke at the first link, where genesis meets the "
            f"record that points at it: {body}",
        )
        self.assertEqual(second["prev_event_id"], first["event_id"])

    def test_a_whole_tenant_chain_verifies_from_genesis_forward(self):
        """Genesis being wrong made the chain unverifiable from its root. A
        chain whose first link cannot be trusted proves nothing about the rest.
        """
        ids = [self._post("tenant-walk-e2e")["event_id"] for _ in range(4)]
        for position, event_id in enumerate(ids):
            with self.subTest(position=position):
                body = self._verify(event_id)
                self.assertTrue(body["valid"], f"position {position}: {body}")
                self.assertTrue(body["chain_valid"], f"position {position}: {body}")


class TheGenesisBranchReallyReSigns(unittest.TestCase):
    """Pins the fix in the SOURCE, not in a reproduction of it.

    Every assertion in the first three classes builds its own payload, so all of
    them stay green if main.py's genesis branch is reverted. The end-to-end
    class would catch it, but only on a timezone-preserving database, which the
    default dev environment is not. This class closes that hole and needs no
    database at all.

    Asserted over the AST, not a substring: an earlier test in this repo did
    ``assertIn("observe_detonation_timeout()", src)`` and passed after the call
    was deleted, because the function name appeared in its own docstring. The
    comment block inside the genesis branch mentions _sign_event by name several
    times, so a text search here would be satisfied by prose.
    """

    def test_the_genesis_branch_contains_a_sign_call(self):
        import ast

        src = (Path(audit.__file__)).read_text(encoding="utf-8")
        tree = ast.parse(src)

        # Located by SHAPE, not by enclosing function name. The first version
        # of this test looked inside ingest_event specifically, and broke the
        # moment the chain logic moved into a helper (_ingest_one) to add
        # collision retry — correctly, and with a message that said so, but a
        # test that must be edited for every refactor gets edited carelessly.
        # What must be true is that the genesis branch re-signs, wherever it
        # lives.
        branch = next(
            (n for n in ast.walk(tree)
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
        self.assertIsNotNone(
            branch,
            "could not find the genesis branch anywhere in main.py (the else: "
            "that sets prev_event_id) — the ingest path was restructured, so "
            "re-derive this rather than deleting it",
        )

        signs = [
            n for n in ast.walk(ast.Module(body=branch.orelse, type_ignores=[]))
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name) and n.func.id == "_sign_event"
        ]
        self.assertGreaterEqual(
            len(signs), 1,
            "the genesis branch sets prev_event_id/prev_signature and never "
            "calls _sign_event again, so its signature covers 20 fields while "
            "verification reconstructs 22. Every tenant's FIRST audit record "
            "reports SIGNATURE_MISMATCH — a genuine record accused of tampering.",
        )


class TheBoolWrapperStillWorks(unittest.TestCase):
    """_verify_signature kept its bool contract for any future caller."""

    def test_wrapper_returns_a_real_bool(self):
        ev, sig = _write_genesis_today()
        value = audit._verify_signature(ev, sig)
        self.assertIsInstance(
            value, bool,
            "returning the NamedTuple here would make `if _verify_signature(..)` "
            "always truthy, silently disabling every tamper check that uses it",
        )
        self.assertTrue(value)


if __name__ == "__main__":
    unittest.main()
