"""An audit outage must not slow down enforcement.

MEASURED 2026-08-14. /evaluate contained::

    # write() returns None on failure; gate decision is never blocked by it.
    evidence_id = await _evidence.write(EvidenceRecord(...))

That comment is true of the DECISION and false of the REQUEST. ``write()`` retries
3 times at 0.25/0.5/1.0s backoff with a 2s timeout each, so a DOWN audit service
added up to ~8 seconds to every /evaluate call -- and the MITM proxy calls
/evaluate on every inspected request.

The consequence was observed, not theorised: restarting the audit service pushed
this container's own healthcheck past its timeout and the host watchdog emailed
"Unhealthy (unmanaged): docker-compose-url-trust-gate-1". An audit outage
degraded the enforcement path, on a security product, because of a write whose
comment said it could not.

The old failure mode was also lossy in a way that looked handled: on final
failure it emitted a ``evidence_write_dead_letter`` log line containing the
serialised payload "so it can be recovered from log aggregation". Nobody was
recovering anything from those lines -- production audit_events held ZERO rows
while they accumulated. Evidence whose recovery depends on someone grepping logs
is evidence that does not exist.

Both are fixed by handing the record to the shared buffered writer
(cyberarmor_core.audit_writer), which spools to a durable volume and retries in
the background.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

_GATE = Path(__file__).resolve().parents[1]
_REPO = _GATE.parent.parent
sys.path.insert(0, str(_GATE))
sys.path.insert(0, str(_REPO / "libs" / "cyberarmor-core"))

_SRC = (_GATE / "main.py").read_text(encoding="utf-8")
_TREE = ast.parse(_SRC)


def _fn(name):
    for n in ast.walk(_TREE):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


def _evaluate_fn():
    """The /evaluate handler, located by its route decorator rather than by
    name, so renaming the function cannot make this file vacuous."""
    for n in ast.walk(_TREE):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in n.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            for a in dec.args:
                if isinstance(a, ast.Constant) and a.value == "/evaluate":
                    return n
    return None


class TheGateDoesNotAwaitTheAuditService(unittest.TestCase):

    def setUp(self):
        self.fn = _evaluate_fn()
        self.assertIsNotNone(self.fn, "no handler decorated with '/evaluate' found")

    def test_evaluate_does_not_await_the_evidence_writer(self):
        """The defect, pinned. Any `await ..._evidence.write(...)` inside the
        request handler puts the audit service's retry budget into user
        traffic."""
        offenders = []
        for node in ast.walk(self.fn):
            if not isinstance(node, ast.Await):
                continue
            call = node.value
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute):
                if call.func.attr == "write":
                    offenders.append(ast.dump(call.func)[:80])
        self.assertEqual(
            offenders, [],
            f"/evaluate awaits a .write() call: {offenders}. With 3 retries and "
            f"a 2s timeout each, a down audit service adds seconds to every "
            f"inspected request and fails this container's healthcheck.",
        )

    def test_it_enqueues_instead(self):
        calls = [
            n for n in ast.walk(self.fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == "_audit_enqueue_evidence"
        ]
        self.assertTrue(
            calls,
            "/evaluate no longer records evidence at all — removing the await "
            "without replacing it would make the gate silent rather than slow",
        )

    def test_the_enqueue_helper_is_synchronous(self):
        """If it were async it would have to be awaited, reintroducing the
        coupling in a different shape."""
        helper = _fn("_audit_enqueue_evidence")
        self.assertIsNotNone(helper, "_audit_enqueue_evidence is gone")
        self.assertNotIsInstance(
            helper, ast.AsyncFunctionDef,
            "_audit_enqueue_evidence is async, so callers must await it and the "
            "audit service is back in the request path",
        )

    def test_the_helper_cannot_raise_into_the_gate(self):
        helper = _fn("_audit_enqueue_evidence")
        handlers = [h for n in ast.walk(helper) if isinstance(n, ast.Try) for h in n.handlers]
        self.assertTrue(
            handlers,
            "_audit_enqueue_evidence can raise, and it is called mid-decision — "
            "a mapping error would turn a URL verdict into a 500",
        )


class TheFlushLoopRuns(unittest.TestCase):
    """A buffered writer nobody drains loses everything on exit."""

    def test_the_writer_loop_is_started_at_startup(self):
        starts = [
            n for n in ast.walk(_TREE)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == "run_forever"
        ]
        self.assertTrue(
            starts,
            "nothing calls run_forever(), so evidence accumulates in memory and "
            "dies with the process",
        )

    def test_the_task_is_held_in_a_module_global(self):
        """asyncio keeps only a weak reference to a bare create_task(); this
        module already documents that trap for the feed-sync task."""
        self.assertIn(
            "_audit_flush_task", _SRC,
            "the flush task is not held anywhere, so it can be garbage "
            "collected mid-flight and the buffer is silently abandoned",
        )


class TheGateUsesTheSharedWriter(unittest.TestCase):
    """One implementation, not two. The genesis-signature defect existed in
    ingest_event and ingest_batch simultaneously because the logic was copied."""

    def test_it_imports_from_cyberarmor_core(self):
        self.assertIn(
            "from cyberarmor_core.audit_writer import AuditWriter", _SRC,
            "the gate does not use the shared writer, so its store-and-forward "
            "behaviour will drift from the proxy's",
        )

    def test_the_shared_writer_is_importable_from_here(self):
        """Both images COPY libs/cyberarmor-core, so this must resolve in the
        gate's container as well as in the proxy's."""
        from cyberarmor_core.audit_writer import AuditWriter
        self.assertTrue(callable(AuditWriter))

    def test_the_gate_has_its_own_spool_directory(self):
        """Two writers sharing a spool would drain each other's files: each
        unlinks a file once IT has delivered the contents."""
        compose = (_REPO / "infra" / "docker-compose.yml").read_text(
            encoding="utf-8")
        self.assertIn(
            "url_trust_gate_audit_spool", compose,
            "the gate has no spool volume of its own; sharing the proxy's would "
            "make each writer delete the other's pending events",
        )


if __name__ == "__main__":
    unittest.main()
