"""The enforcement point must not lose audit events when audit is down.

CONTEXT. Production ``audit_events`` held ZERO rows on 2026-08-12. The MITM
proxy -- the component that sees the traffic and makes the decisions -- had no
audit code at all. A live demo produced no records.

The naive fix is a POST per request, and it is wrong three ways: it puts the
audit service's latency and outages into the customer's request path; it writes
one event per request against a chain that serialises per tenant, making the
audit service's per-tenant ceiling the proxy's ceiling; and when audit is
unavailable it drops events -- precisely when something interesting is likely
happening, because outages correlate with incidents.

So: buffered, batched, and spooled to a durable volume on failure.

WHAT THESE TESTS ARE FOR. Every one of them is about the promise "we won't lose
it". A writer that silently drops under pressure would pass a naive
does-it-send test and fail the only property that matters.
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyberarmor_core import audit_writer as aw  # noqa: E402


class _Resp:
    def __init__(self, status=202, body=None):
        self.status_code = status
        self._body = body if body is not None else {"stored": 0, "total": 0, "failed": []}
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


class _Client:
    """Stands in for httpx.AsyncClient. `up` flips the outage on and off."""

    def __init__(self, up=True, status=202):
        self.up = up
        self.status = status
        self.batches = []

    async def post(self, url, json=None, headers=None):
        if not self.up:
            raise ConnectionError("audit service unreachable")
        events = (json or {}).get("events", [])
        self.batches.append(events)
        return _Resp(self.status, {"stored": len(events), "total": len(events), "failed": []})

    def all_event_ids(self):
        return {e["event_id"] for b in self.batches for e in b}


def _writer(tmp, **kw):
    return aw.AuditWriter(service_url="http://audit:8011", api_secret="s",
                          spool_dir=tmp, **kw)


def _ev(i):
    return {"trace_id": f"t{i}", "tenant_id": "t1", "agent_id": "proxy",
            "event_type": "ai_request"}


class NothingIsLostWhenAuditIsDown(unittest.TestCase):
    """The promise, end to end."""

    def test_events_are_spooled_then_drained_with_none_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = _writer(tmp)
            for i in range(10):
                w.enqueue(_ev(i))
            enqueued = {e["event_id"] for e in list(w._buffer)}

            down = _Client(up=False)
            asyncio.run(w.flush_once(down))
            self.assertEqual(down.batches, [], "it claimed to send during an outage")
            self.assertTrue(
                list(Path(tmp).glob("*.jsonl")),
                "the audit service was down and nothing was spooled — those "
                "events are gone",
            )

            up = _Client(up=True)
            asyncio.run(w.drain_spool(up))
            self.assertEqual(
                up.all_event_ids(), enqueued,
                "the set of events that reached audit differs from the set the "
                "proxy recorded — the outage lost or duplicated records",
            )

    def test_a_failed_drain_does_not_delete_the_spool(self):
        """A file unlinked on a failed send is an event lost forever."""
        with tempfile.TemporaryDirectory() as tmp:
            w = _writer(tmp)
            w.enqueue(_ev(1))
            asyncio.run(w.flush_once(_Client(up=False)))
            before = list(Path(tmp).glob("*.jsonl"))
            self.assertTrue(before)

            asyncio.run(w.drain_spool(_Client(up=False)))
            self.assertEqual(
                list(Path(tmp).glob("*.jsonl")), before,
                "the spool file was removed while audit was still down",
            )

    def test_a_rejected_batch_is_spooled_not_dropped(self):
        """A 4xx is not a transport error. url-trust-gate discarded exactly
        this response for the life of the codebase and 422'd unnoticed."""
        with tempfile.TemporaryDirectory() as tmp:
            w = _writer(tmp)
            w.enqueue(_ev(1))
            asyncio.run(w.flush_once(_Client(up=True, status=422)))
            self.assertTrue(
                list(Path(tmp).glob("*.jsonl")),
                "a 422 was treated as success and the event was dropped",
            )

    def test_ids_are_assigned_before_sending_so_retries_are_idempotent(self):
        """If the audit service minted ids, a retried batch would double-write."""
        with tempfile.TemporaryDirectory() as tmp:
            w = _writer(tmp)
            w.enqueue(_ev(1))
            first = list(w._buffer)[0]["event_id"]
            asyncio.run(w.flush_once(_Client(up=False)))
            spooled = json.loads(next(Path(tmp).glob("*.jsonl")).read_text().strip())
            self.assertEqual(spooled["event_id"], first)


class ItNeverSilentlyDrops(unittest.TestCase):
    """Loss is permitted only when unavoidable, and never quietly."""

    def test_a_full_spool_refuses_and_counts_rather_than_evicting(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = _writer(tmp, spool_max_bytes=1)   # full immediately
            w.enqueue(_ev(1))
            asyncio.run(w.flush_once(_Client(up=False)))
            s = w.stats()
            self.assertGreater(
                s["lost"], 0,
                "events were discarded without being counted as lost",
            )
            self.assertFalse(s["healthy"])

    def test_an_unusable_spool_is_detected_at_construction(self):
        """A named volume mounted at a path the image never created comes up
        root-owned, and this process runs as appuser. exists() would say yes."""
        w = _writer("/proc/cyberarmor-cannot-write-here")
        self.assertFalse(w.stats()["spool_ready"])
        w.enqueue(_ev(1))
        asyncio.run(w.flush_once(_Client(up=False)))
        self.assertGreater(w.stats()["lost"], 0)

    def test_memory_pressure_spills_to_disk_instead_of_growing(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = _writer(tmp, memory_max=10)
            for i in range(30):
                w.enqueue(_ev(i))
            self.assertLess(len(w._buffer), 30, "the buffer grew unbounded")
            self.assertTrue(
                list(Path(tmp).glob("*.jsonl")),
                "events left memory and did not reach disk — they were dropped",
            )
            self.assertEqual(w.stats()["lost"], 0, "spilling to disk lost events")

    def test_a_corrupt_spool_line_is_counted_not_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = _writer(tmp)
            p = Path(tmp) / "spool-1.jsonl"
            p.write_text('{"event_id":"evt_ok","tenant_id":"t1"}\n{not json\n',
                         encoding="utf-8")
            up = _Client(up=True)
            asyncio.run(w.drain_spool(up))
            self.assertEqual(
                w.stats()["corrupt_lines_skipped"], 1,
                "a corrupt line was skipped without being counted, so a lost "
                "event is invisible",
            )
            self.assertEqual(len(up.all_event_ids()), 1)


class ItDoesNotBlockOrOverwhelm(unittest.TestCase):

    def test_enqueue_never_raises(self):
        """It runs in mitmproxy's request path. An exception here is an outage
        for all traffic, not just for auditing."""
        with tempfile.TemporaryDirectory() as tmp:
            w = _writer(tmp)
            for bad in (None, 1, "x"):
                with self.subTest(value=bad):
                    try:
                        w.enqueue(bad)          # type: ignore[arg-type]
                    except Exception as exc:
                        self.fail(f"enqueue raised into the request path: {exc}")

    def test_it_batches_rather_than_sending_one_event_per_request(self):
        """Per-request writes would make the audit chain's per-tenant ceiling
        the enforcement point's ceiling."""
        with tempfile.TemporaryDirectory() as tmp:
            w = _writer(tmp, batch_max=50)
            for i in range(50):
                w.enqueue(_ev(i))
            up = _Client(up=True)
            asyncio.run(w.flush_once(up))
            self.assertEqual(len(up.batches), 1, "it sent more than one request")
            self.assertEqual(len(up.batches[0]), 50)

    def test_shutdown_spools_whatever_is_left(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = _writer(tmp)
            for i in range(5):
                w.enqueue(_ev(i))
            asyncio.run(w.shutdown(_Client(up=False)))
            self.assertTrue(
                list(Path(tmp).glob("*.jsonl")),
                "events in memory at shutdown were discarded",
            )


if __name__ == "__main__":
    unittest.main()
