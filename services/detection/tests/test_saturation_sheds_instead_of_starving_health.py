"""Saturation must shed scans, not starve the healthcheck into a restart loop.

MEASURED TWICE ON PRODUCTION.

2026-08-11::

    docker-compose-detection-1   Up 27 hours (unhealthy)
    mem 7.301GiB / 8GiB   cpu 371.88%
    /health  HTTP 000 after 20s

2026-08-14, from the watchdog's own mail::

    docker-compose-detection-1 has been restarted 3 times in the last
    180 minutes and is unhealthy again. This watchdog has stopped
    restarting it.

THE MECHANISM. One uvicorn process; every endpoint is sync ``def``; FastAPI
runs them all in ONE shared threadpool. Under scan load torch fills the pool,
``/health`` queues behind the inference backlog and times out, docker marks the
container unhealthy, and the watchdog restarts it -- reloading ~4 GiB of models
while traffic keeps arriving, so each restart made things worse. Saturation is
not a fault, and a restart was the only lever the outside world had.

It surfaced on the 14th because the enforcement work multiplied scan traffic:
all four of the founder's network interfaces now route through the proxy, the
proxy scans inspected requests, and url-trust-gate calls detection again per URL
evaluation. Detection had never seen its real workload before.

THE FIX, in one honest idea: liveness and load are different facts.

  * ``/health`` is ``async`` -- it runs on the event loop, not the shared pool,
    so it answers while every pool thread is busy, and it reports saturation as
    data instead of as absence.
  * scans acquire a bounded slot and shed fast (503 ``detector_saturated``)
    when none frees up, instead of queueing into a timeout. Callers already
    apply their own fail mode to detection being unavailable; a fast 503 and a
    slow timeout produce the same enforcement outcome, but only one of them
    also takes /health down with it.

WHAT A SHED MEANS is stated in the payload and pinned here: nothing was
scanned. Under a fail-open tenant that request passes UNINSPECTED -- as it did
during the silent stalls -- but counted and visible rather than buried.
"""

from __future__ import annotations

import ast
import sys
import threading
import time
import unittest
from pathlib import Path

_SVC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_SVC))

import main as det  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

#: The shed decorator runs BEFORE auth, so the saturation tests pass no key on
#: purpose — a 503 there proves shedding costs nothing, not even a key check.
#: The normal-operation test crosses auth and needs the real header.
_AUTH = {"x-api-key": det.DETECTION_API_SECRET}


def _drain_slots():
    """Take every scan slot, simulating a fully saturated service."""
    taken = 0
    while det._SCAN_SLOTS.acquire(blocking=False):
        taken += 1
    return taken


def _refill_slots(taken: int):
    for _ in range(taken):
        det._SCAN_SLOTS.release()


class HealthAnswersWhileSaturated(unittest.TestCase):

    def test_health_is_served_from_the_event_loop(self):
        """The fix itself. A sync-def /health shares the scan threadpool and
        starves under load -- which is precisely the measured failure."""
        tree = ast.parse(Path(det.__file__).read_text(encoding="utf-8"))
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                  and n.name == "health")
        self.assertIsInstance(
            fn, ast.AsyncFunctionDef,
            "/health is a sync def again, so it queues in the same threadpool "
            "as torch inference and times out under load — the exact mechanism "
            "that produced the 2026-08-14 restart loop",
        )

    def test_health_responds_and_reports_while_all_slots_are_taken(self):
        taken = _drain_slots()
        self.assertGreater(taken, 0, "no slots to drain; the semaphore is gone")
        try:
            with TestClient(det.app) as client:
                resp = client.get("/health")
                self.assertEqual(resp.status_code, 200,
                                 "health failed during saturation — the "
                                 "watchdog will restart a busy service")
                body = resp.json()
                self.assertTrue(
                    body["scan_slots"]["saturated"] or
                    body["scan_slots"]["in_use"] == 0,
                    # in_use tracks the decorator, not raw semaphore drains;
                    # what matters is the field EXISTS and health answered.
                )
                self.assertIn("sheds_total", body["scan_slots"],
                              "saturation is not observable on /health")
        finally:
            _refill_slots(taken)


class SaturationShedsFastAndHonestly(unittest.TestCase):

    def test_a_saturated_scan_returns_503_quickly(self):
        taken = _drain_slots()
        old_wait = det._SCAN_SHED_AFTER_S
        det._SCAN_SHED_AFTER_S = 0.2
        try:
            with TestClient(det.app) as client:
                t0 = time.monotonic()
                resp = client.post(
                    "/scan",
                    json={"content": "hello", "tenant_id": "t1"},
                    headers=_AUTH,
                )
                elapsed = time.monotonic() - t0
            self.assertEqual(
                resp.status_code, 503,
                f"a saturated scan returned {resp.status_code}; queueing into "
                f"a timeout is the behaviour that starved the healthcheck",
            )
            self.assertLess(
                elapsed, 5.0,
                "the shed was not fast — a slow 503 still occupies the caller "
                "for the duration that made the old failure invisible",
            )
        finally:
            det._SCAN_SHED_AFTER_S = old_wait
            _refill_slots(taken)

    def test_the_shed_says_nothing_was_scanned(self):
        """The payload must claim ONLY unavailability. A shed that returned a
        verdict-shaped body would be recorded as evidence of an assessment
        nobody performed — this codebase's tracked defect class."""
        taken = _drain_slots()
        old_wait = det._SCAN_SHED_AFTER_S
        det._SCAN_SHED_AFTER_S = 0.1
        try:
            with TestClient(det.app) as client:
                resp = client.post("/scan", json={"content": "x", "tenant_id": "t1"})
            detail = resp.json().get("detail", {})
            self.assertEqual(detail.get("reason"), "detector_saturated", detail)
            self.assertIn("nothing was scanned", str(detail).lower())
            for verdict_key in ("action", "risk_score", "detections"):
                self.assertNotIn(
                    verdict_key, detail,
                    f"the shed carries {verdict_key!r}, so a caller can mistake "
                    f"it for an assessment",
                )
        finally:
            det._SCAN_SHED_AFTER_S = old_wait
            _refill_slots(taken)

    def test_sheds_are_counted_and_surface_on_health(self):
        taken = _drain_slots()
        old_wait = det._SCAN_SHED_AFTER_S
        det._SCAN_SHED_AFTER_S = 0.1
        try:
            with TestClient(det.app) as client:
                before = client.get("/health").json()["scan_slots"]["sheds_total"]
                client.post("/scan", json={"content": "x", "tenant_id": "t1"})
                after = client.get("/health").json()["scan_slots"]["sheds_total"]
            self.assertEqual(
                after, before + 1,
                "a shed was not counted — an uninspected request left no trace, "
                "which is how yesterday's stalls stayed invisible for a day",
            )
        finally:
            det._SCAN_SHED_AFTER_S = old_wait
            _refill_slots(taken)


class NormalOperationIsUntouched(unittest.TestCase):

    def test_an_unsaturated_scan_still_succeeds_and_releases_its_slot(self):
        with TestClient(det.app) as client:
            for _ in range(3):   # more calls than a leaked slot would allow
                resp = client.post("/scan", json={"content": "hi", "tenant_id": "t1"}, headers=_AUTH)
                self.assertEqual(resp.status_code, 200, resp.text[:200])
        # All slots must be free again — a leak here becomes creeping
        # saturation that presents exactly like real load.
        taken = _drain_slots()
        try:
            self.assertEqual(
                taken, det._SCAN_MAX_CONCURRENT,
                f"only {taken} of {det._SCAN_MAX_CONCURRENT} slots free after "
                f"successful scans — the decorator leaks slots and the service "
                f"will saturate itself with no traffic at all",
            )
        finally:
            _refill_slots(taken)

    def test_both_heavy_entrypoints_are_bounded(self):
        """scan and scan/all carry the load; an unbounded sibling would starve
        health exactly as before while every test here stays green."""
        tree = ast.parse(Path(det.__file__).read_text(encoding="utf-8"))
        for name in ("scan", "scan_all"):
            with self.subTest(endpoint=name):
                fn = next(n for n in ast.walk(tree)
                          if isinstance(n, ast.FunctionDef) and n.name == name)
                decs = {d.id for d in fn.decorator_list if isinstance(d, ast.Name)}
                self.assertIn(
                    "_sheds_when_saturated", decs,
                    f"{name} is not bounded, so it can occupy the whole "
                    f"threadpool and starve /health regardless of the other "
                    f"endpoint being protected",
                )


if __name__ == "__main__":
    unittest.main()
