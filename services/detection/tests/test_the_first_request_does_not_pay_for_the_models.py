"""Models load at startup, off the request path -- and /ready stays honest.

MEASURED on the box 2026-08-07:

  * the first /scan after a container restart paid +1.73s to load weights,
    against a proxy budget of 5.0s that FAILS CLOSED;
  * the first scan of the demo corpus through the public path took 5307ms --
    over budget, so that request would have been blocked;
  * steady state was 1.8-2.1s.

So the request most likely to be blocked was the first one anybody made,
which on a demo machine is the demo.

Nothing warmed the registry. It was lazy by design, and /ready was
deliberately a pure read -- "a probe must never be the thing that pulls model
weights" -- so the only thing that ever loaded a model was a customer request.

TWO THINGS THIS FILE PINS, and the second is the one that is easy to lose:

  1. A warmup exists, runs off the request path, and cannot take the service
     down when a model is broken.

  2. /ready still distinguishes states that now look identical. `not_attempted`
     used to mean exactly one thing -- lazy loading working as designed. With a
     warmup it means three, and only one of them is healthy:

         warmup running  -> not reached yet; transient
         warmup finished -> the warmup walked every declared model, so one
                            still untouched is one it did not know about; a
                            real fault
         warmup disabled -> genuine lazy loading, the original meaning

     Collapsing those would hand this probe back the defect it was written to
     fix: a payload that reads identically whether the thing it describes is
     healthy or broken.
"""

from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve()
_SERVICE = _HERE.parents[1]
_REPO = _HERE.parents[3]
sys.path.insert(0, str(_SERVICE))
sys.path.insert(0, str(_REPO / "libs" / "cyberarmor-core"))

import main  # noqa: E402
import ml_models  # noqa: E402


class _WarmupState:
    """Restore the module's warmup state, so tests cannot leak into each
    other through a process-global dict."""

    def __enter__(self):
        with ml_models._WARMUP_LOCK:
            self._saved = dict(ml_models._WARMUP)
        return self

    def __exit__(self, *exc):
        with ml_models._WARMUP_LOCK:
            ml_models._WARMUP.clear()
            ml_models._WARMUP.update(self._saved)
        return False


def _set_warmup(**fields):
    with ml_models._WARMUP_LOCK:
        ml_models._WARMUP.update(fields)


class _Statuses:
    """Drive /ready with a chosen model_status.

    Necessary rather than fussy: in a checkout without `transformers` every
    model reports `unavailable` (permanent), so a test that waits for
    `not_attempted` to appear on its own skips forever and proves nothing --
    including on CI, where it would look like a pass.
    """

    def __init__(self, status):
        self.status = status

    def __enter__(self):
        self._orig = main.model_status
        main.model_status = lambda: {
            name: {"status": self.status, "model_id": mid}
            for name, mid in ml_models.MODEL_IDS.items()
        }
        return self

    def __exit__(self, *exc):
        main.model_status = self._orig
        return False


class TheWarmupRunsOffTheRequestPath(unittest.TestCase):

    def test_it_does_not_block_the_caller(self):
        """The healthcheck polls /health every 10s with 3 retries and NO
        start_period, and three services gate on `condition: service_healthy`.
        A warmup that blocks startup eats that budget for no benefit."""
        with _WarmupState():
            _set_warmup(state="not_started")
            slow = threading.Event()
            loaded = []

            def _slow_load(name):
                slow.wait(5.0)
                loaded.append(name)
                return None

            orig = ml_models.load_pipeline
            ml_models.load_pipeline = _slow_load
            try:
                t0 = time.monotonic()
                ml_models.start_model_warmup()
                elapsed = time.monotonic() - t0
                self.assertLess(
                    elapsed, 0.5,
                    f"start_model_warmup blocked its caller for {elapsed:.2f}s "
                    f"-- it must hand off to a thread and return")
                self.assertEqual(ml_models.warmup_status()["state"], "running")
            finally:
                slow.set()
                ml_models.load_pipeline = orig

    def test_a_model_that_raises_does_not_kill_the_service(self):
        """A warmup that can crash the process is worse than no warmup: the
        container would crash-loop instead of serving on heuristic fallbacks,
        which is the whole point of the degraded-but-answering design."""
        with _WarmupState():
            _set_warmup(state="not_started")
            orig = ml_models.load_pipeline
            ml_models.load_pipeline = lambda name: (_ for _ in ()).throw(
                RuntimeError("model path is nonsense"))
            try:
                ml_models._warm_models()          # runs inline, must not raise
            finally:
                ml_models.load_pipeline = orig
            self.assertEqual(ml_models.warmup_status()["state"], "finished")

    def test_it_warms_every_declared_model(self):
        """Derived from MODEL_IDS, never a second list -- a warmup that knows
        about four of five models leaves the fifth on the request path, which
        is the bug this file exists to close, just quieter."""
        with _WarmupState():
            _set_warmup(state="not_started")
            seen = []
            orig = ml_models.load_pipeline
            ml_models.load_pipeline = lambda name: seen.append(name)
            try:
                ml_models._warm_models()
            finally:
                ml_models.load_pipeline = orig
            self.assertEqual(sorted(seen), sorted(ml_models.MODEL_IDS))

    def test_two_calls_do_not_start_two_warmups(self):
        with _WarmupState():
            _set_warmup(state="not_started")
            orig = ml_models.load_pipeline
            ml_models.load_pipeline = lambda name: None
            try:
                ml_models.start_model_warmup()
                started = ml_models.warmup_status()["started_at"]
                ml_models.start_model_warmup()
                self.assertEqual(ml_models.warmup_status()["started_at"], started)
            finally:
                ml_models.load_pipeline = orig


class ReadyStillTellsTheStatesApart(unittest.TestCase):

    def test_a_model_untouched_after_warmup_finished_is_degraded(self):
        """The case that would otherwise read as healthy. The warmup walked
        every declared model, so one still `not_attempted` is one the warmup
        never knew about."""
        with _WarmupState(), _Statuses(ml_models.MODEL_STATUS_NOT_ATTEMPTED):
            _set_warmup(state="finished", pending=[])
            body = main.ready()
            self.assertEqual(
                body["status"], "degraded",
                "a model the finished warmup never touched was reported ready")
            self.assertTrue(body["degraded_models"])

    def test_the_same_model_mid_warmup_is_not_degraded(self):
        """The other direction: 'not reached yet' must not page anybody."""
        with _WarmupState(), _Statuses(ml_models.MODEL_STATUS_NOT_ATTEMPTED):
            _set_warmup(state="running", pending=list(ml_models.MODEL_IDS))
            body = main.ready()
            self.assertEqual(
                body["degraded_models"], [],
                "a model the warmup has not reached yet was called degraded")
            self.assertEqual(body["status"], "ready")

    def test_disabled_warmup_keeps_the_original_lazy_meaning(self):
        """With no warmup running, `not_attempted` means what it always meant:
        lazy loading working as designed, not a fault."""
        with _WarmupState(), _Statuses(ml_models.MODEL_STATUS_NOT_ATTEMPTED):
            _set_warmup(state="disabled", pending=[])
            self.assertEqual(main.ready()["degraded_models"], [])

    def test_ready_reports_the_warmup_state_at_all(self):
        """Without this the three cases are indistinguishable to any caller,
        which is the same defect in a different place."""
        with _WarmupState(), _Statuses(ml_models.MODEL_STATUS_NOT_ATTEMPTED):
            _set_warmup(state="running", pending=["zero_shot"])
            body = main.ready()
            self.assertIn("warmup", body)
            self.assertEqual(body["warmup"]["state"], "running")
            self.assertIn("warming", body["detail"])

    def test_ready_never_triggers_a_load(self):
        """Unchanged constraint, restated because the warmup is a new way to
        break it: a probe must never be the thing that pulls model weights."""
        with _WarmupState():
            _set_warmup(state="finished", pending=[])
            calls = []
            orig = ml_models._registry._load
            ml_models._registry._load = lambda *a, **k: calls.append(a)
            try:
                main.ready()
            finally:
                ml_models._registry._load = orig
            self.assertEqual(calls, [], "/ready called _load")


class TheRegistryIsActuallyThreadSafe(unittest.TestCase):
    """It called itself thread-safe while importing no lock. The warmup thread
    is what turns that from a latent race into a likely one."""

    def test_concurrent_first_loads_build_exactly_one_pipeline(self):
        registry = ml_models.MLModelRegistry()
        builds = []
        barrier = threading.Barrier(8)

        def _build(*_a, **_k):
            builds.append(1)
            time.sleep(0.02)            # widen the window a real load has
            return object()

        saved_models = dict(registry._models)
        saved_state = dict(registry._state)
        registry._models.pop("racer", None)
        registry._state.pop("racer", None)
        orig_hf = ml_models.hf_pipeline
        orig_avail = ml_models._TRANSFORMERS_AVAILABLE
        ml_models.hf_pipeline = _build
        ml_models._TRANSFORMERS_AVAILABLE = True
        try:
            def _worker():
                barrier.wait()
                registry._load("racer", "some/model", "text-classification")
            threads = [threading.Thread(target=_worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(10)
        finally:
            ml_models.hf_pipeline = orig_hf
            ml_models._TRANSFORMERS_AVAILABLE = orig_avail
            registry._models.clear()
            registry._models.update(saved_models)
            registry._state.clear()
            registry._state.update(saved_state)

        self.assertEqual(
            len(builds), 1,
            f"{len(builds)} threads each built their own copy of the model. "
            f"For bart-large-mnli that is ~1.6 GiB apiece inside mem_limit 8g.")


if __name__ == "__main__":
    unittest.main()
