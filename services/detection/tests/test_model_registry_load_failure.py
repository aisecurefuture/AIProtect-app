"""A model that failed to load once must not be written off forever — silently.

MLModelRegistry._load cached ``None`` on every failure, with the comment
"already attempted (may be None on failure)". Two very different situations
were recorded identically:

  * transformers is not installed  – permanent; retrying can never help.
  * the load raised this time      – transient (memory pressure at boot, a
                                     network blip pulling weights); the next
                                     attempt would very likely succeed.

The second case permanently degraded the process: one unlucky moment during
startup and that detector was dead until someone restarted the container, with
nothing above WARNING in the logs and no endpoint reporting the gap.

These tests pin the behaviour, not the mechanism — a fix that retries forever
is as wrong as one that never retries, so both bounds are asserted.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent          # services/detection
sys.path.insert(0, str(ROOT))

import ml_models  # noqa: E402


class _Loader:
    """Stand-in for transformers.pipeline. Records calls; fails on demand."""

    def __init__(self, failures: int):
        self.failures = failures
        self.calls = 0

    def __call__(self, *_args, **_kwargs):
        self.calls += 1
        if self.calls <= self.failures:
            raise RuntimeError("simulated model load failure")
        return object()


class _RegistryFixture(unittest.TestCase):
    """Each test gets its own registry instance (the real one is a singleton)."""

    def setUp(self):
        saved = ml_models.MLModelRegistry._instance
        ml_models.MLModelRegistry._instance = None
        self.registry = ml_models.MLModelRegistry()
        self.addCleanup(
            setattr, ml_models.MLModelRegistry, "_instance", saved
        )

    def _load(self, **overrides):
        return self.registry._load("toxicity", "unitary/toxic-bert", "text-classification", **overrides)


class TestTransientFailureIsRetryable(_RegistryFixture):
    def test_failed_load_is_retried_after_the_cooldown(self):
        """The regression: the second call used to return the cached None."""
        loader = _Loader(failures=1)
        with mock.patch.object(ml_models, "hf_pipeline", loader), \
             mock.patch.object(ml_models, "_TRANSFORMERS_AVAILABLE", True), \
             mock.patch.object(ml_models, "MODEL_LOAD_RETRY_COOLDOWN_SECONDS", 0.0):
            first = self._load()
            second = self._load()

        self.assertIsNone(first, "The first attempt failed, so it yields no pipeline")
        self.assertIsNotNone(
            second,
            "A transient load failure was cached forever: the model never got a "
            "second chance and the service stayed degraded until restart",
        )
        self.assertEqual(loader.calls, 2)

    def test_success_is_cached_and_not_reloaded(self):
        loader = _Loader(failures=0)
        with mock.patch.object(ml_models, "hf_pipeline", loader), \
             mock.patch.object(ml_models, "_TRANSFORMERS_AVAILABLE", True):
            first = self._load()
            second = self._load()
        self.assertIs(first, second)
        self.assertEqual(loader.calls, 1, "A loaded model must not be re-loaded")


class TestRetryIsBounded(_RegistryFixture):
    def test_a_broken_model_is_not_reloaded_on_every_call(self):
        """Retrying per request would hammer a broken model path under load."""
        loader = _Loader(failures=99)
        with mock.patch.object(ml_models, "hf_pipeline", loader), \
             mock.patch.object(ml_models, "_TRANSFORMERS_AVAILABLE", True), \
             mock.patch.object(ml_models, "MODEL_LOAD_RETRY_COOLDOWN_SECONDS", 3600.0):
            for _ in range(25):
                self.assertIsNone(self._load())
        self.assertEqual(
            loader.calls, 1, "Within the cooldown window, no retry may be attempted"
        )

    def test_attempts_are_capped(self):
        loader = _Loader(failures=99)
        with mock.patch.object(ml_models, "hf_pipeline", loader), \
             mock.patch.object(ml_models, "_TRANSFORMERS_AVAILABLE", True), \
             mock.patch.object(ml_models, "MODEL_LOAD_RETRY_COOLDOWN_SECONDS", 0.0):
            for _ in range(25):
                self.assertIsNone(self._load())
        self.assertLessEqual(
            loader.calls,
            ml_models.MODEL_LOAD_MAX_ATTEMPTS,
            "A permanently broken model must eventually stop being retried",
        )
        self.assertGreater(loader.calls, 1, "…but it must be retried at least once")


class TestPermanentUnavailabilityIsNotRetried(_RegistryFixture):
    def test_missing_transformers_is_cached_permanently(self):
        loader = _Loader(failures=0)
        with mock.patch.object(ml_models, "hf_pipeline", loader), \
             mock.patch.object(ml_models, "_TRANSFORMERS_AVAILABLE", False), \
             mock.patch.object(ml_models, "MODEL_LOAD_RETRY_COOLDOWN_SECONDS", 0.0):
            for _ in range(10):
                self.assertIsNone(self._load())
        self.assertEqual(
            loader.calls, 0, "No load may be attempted when transformers is absent"
        )
        status = self.registry.model_status()["toxicity"]
        self.assertEqual(status["status"], "unavailable")
        self.assertFalse(status["retryable"])


class TestFailureIsVisible(_RegistryFixture):
    def test_load_failure_is_logged_at_error(self):
        """It was logged at WARNING — below the level most deployments alert on.

        transformers IS installed here, so this model was expected to exist:
        its absence is an error, not a note.
        """
        loader = _Loader(failures=1)
        with mock.patch.object(ml_models, "hf_pipeline", loader), \
             mock.patch.object(ml_models, "_TRANSFORMERS_AVAILABLE", True):
            with self.assertLogs("detection.ml_models", level="ERROR") as captured:
                self._load()
        self.assertTrue(
            any("simulated model load failure" in line for line in captured.output)
        )

    def test_failure_is_reported_in_model_status(self):
        loader = _Loader(failures=1)
        with mock.patch.object(ml_models, "hf_pipeline", loader), \
             mock.patch.object(ml_models, "_TRANSFORMERS_AVAILABLE", True):
            self._load()

        status = self.registry.model_status()["toxicity"]
        self.assertEqual(status["status"], "failed")
        self.assertTrue(status["retryable"])
        self.assertIn("simulated model load failure", status["last_error"] or "")

    def test_untouched_model_is_not_reported_as_failed(self):
        """Lazy loading is not a fault: 'nobody asked yet' is its own state."""
        with mock.patch.object(ml_models, "_TRANSFORMERS_AVAILABLE", True):
            status = self.registry.model_status()["zero_shot"]
        self.assertEqual(status["status"], "not_attempted")
        self.assertIsNone(status["last_error"])


if __name__ == "__main__":
    unittest.main()
