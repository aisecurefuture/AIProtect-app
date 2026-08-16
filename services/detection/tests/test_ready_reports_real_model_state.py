"""/ready must report the models that are loaded, not the ones it means to have.

The endpoint returned a hardcoded dict of four model names and ``"status":
"ready"`` unconditionally. A container whose ML models had every one of them
fail to load answered with a payload byte-identical to a fully healthy one —
the readiness probe described intent, not state.

Two properties are non-negotiable and both are pinned here:

  1. The probe must never trigger a model download or a cold load. It runs
     every few seconds against every replica; a probe that pulls weights
     turns a slow model into a restart loop.
  2. A missing ML model must NOT fail the probe. Every ML detector has a
     heuristic/regex fallback and the service keeps serving real answers
     without it, so returning "not ready" would remove working capacity. It
     reports "degraded" with detail instead: honest about the reduced
     coverage, still accepting traffic.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent          # services/detection
REPO = ROOT.parent.parent                              # repo root
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(REPO / "libs" / "cyberarmor-core"))

import ml_models  # noqa: E402


def _load_detection_main():
    """Import services/detection/main.py under a unique module name.

    Nearly every service in this repo has a top-level `main.py`; importing
    this one as plain `main` would poison sys.modules for any other service's
    tests sharing the pytest session.
    """
    if "detection_main" in sys.modules:
        return sys.modules["detection_main"]
    spec = importlib.util.spec_from_file_location("detection_main", ROOT / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["detection_main"] = module
    spec.loader.exec_module(module)
    return module


main = _load_detection_main()


class _Loader:
    def __init__(self, fail: bool = False):
        self.fail = fail
        self.calls = 0

    def __call__(self, *_args, **_kwargs):
        self.calls += 1
        if self.fail:
            raise RuntimeError("simulated model load failure")
        return object()


class _ReadyFixture(unittest.TestCase):
    def setUp(self):
        # Fresh registry so one test's load state cannot leak into another.
        saved_instance = ml_models.MLModelRegistry._instance
        saved_registry = ml_models._registry
        ml_models.MLModelRegistry._instance = None
        ml_models._registry = ml_models.MLModelRegistry()
        self.addCleanup(setattr, ml_models, "_registry", saved_registry)
        self.addCleanup(
            setattr, ml_models.MLModelRegistry, "_instance", saved_instance
        )
        # No network in tests: the Ollama probe is an HTTP call.
        patcher = mock.patch.object(
            main.ollama_judge, "is_available", return_value=False
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _load_all(self, loader):
        reg = ml_models._registry
        reg.prompt_injection_pipeline()
        reg.ner_pipeline()
        reg.ner_phi_pipeline()
        reg.toxicity_pipeline()
        reg.zero_shot_pipeline()


class TestReadyDoesNotForceModelLoads(_ReadyFixture):
    def test_probe_never_triggers_a_load(self):
        loader = _Loader()
        with mock.patch.object(ml_models, "hf_pipeline", loader), \
             mock.patch.object(ml_models, "_TRANSFORMERS_AVAILABLE", True):
            for _ in range(5):
                main.ready()
        self.assertEqual(
            loader.calls,
            0,
            "A health probe that cold-loads models would download weights on "
            "every probe interval and wedge the container",
        )


class TestReadyReportsWhatIsActuallyLoaded(_ReadyFixture):
    def test_loaded_models_are_reported_ready(self):
        loader = _Loader()
        with mock.patch.object(ml_models, "hf_pipeline", loader), \
             mock.patch.object(ml_models, "_TRANSFORMERS_AVAILABLE", True):
            self._load_all(loader)
            body = main.ready()

        self.assertEqual(body["status"], "ready")
        self.assertEqual(body["degraded_models"], [])
        for name, state in body["ml_model_status"].items():
            self.assertEqual(state["status"], "loaded", name)

    def test_failed_model_is_reported_not_hidden(self):
        """The regression: this used to return status "ready" regardless."""
        good = _Loader()
        bad = _Loader(fail=True)
        with mock.patch.object(ml_models, "_TRANSFORMERS_AVAILABLE", True):
            with mock.patch.object(ml_models, "hf_pipeline", good):
                ml_models._registry.prompt_injection_pipeline()
            with mock.patch.object(ml_models, "hf_pipeline", bad):
                ml_models._registry.toxicity_pipeline()
            body = main.ready()

        self.assertNotEqual(
            body["status"],
            "ready",
            "A service whose toxicity model failed to load reported itself "
            "exactly as healthy as one where it loaded fine",
        )
        self.assertEqual(body["status"], "degraded")
        self.assertIn("toxicity", body["degraded_models"])
        self.assertEqual(body["ml_model_status"]["toxicity"]["status"], "failed")
        self.assertEqual(
            body["ml_model_status"]["prompt_injection"]["status"], "loaded"
        )
        self.assertIn("toxicity", body["detail"])

    def test_never_attempted_is_not_reported_as_broken(self):
        with mock.patch.object(ml_models, "_TRANSFORMERS_AVAILABLE", True):
            body = main.ready()
        self.assertEqual(
            body["status"],
            "ready",
            "Lazy loading is the design: untouched models are not a fault",
        )
        for state in body["ml_model_status"].values():
            self.assertEqual(state["status"], "not_attempted")

    def test_missing_transformers_is_degraded_not_ready(self):
        with mock.patch.object(ml_models, "_TRANSFORMERS_AVAILABLE", False):
            body = main.ready()
        self.assertEqual(body["status"], "degraded")
        self.assertEqual(sorted(body["degraded_models"]), sorted(ml_models.MODEL_IDS))


class TestDegradedStillServes(_ReadyFixture):
    def test_degraded_service_still_reports_ready_true(self):
        """Deliberate call: heuristic fallbacks work, so do not fail the probe."""
        with mock.patch.object(ml_models, "_TRANSFORMERS_AVAILABLE", False):
            body = main.ready()  # must not raise HTTPException / 503
        self.assertIs(body["ready"], True)
        self.assertEqual(body["status"], "degraded")

    def test_existing_fields_are_preserved(self):
        """Live consumers read this payload; nothing may be renamed or dropped."""
        body = main.ready()
        for key in ("status", "service", "version", "ml_models", "ollama_enabled",
                    "ollama_judge"):
            self.assertIn(key, body)
        self.assertEqual(body["service"], "detection")
        self.assertEqual(
            set(body["ml_models"]),
            {"prompt_injection", "ner_pii", "ner_phi", "toxicity", "zero_shot"},
            # ner_phi is the clinical de-identification model. It is pinned
            # here on purpose: a HIPAA tenant's PHI redaction depends on it,
            # and /ready silently dropping it would hide exactly the state
            # (configured but never loaded) that makes a PHI scan come back
            # clean without having looked.
            "The configured-model map kept its expected keys",
        )
        for model_id in body["ml_models"].values():
            self.assertIsInstance(model_id, str)


if __name__ == "__main__":
    unittest.main()
