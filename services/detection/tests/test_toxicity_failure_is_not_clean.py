"""A toxicity check that never ran must not look like a toxicity check that passed.

_scan_toxicity used to be `return [result] if result else []`, and
ToxicityDetector.detect returned ``None`` for three different situations:

  * the text is clean            (the check ran, found nothing)
  * the model never loaded       (the check did not run)
  * inference raised             (the check crashed mid-flight)

All three produced ``detections: []`` and ``risk_score: 0.0``. The /scan and
/scan/all callers — the endpoint proxy, the runtime decision path, the audit
trail — recorded "assessed, nothing found" for content nothing had ever
looked at. This is the same shape as the prompt-injection defect fixed in
65a340b: the exception handler produced the reassuring answer.

These tests pin the CONTRACT, not the wiring: whatever the finding schema
becomes, a scan whose toxicity detector was down must be distinguishable from
a scan whose toxicity detector came back clean, and that difference must be
visible to the caller in the response payload.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

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


class _Exploding:
    """A pipeline that loaded fine and then raises during inference."""

    def __call__(self, *_args, **_kwargs):
        raise RuntimeError("simulated toxicity inference failure")


class _Clean:
    """A healthy pipeline whose verdict is 'not toxic'."""

    def __call__(self, *_args, **_kwargs):
        return [{"label": "NON_TOXIC", "score": 0.99}]


class _Toxic:
    def __call__(self, *_args, **_kwargs):
        return [{"label": "TOXIC", "score": 0.97}]


class _ToxicityPipelineFixture(unittest.TestCase):
    """Swap the registry accessor: detect() resolves its pipeline per call."""

    pipeline = None  # set by subclasses / helpers

    def _with_pipeline(self, pipe):
        original = ml_models._registry.toxicity_pipeline
        ml_models._registry.toxicity_pipeline = lambda: pipe
        self.addCleanup(setattr, ml_models._registry, "toxicity_pipeline", original)

    def _with_healthy_peers(self):
        """Stub the OTHER ML detectors that /scan also runs.

        Added when the sweep reached NERPIIDetector and ZeroShotThreatDetector:
        those now report their own unavailability, so on a host without
        transformers a /scan response is legitimately incomplete even when the
        toxicity model is fine. Any test asserting `scan_complete is True` has
        to make every detector in the pipeline healthy, not just this one.
        """
        for accessor, healthy in (
            ("ner_pipeline", lambda *_a, **_k: []),
            ("zero_shot_pipeline",
             lambda *_a, **_k: {"labels": ["safe benign request"], "scores": [0.99]}),
        ):
            original = getattr(ml_models._registry, accessor)
            setattr(ml_models._registry, accessor, lambda h=healthy: h)
            self.addCleanup(setattr, ml_models._registry, accessor, original)


class TestDetectorDistinguishesFailureFromClean(_ToxicityPipelineFixture):
    def test_inference_crash_reports_unavailable(self):
        self._with_pipeline(_Exploding())
        with self.assertLogs("detection.ml_models", level="ERROR"):
            result = ml_models.ToxicityDetector().detect("anything")
        self.assertIsNotNone(
            result, "A crashing classifier must not return the clean answer (None)"
        )
        self.assertIs(result.get("available"), False)
        self.assertIn("error", result)

    def test_missing_model_reports_unavailable(self):
        self._with_pipeline(None)
        result = ml_models.ToxicityDetector().detect("anything")
        self.assertIsNotNone(
            result, "A model that never loaded must not return the clean answer (None)"
        )
        self.assertIs(result.get("available"), False)

    def test_clean_text_is_still_clean(self):
        self._with_pipeline(_Clean())
        self.assertIsNone(
            ml_models.ToxicityDetector().detect("what a nice afternoon"),
            "A ran-and-found-nothing verdict must stay cheap and quiet",
        )

    def test_toxic_text_is_still_detected(self):
        self._with_pipeline(_Toxic())
        result = ml_models.ToxicityDetector().detect("something vile")
        self.assertIsNotNone(result)
        self.assertEqual(result.get("type"), "harmful_content")
        self.assertGreaterEqual(
            result.get("confidence", 0.0), ml_models.TOXICITY_ML_THRESHOLD
        )


class TestScanToxicityContract(_ToxicityPipelineFixture):
    def test_failure_and_clean_are_not_the_same_result(self):
        """The core regression: these two must not be equal."""
        self._with_pipeline(_Clean())
        clean = main._scan_toxicity("a perfectly ordinary sentence")

        self._with_pipeline(_Exploding())
        broken = main._scan_toxicity("a perfectly ordinary sentence")

        self.assertEqual(clean, [], "A clean scan reports no findings")
        self.assertNotEqual(
            broken,
            clean,
            "A toxicity model that crashed produced the same empty result as a "
            "clean verdict — a failed check indistinguishable from a passed one",
        )
        self.assertTrue(
            any(f.get("assessed") is False for f in broken),
            "The failure must be carried as a finding that says it was not assessed",
        )

    def test_unavailable_finding_does_not_fabricate_risk(self):
        """A gap in coverage is not evidence of a threat.

        Also guards the blast radius: services/runtime escalates any finding
        with severity high/critical straight to block, so a broken toxicity
        model must never emit one.
        """
        self._with_pipeline(None)
        findings = main._scan_toxicity("hello")
        self.assertEqual(main._risk_score(findings), 0.0)
        for f in findings:
            self.assertNotIn(
                (f.get("severity") or "").lower(),
                {"high", "critical"},
                "An unavailable detector must not auto-block traffic",
            )


class TestScanResponseTellsTheCaller(_ToxicityPipelineFixture):
    """The caller makes a security/evidence decision on this payload."""

    def setUp(self):
        original = main._verify_api_key
        main._verify_api_key = lambda _key: None  # auth is not under test
        self.addCleanup(setattr, main, "_verify_api_key", original)

    def test_scan_marks_the_scan_incomplete(self):
        self._with_pipeline(None)
        body = main.scan(main.GenericScanRequest(content="hello there"), x_api_key=None)
        self.assertFalse(
            body["scan_complete"],
            "A response whose toxicity check never ran must not claim a complete scan",
        )
        self.assertTrue(body["detectors_unavailable"])
        # Existing fields must survive untouched (live production consumers).
        for key in ("action", "reason", "risk_score", "detections", "tenant_id",
                    "direction"):
            self.assertIn(key, body)

    def test_scan_reports_complete_when_detector_healthy(self):
        self._with_pipeline(_Clean())
        self._with_healthy_peers()
        body = main.scan(main.GenericScanRequest(content="hello there"), x_api_key=None)
        self.assertTrue(body["scan_complete"])
        self.assertEqual(body["detectors_unavailable"], [])

    def test_scan_all_marks_the_scan_incomplete(self):
        self._with_pipeline(_Exploding())
        body = main.scan_all(main.TextRequest(text="hello there"), x_api_key=None)
        self.assertFalse(body["scan_complete"])
        self.assertTrue(body["detectors_unavailable"])

    def test_unavailable_finding_is_ignored_by_downstream_kind_matching(self):
        """Consumers bucket findings by substring of `type`.

        url-trust-gate matches "prompt_injection" / "promptware" / "exfil" /
        "dlp" / "sensitive" / "phishing" / "credential". The new finding must
        not accidentally register as one of those threat classes.
        """
        self._with_pipeline(None)
        findings = main._scan_toxicity("hello")
        for f in findings:
            kind = f.get("type", "")
            for threat in ("prompt_injection", "promptware", "exfil", "dlp",
                           "sensitive", "phishing", "credential"):
                self.assertNotIn(threat, kind)


if __name__ == "__main__":
    unittest.main()
