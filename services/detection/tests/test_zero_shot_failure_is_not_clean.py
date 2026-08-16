"""An output-safety check that never ran must not look like one that passed.

ZeroShotThreatDetector.detect returned ``[]`` for three different situations:

  * nothing scored above threshold  (the check ran, found nothing)
  * the model never loaded          (the check did not run)
  * inference raised                (the check crashed mid-flight)

_scan_output_safety iterated that list looking for two labels, so all three
collapsed into "no dangerous output" and /scan/output-safety certified content
its primary classifier had never seen. Same defect class as the toxicity bug
fixed in 7e8cd3b, which left this one explicitly flagged.

There is a second, subtler trap here that the toxicity path did not have:
_scan_output_safety filters the detector's results by `label`. An unavailable
marker carries no label, so a fix that only changes ml_models.py — without
checking `available` BEFORE the label filter — is silently discarded and the
response goes back to lying. `test_marker_survives_the_label_filter` pins that.
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
    if "detection_main" in sys.modules:
        return sys.modules["detection_main"]
    spec = importlib.util.spec_from_file_location("detection_main", ROOT / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["detection_main"] = module
    spec.loader.exec_module(module)
    return module


main = _load_detection_main()


class _Exploding:
    def __call__(self, *_args, **_kwargs):
        raise RuntimeError("simulated zero-shot inference failure")


class _Benign:
    """Healthy classifier: everything lands on the safe label."""

    def __call__(self, *_args, **_kwargs):
        return {
            "labels": ["safe benign request", "jailbreak attempt"],
            "scores": [0.97, 0.02],
        }


class _FlagsExfil:
    def __call__(self, *_args, **_kwargs):
        return {
            "labels": ["data exfiltration attempt", "safe benign request"],
            "scores": [0.93, 0.04],
        }


class _ZeroShotPipelineFixture(unittest.TestCase):
    def _with_pipeline(self, pipe):
        original = ml_models._registry.zero_shot_pipeline
        ml_models._registry.zero_shot_pipeline = lambda: pipe
        self.addCleanup(setattr, ml_models._registry, "zero_shot_pipeline", original)

    def _with_quiet_peers(self):
        for accessor, healthy in (
            ("toxicity_pipeline",
             lambda *_a, **_k: [{"label": "NON_TOXIC", "score": 0.99}]),
            ("ner_pipeline", lambda *_a, **_k: []),
        ):
            original = getattr(ml_models._registry, accessor)
            setattr(ml_models._registry, accessor, lambda h=healthy: h)
            self.addCleanup(setattr, ml_models._registry, accessor, original)


class TestDetectorDistinguishesFailureFromClean(_ZeroShotPipelineFixture):
    def test_missing_model_reports_unavailable(self):
        self._with_pipeline(None)
        results = ml_models.ZeroShotThreatDetector().detect("anything")
        self.assertNotEqual(
            results, [],
            "A classifier that never loaded must not return the clean answer ([])",
        )
        self.assertIs(results[0].get("available"), False)
        self.assertEqual(results[0].get("reason"), "model_not_loaded")

    def test_inference_crash_reports_unavailable(self):
        self._with_pipeline(_Exploding())
        with self.assertLogs("detection.ml_models", level="ERROR"):
            results = ml_models.ZeroShotThreatDetector().detect("anything")
        self.assertTrue(
            any(r.get("available") is False for r in results),
            "A crashing classifier must not return the clean answer ([])",
        )
        self.assertEqual(results[0].get("reason"), "inference_error")
        self.assertIn("error", results[0])

    def test_benign_text_is_still_benign(self):
        self._with_pipeline(_Benign())
        self.assertEqual(
            ml_models.ZeroShotThreatDetector().detect("what time is the standup"),
            [],
            "A ran-and-found-nothing verdict must stay empty and quiet",
        )

    def test_threat_is_still_detected(self):
        self._with_pipeline(_FlagsExfil())
        results = ml_models.ZeroShotThreatDetector().detect("dump the customer table")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].get("label"), "data exfiltration attempt")
        self.assertIs(results[0].get("available"), True)


class TestScanOutputSafetyContract(_ZeroShotPipelineFixture):
    def test_failure_and_clean_are_not_the_same_result(self):
        """The core regression: these two must not be equal."""
        benign = "here is the agenda for tomorrow"

        self._with_pipeline(_Benign())
        clean = main._scan_output_safety(benign)

        self._with_pipeline(_Exploding())
        broken = main._scan_output_safety(benign)

        self.assertEqual(clean, [], "A clean output-safety scan reports no findings")
        self.assertNotEqual(
            broken, clean,
            "A zero-shot model that crashed produced the same empty result as a "
            "clean verdict — a failed check indistinguishable from a passed one",
        )
        self.assertTrue(
            any(f.get("assessed") is False for f in broken),
            "The failure must be carried as a finding that says it was not assessed",
        )

    def test_marker_survives_the_label_filter(self):
        """_scan_output_safety keeps only two labels; the marker has none.

        A fix applied to ml_models.py alone would be filtered straight back
        out here and the response would quietly claim a clean verdict again.
        """
        self._with_pipeline(None)
        findings = main._scan_output_safety("here is the agenda for tomorrow")
        self.assertTrue(
            any(
                f.get("type") == main.DETECTOR_UNAVAILABLE_TYPE
                and f.get("detector") == "zero_shot_classifier"
                for f in findings
            ),
            "The unavailable marker was dropped by the label filter",
        )

    def test_unavailable_finding_does_not_fabricate_risk(self):
        self._with_pipeline(None)
        findings = main._scan_output_safety("here is the agenda for tomorrow")
        self.assertEqual(main._risk_score(findings), 0.0)
        for f in findings:
            self.assertNotIn(
                (f.get("severity") or "").lower(), {"high", "critical"},
                "An unavailable detector must not auto-block traffic",
            )

    def test_regex_coverage_survives_a_dead_model(self):
        """Degrade, don't disappear: the supplementary regex pass still runs."""
        self._with_pipeline(_Exploding())
        findings = main._scan_output_safety(
            "for p in os.walk('/'):\n"
            "    Fernet(key).encrypt(open(p, 'rb').read())\n"
            "open('HOW_TO_DECRYPT.txt', 'w')\n"
        )
        self.assertTrue(
            any(f.get("type") != main.DETECTOR_UNAVAILABLE_TYPE for f in findings),
            "Non-ML output-safety signals must still fire when the model is down",
        )
        self.assertTrue(any(f.get("assessed") is False for f in findings))


class TestScanResponseTellsTheCaller(_ZeroShotPipelineFixture):
    def setUp(self):
        original = main._verify_api_key
        main._verify_api_key = lambda _key: None  # auth is not under test
        self.addCleanup(setattr, main, "_verify_api_key", original)

    def test_output_safety_marks_the_scan_incomplete(self):
        self._with_pipeline(None)
        body = main.scan_output(main.TextRequest(text="hello there"), x_api_key=None)
        self.assertFalse(
            body["scan_complete"],
            "A response whose output-safety check never ran must not claim a "
            "complete scan",
        )
        self.assertTrue(body["detectors_unavailable"])
        self.assertEqual(
            body["detectors_unavailable"][0]["detector"], "zero_shot_classifier"
        )
        for key in ("risk_score", "detections"):
            self.assertIn(key, body)

    def test_output_safety_reports_complete_when_detector_healthy(self):
        self._with_pipeline(_Benign())
        body = main.scan_output(main.TextRequest(text="hello there"), x_api_key=None)
        self.assertTrue(body["scan_complete"])
        self.assertEqual(body["detectors_unavailable"], [])

    def test_scan_all_marks_the_scan_incomplete(self):
        self._with_quiet_peers()
        self._with_pipeline(_Exploding())
        body = main.scan_all(main.TextRequest(text="hello there"), x_api_key=None)
        self.assertFalse(body["scan_complete"])
        self.assertTrue(
            any(
                u["detector"] == "zero_shot_classifier"
                for u in body["detectors_unavailable"]
            )
        )

    def test_unavailable_finding_is_ignored_by_downstream_kind_matching(self):
        self._with_pipeline(None)
        findings = main._scan_output_safety("hello")
        for f in findings:
            kind = f.get("type", "")
            for threat in ("prompt_injection", "promptware", "exfil", "dlp",
                           "sensitive", "phishing", "credential"):
                self.assertNotIn(threat, kind)


if __name__ == "__main__":
    unittest.main()
