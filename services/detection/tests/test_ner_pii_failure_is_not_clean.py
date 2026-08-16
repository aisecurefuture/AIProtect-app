"""A PII check that never ran must not look like a PII check that found nothing.

NERPIIDetector.detect returned ``[]`` for three different situations:

  * the text contains no PII      (the check ran, found nothing)
  * the NER model never loaded    (the check did not run)
  * inference raised              (the check crashed mid-flight)

_scan_sensitive_data did `findings.extend(...)` on all three, so /scan,
/scan/all and /scan/sensitive-data reported the same "assessed, nothing found"
DLP verdict for content the PII model had never seen. This is the defect class
7e8cd3b fixed in the toxicity detector and explicitly left flagged here.

These tests pin the CONTRACT, not the wiring: whatever the finding schema
becomes, a DLP scan whose NER model was down must be distinguishable from a
DLP scan that came back clean, and that difference must reach the caller in
the response payload.
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
        raise RuntimeError("simulated NER inference failure")


class _NoEntities:
    """A healthy pipeline whose verdict is 'this text has no entities'."""

    def __call__(self, *_args, **_kwargs):
        return []


class _FindsAPerson:
    def __call__(self, *_args, **_kwargs):
        return [
            {
                "entity_group": "PER",
                "word": "Jane Doe",
                "score": 0.99,
                "start": 0,
                "end": 8,
            }
        ]


class _NERPipelineFixture(unittest.TestCase):
    """Swap the registry accessor: detect() resolves its pipeline per call."""

    def _with_pipeline(self, pipe):
        original = ml_models._registry.ner_pipeline
        ml_models._registry.ner_pipeline = lambda: pipe
        self.addCleanup(setattr, ml_models._registry, "ner_pipeline", original)

    def _with_quiet_peers(self):
        """Keep the other ML detectors out of the assertions.

        /scan and /scan/all run several detectors; a test about NER must not
        pass or fail because the zero-shot or toxicity model also happened to
        be missing on this host.
        """
        for accessor, healthy in (
            ("toxicity_pipeline",
             lambda *_a, **_k: [{"label": "NON_TOXIC", "score": 0.99}]),
            ("zero_shot_pipeline",
             lambda *_a, **_k: {"labels": ["safe benign request"], "scores": [0.99]}),
        ):
            original = getattr(ml_models._registry, accessor)
            setattr(ml_models._registry, accessor, lambda h=healthy: h)
            self.addCleanup(setattr, ml_models._registry, accessor, original)


class TestDetectorDistinguishesFailureFromClean(_NERPipelineFixture):
    def test_missing_model_reports_unavailable(self):
        self._with_pipeline(None)
        results = ml_models.NERPIIDetector().detect("anything at all")
        self.assertNotEqual(
            results, [],
            "A NER model that never loaded must not return the clean answer ([])",
        )
        self.assertTrue(any(r.get("available") is False for r in results))
        self.assertEqual(results[0].get("reason"), "model_not_loaded")

    def test_inference_crash_reports_unavailable(self):
        self._with_pipeline(_Exploding())
        with self.assertLogs("detection.ml_models", level="ERROR"):
            results = ml_models.NERPIIDetector().detect("anything at all")
        self.assertTrue(
            any(r.get("available") is False for r in results),
            "A crashing NER pipeline must not return the clean answer ([])",
        )
        marker = next(r for r in results if r.get("available") is False)
        self.assertEqual(marker.get("reason"), "inference_error")
        self.assertIn("error", marker)

    def test_clean_text_is_still_clean(self):
        self._with_pipeline(_NoEntities())
        self.assertEqual(
            ml_models.NERPIIDetector().detect("the quarterly numbers look fine"),
            [],
            "A ran-and-found-nothing verdict must stay empty and quiet",
        )

    def test_pii_is_still_detected(self):
        self._with_pipeline(_FindsAPerson())
        results = ml_models.NERPIIDetector().detect("Jane Doe signed the form")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].get("type"), "sensitive_data")
        self.assertEqual(results[0].get("entity_type"), "person_name")
        self.assertIs(results[0].get("available"), True)


class TestScanSensitiveDataContract(_NERPipelineFixture):
    def test_failure_and_clean_are_not_the_same_result(self):
        """The core regression: these two must not be equal."""
        benign = "the quarterly numbers look fine"

        self._with_pipeline(_NoEntities())
        clean = main._scan_sensitive_data(benign)

        self._with_pipeline(_Exploding())
        broken = main._scan_sensitive_data(benign)

        self.assertEqual(clean, [], "A clean DLP scan reports no findings")
        self.assertNotEqual(
            broken, clean,
            "A NER model that crashed produced the same empty result as a clean "
            "DLP verdict — a failed check indistinguishable from a passed one",
        )
        self.assertTrue(
            any(f.get("assessed") is False for f in broken),
            "The failure must be carried as a finding that says it was not assessed",
        )

    def test_unavailable_finding_does_not_fabricate_risk(self):
        """A gap in coverage is not evidence of a threat.

        services/runtime escalates any finding with severity high/critical
        straight to block, so a broken NER model must never emit one.
        """
        self._with_pipeline(None)
        findings = main._scan_sensitive_data("the quarterly numbers look fine")
        self.assertEqual(main._risk_score(findings), 0.0)
        for f in findings:
            self.assertNotIn(
                (f.get("severity") or "").lower(), {"high", "critical"},
                "An unavailable detector must not auto-block traffic",
            )

    def test_regex_coverage_survives_a_dead_ner_model(self):
        """Degrade, don't disappear: the regex passes still run."""
        self._with_pipeline(_Exploding())
        findings = main._scan_sensitive_data("my ssn is 123-45-6789")
        self.assertTrue(
            any(f.get("subtype") == "ssn" for f in findings),
            "Structured PII must still be caught when the NER model is down",
        )
        self.assertTrue(any(f.get("assessed") is False for f in findings))


class TestScanResponseTellsTheCaller(_NERPipelineFixture):
    """The caller makes a security/evidence decision on this payload."""

    def setUp(self):
        original = main._verify_api_key
        main._verify_api_key = lambda _key: None  # auth is not under test
        self.addCleanup(setattr, main, "_verify_api_key", original)

    def test_scan_sensitive_data_marks_the_scan_incomplete(self):
        self._with_pipeline(None)
        body = main.scan_sensitive(main.TextRequest(text="hello there"), x_api_key=None)
        self.assertFalse(
            body["scan_complete"],
            "A DLP response whose NER check never ran must not claim a complete scan",
        )
        self.assertTrue(body["detectors_unavailable"])
        self.assertEqual(body["detectors_unavailable"][0]["detector"], "ner_pii_model")
        # Existing fields must survive untouched (live production consumers).
        for key in ("risk_score", "detections"):
            self.assertIn(key, body)

    def test_scan_sensitive_data_reports_complete_when_detector_healthy(self):
        self._with_pipeline(_NoEntities())
        body = main.scan_sensitive(main.TextRequest(text="hello there"), x_api_key=None)
        self.assertTrue(body["scan_complete"])
        self.assertEqual(body["detectors_unavailable"], [])

    def test_scan_marks_the_scan_incomplete(self):
        self._with_quiet_peers()
        self._with_pipeline(_Exploding())
        body = main.scan(main.GenericScanRequest(content="hello there"), x_api_key=None)
        self.assertFalse(body["scan_complete"])
        self.assertTrue(
            any(u["detector"] == "ner_pii_model" for u in body["detectors_unavailable"])
        )

    def test_scan_all_marks_the_scan_incomplete(self):
        self._with_quiet_peers()
        self._with_pipeline(None)
        body = main.scan_all(main.TextRequest(text="hello there"), x_api_key=None)
        self.assertFalse(body["scan_complete"])
        self.assertTrue(
            any(u["detector"] == "ner_pii_model" for u in body["detectors_unavailable"])
        )

    def test_unavailable_finding_is_ignored_by_downstream_kind_matching(self):
        """Consumers bucket findings by substring of `type`.

        url-trust-gate matches "prompt_injection" / "promptware" / "exfil" /
        "dlp" / "sensitive" / "phishing" / "credential". The unavailable
        finding must not register as one of those threat classes — least of
        all "sensitive", which is what this detector emits when it DOES fire.
        """
        self._with_pipeline(None)
        findings = main._scan_sensitive_data("hello")
        for f in findings:
            kind = f.get("type", "")
            for threat in ("prompt_injection", "promptware", "exfil", "dlp",
                           "sensitive", "phishing", "credential"):
                self.assertNotIn(threat, kind)


if __name__ == "__main__":
    unittest.main()
