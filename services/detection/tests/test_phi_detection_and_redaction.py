"""PHI must actually be detected and actually be removed.

WHY THIS EXISTS

The pii.* classes cover nine of HIPAA Safe Harbor's 18 identifier categories
(§164.514(b)(2)). The nine they missed are the healthcare-specific ones, so a
covered entity redacting with pii.* alone was shipping medical record numbers
and Medicare IDs to an AI provider while a HIPAA control read green. The phi.*
classes close that. This file pins three properties, each of which has a
distinct way of silently failing:

  1. DETECTION -- the pattern fires on a real identifier.
  2. REDACTION -- the value is actually gone from the output. A class can be
     detected and reported while remaining in the payload if it is missing from
     _REDACT_CLASS_MAP; the finding looks right and the PHI still leaves.
  3. PRECISION -- benign text produces nothing. This is not politeness. A
     redactor that mangles invoice numbers gets switched off by the tenant, and
     a switched-off redactor protects nobody. transparent_proxy.py records what
     over-matching cost at production scale.

Property 2 is the one that caught a real defect while this was being written:
an MBI adjacent to an unrelated "Member ID:" label was redacted under
phi.health_plan_id, so phi.mbi counted zero. The value was removed, but the
class on the compliance record was wrong. test_mbi_is_classed_as_mbi pins it.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # services/detection
REPO = ROOT.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(REPO / "libs" / "cyberarmor-core"))

import main  # noqa: E402


# One realistic positive per class. Values are synthetic but format-correct.
POSITIVES = {
    "phi.mrn":            "MRN: 004512338 admitted 3 days ago",
    "phi.health_plan_id": "Member ID: XZ9928471123 verified at intake",
    "phi.mbi":            "Medicare MBI 1EG4-TE5-MK73 on file",
    "phi.icd10":          "Assessment: E11.9, type 2 diabetes without complications",
    "phi.npi":            "Referring provider NPI 1234567893",
    "phi.dea":            "DEA number AB1234563 on the prescription",
}

# Text that must produce NO phi.* match. Each entry is a shape that a naive
# implementation gets wrong: bare digit runs at MRN/NPI length, an ICD-10-like
# code without the dot, and high-entropy tokens that look structured.
BENIGN = [
    "Invoice number 004512338 is overdue",
    "Order #1234567893 shipped today",
    "Ticket 8829471123 was closed by support",
    "Form I10 must be filed; see section E11 and code A1",
    "commit 3f9a2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90",
    "AKIAIOSFODNN7EXAMPLE and sk-proj-abcdefghijklmnopqrst",
    "uuid 550e8400-e29b-41d4-a716-446655440000",
    "Build v2.10.4 released; SKU AB1234563X in stock",
    "The quick brown fox jumps over the lazy dog",
]

PHI_CLASSES = sorted(c for c in main._REDACT_CLASS_MAP if c.startswith("phi."))


def _matches(text: str, cls: str) -> bool:
    return any(p.search(text) for _n, p, _g in main._REDACT_CLASS_MAP[cls])


class TestPHIIsDetected(unittest.TestCase):

    def test_every_phi_class_is_in_the_catalog(self):
        """A class absent from the catalog cannot be chosen in a policy."""
        for cls in POSITIVES:
            self.assertIn(cls, main.REDACT_CLASS_CATALOG, cls)

    def test_each_class_detects_its_identifier(self):
        for cls, text in POSITIVES.items():
            with self.subTest(cls=cls):
                self.assertTrue(_matches(text, cls),
                                f"{cls} did not fire on {text!r}")


class TestPHIIsActuallyRemoved(unittest.TestCase):
    """Detection without redaction still leaks. Assert on the output text."""

    def test_no_phi_value_survives_redaction(self):
        note = ("Patient Jane Doe, MRN: 004512338, MBI 1EG4-TE5-MK73, "
                "Member ID: XZ9928471123, dx E11.9, NPI 1234567893, "
                "DEA AB1234563.")
        out, _counts, status = main._redact_text(note, PHI_CLASSES)
        self.assertTrue(status["complete"], status)
        for value in ("004512338", "1EG4-TE5-MK73", "XZ9928471123",
                      "E11.9", "1234567893", "AB1234563"):
            with self.subTest(value=value):
                self.assertNotIn(value, out,
                                 f"{value} survived redaction: {out!r}")

    def test_mbi_is_classed_as_mbi(self):
        """The defect this file was written against.

        An MBI followed by an unrelated 'Member ID:' label was captured by the
        health-plan trailing-label pattern, so the value was redacted under the
        wrong class and phi.mbi counted zero. The value leaving is not the
        failure here -- the compliance record naming the wrong identifier
        category is.
        """
        note = "MBI 1EG4-TE5-MK73, Member ID: XZ9928471123"
        _out, counts, _status = main._redact_text(note, PHI_CLASSES)
        self.assertEqual(counts.get("phi.mbi"), 1,
                         f"MBI not classed as phi.mbi; counts={counts}")
        self.assertEqual(counts.get("phi.health_plan_id"), 1,
                         f"health plan id miscounted; counts={counts}")

    def test_trailing_label_still_matches_when_genuinely_adjacent(self):
        """Tightening the trailing-label gap must not disable the form."""
        out, _c, _s = main._redact_text("XZ9928471123 (member id) on file",
                                        ["phi.health_plan_id"])
        self.assertIn("REDACTED", out, out)


class TestPHIDoesNotOverMatch(unittest.TestCase):

    def test_benign_text_produces_no_phi_match(self):
        for text in BENIGN:
            for cls in PHI_CLASSES:
                with self.subTest(text=text, cls=cls):
                    self.assertFalse(
                        _matches(text, cls),
                        f"{cls} false-positived on {text!r}")

    def test_benign_text_is_returned_unchanged(self):
        for text in BENIGN:
            with self.subTest(text=text):
                out, counts, _status = main._redact_text(text, PHI_CLASSES)
                self.assertEqual(out, text, f"redactor altered benign text: {counts}")


class TestPHIModelIsRegisteredSeparately(unittest.TestCase):
    """PHI needs its own model, and its own line in /ready.

    dslim/bert-base-NER is CoNLL-2003 -- PER/LOC/ORG/MISC and nothing else. It
    cannot emit a medical-record entity at any threshold, so pointing PHI at it
    yields a detector that is permanently and silently clean. The separate
    registry entry is also what lets /ready say "PII healthy, PHI missing"
    instead of implying both work.
    """

    def test_phi_model_is_a_distinct_registry_entry(self):
        import ml_models
        self.assertIn("ner_phi", ml_models.MODEL_IDS)
        self.assertNotEqual(ml_models.MODEL_IDS["ner_phi"],
                            ml_models.MODEL_IDS["ner_pii"],
                            "PHI must not reuse the CoNLL PII model")

    def test_phi_group_map_covers_the_record_identifiers(self):
        import ml_models
        for cls in ("phi.mrn", "phi.health_plan_id"):
            self.assertIn(cls, ml_models.REDACT_CLASS_TO_NER_PHI_GROUPS, cls)


if __name__ == "__main__":
    unittest.main()
