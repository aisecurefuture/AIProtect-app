"""A page that mentions a person, a company, or a place is not exfiltrating data.

DIAGNOSED 2026-08-15 from the code, no model run required. The gate scored
data_exfil from any detection finding whose ``type`` contained "sensitive":

    scores.data_exfil = max(scores.data_exfil, float(f.get("confidence", 0.0)))

The detection service emits ``type="sensitive_data"`` for ordinary named
entities -- PER / LOC / ORG / GPE -- from its NER model
(services/detection/ml_models.py:936, _NER_PII_GROUPS at :585), and the
``confidence`` on those findings is the tagger's ENTITY-TYPE score: "I am
99.9% sure this token is a person's name." Consumed as a threat probability,
it made every page naming anyone or anywhere score data_exfil ~1.00. Because
overall_risk is a max-of across dimensions, that became overall_risk ~1.00 and
then a warn -- and under a tenant policy with a redact or block rule at that
threshold, essentially all traffic.

The reported case is scripts/poc/test-pages/benign.html, a tea article whose
entire threat surface is the phrases "Camellia sinensis", "Vermont", and "the
Tea Society of Vermont".

The 2026-08-14 handoff attributed this to the 1fae0294 fine-tune and recorded
it as undiagnosable without the models. The fine-tune is not implicated by
this path: the arithmetic above turns a CORRECT entity tagging into a maximal
threat score, and it does so for any NER model at any quality.

These tests drive the REAL _score_with_detection with the REAL finding shapes
the detection service produces.

Run: python3 -m unittest services.url-trust-gate.tests.test_named_entities_are_not_data_exfiltration
  or: cd services/url-trust-gate && python3 -m unittest tests.test_named_entities_are_not_data_exfiltration
"""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path

_GATE = Path(__file__).resolve().parents[1]
_REPO = _GATE.parent.parent
sys.path.insert(0, str(_GATE))
sys.path.insert(0, str(_REPO / "libs" / "cyberarmor-core"))

import main as gate  # noqa: E402


def _client_returning(detections, extra=None):
    """An httpx.AsyncClient stand-in whose /scan returns these detections."""

    body = {"detections": detections}
    if extra:
        body.update(extra)

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            class _R:
                status_code = 200
                text = ""

                @staticmethod
                def json():
                    return body

            return _R()

    return _Client


def _signals(text="A Beginner's Guide to Tea Blends"):
    s = gate.ExtractedSignals.__new__(gate.ExtractedSignals)
    # Only the fields _score_with_detection reads. Every heuristic is off, so
    # any score that appears came from the detection findings under test.
    s.has_credential_form = False
    s.has_brand_impersonation_keywords = False
    s.hidden_text_blocks = []
    s.text_for_ml = text
    s.iocs = []
    return s


def _req():
    return gate.TrustGateRequest(
        tenant_id="cyberarmor",
        url="http://demo-content:8090/benign.html",
        source="served-demo",
    )


class _ScoringCase(unittest.TestCase):
    def score(self, detections, extra=None):
        real = gate.httpx.AsyncClient
        gate.httpx.AsyncClient = _client_returning(detections, extra)
        try:
            scores, _ = asyncio.run(
                gate._score_with_detection(_req(), _signals(), session_id="req-test")
            )
        finally:
            gate.httpx.AsyncClient = real
        return scores


# The exact shape ml_models.py:936 produces for a CoNLL entity.
def _ner(entity_type, value, confidence=0.9997):
    return {
        "available": True,
        "type": "sensitive_data",
        "subtype": "ner_pii_model",
        "entity_type": entity_type,
        "value": value,
        "confidence": confidence,
        "severity": "medium",
        "detector": "ner_model",
        "model": "dslim/bert-base-NER",
    }


class NamedEntitiesScoreZeroExfil(_ScoringCase):

    def test_the_benign_demo_page_entities_do_not_score_data_exfil(self):
        """The reported false positive, reconstructed from its actual content."""
        scores = self.score([
            _ner("person_name", "Camellia sinensis"),
            _ner("location", "Vermont"),
            _ner("organization", "Tea Society of Vermont"),
        ])
        self.assertEqual(
            scores.data_exfil, 0.0,
            f"a tea article scored data_exfil={scores.data_exfil:.2f} on named "
            "entities alone -- the NER tagger's entity-type confidence is being "
            "read as a threat probability",
        )

    def test_and_therefore_the_page_carries_no_overall_risk(self):
        """The score that actually drives the verdict."""
        scores = self.score([
            _ner("person_name", "Camellia sinensis"),
            _ner("location", "Vermont"),
            _ner("organization", "Tea Society of Vermont"),
        ])
        self.assertLess(
            scores.overall_risk, 0.5,
            f"overall_risk={scores.overall_risk:.2f} still crosses the "
            "fallback warn threshold (_fallback_decision: overall_risk >= 0.5) "
            "for a page whose only findings are ordinary named entities",
        )

    def test_a_perfectly_confident_tagger_still_scores_zero(self):
        """Confidence 1.0 is the tagger being certain about the TOKEN TYPE."""
        scores = self.score([_ner("person_name", "Alice", confidence=1.0)])
        self.assertEqual(
            scores.data_exfil, 0.0,
            "entity-type confidence is still being used as a threat score",
        )

    def test_contact_details_on_a_page_are_not_exfiltration(self):
        """An email or phone number on a contact page is not data leaving."""
        scores = self.score([
            {"type": "sensitive_data", "subtype": "entity_dlp", "entity": "email",
             "match": "hello@example.test", "severity": "medium", "detector": "entity_regex"},
            {"type": "sensitive_data", "subtype": "entity_dlp", "entity": "phone",
             "match": "555-010-9999", "severity": "medium", "detector": "entity_regex"},
        ])
        self.assertEqual(scores.data_exfil, 0.0,
                         f"a published contact address scored data_exfil={scores.data_exfil:.2f}")


class RealSecretsStillScore(_ScoringCase):
    """The fix must not be "score nothing" -- that trades a false positive for
    a false negative, which is the worse of the two for a security product."""

    def test_a_leaked_private_key_scores_high(self):
        scores = self.score([
            {"type": "sensitive_data", "subtype": "private_key", "severity": "high",
             "detector": "regex_fallback"},
        ])
        self.assertGreaterEqual(
            scores.data_exfil, 0.7,
            f"a page publishing a private key scored data_exfil={scores.data_exfil:.2f}",
        )

    def test_a_leaked_cloud_credential_scores_high(self):
        for subtype in ("aws_key", "github_token", "openai_api_key", "anthropic_api_key"):
            with self.subTest(subtype=subtype):
                scores = self.score([
                    {"type": "sensitive_data", "subtype": subtype,
                     "severity": "high", "detector": "regex_fallback"},
                ])
                self.assertGreaterEqual(
                    scores.data_exfil, 0.7,
                    f"{subtype} scored data_exfil={scores.data_exfil:.2f}",
                )

    def test_regulated_identifiers_score(self):
        scores = self.score([
            {"type": "sensitive_data", "subtype": "ssn", "severity": "medium",
             "detector": "regex_fallback"},
        ])
        self.assertGreaterEqual(scores.data_exfil, 0.5,
                                f"an SSN scored data_exfil={scores.data_exfil:.2f}")

    def test_a_semantic_credential_dump_scores(self):
        """Semantic DLP describes the SHAPE of the text, which is the right
        kind of signal for exfiltration."""
        scores = self.score([
            {"type": "sensitive_data", "subtype": "semantic_dlp",
             "concept": "credential_exfiltration", "similarity": 0.81,
             "threshold": 0.72, "severity": "high"},
        ])
        self.assertGreaterEqual(
            scores.data_exfil, 0.7,
            f'a "credential dump" semantic match scored data_exfil={scores.data_exfil:.2f}',
        )

    def test_a_secret_alongside_named_entities_still_scores(self):
        """The realistic mixed page: prose (entities) plus a leaked key."""
        scores = self.score([
            _ner("person_name", "Alice"),
            _ner("organization", "Contoso"),
            {"type": "sensitive_data", "subtype": "aws_key", "severity": "high",
             "detector": "regex_fallback"},
        ])
        self.assertGreaterEqual(
            scores.data_exfil, 0.7,
            "the entity findings suppressed the real secret finding",
        )

    def test_content_evidence_alone_never_reaches_certainty(self):
        """No page-content finding should assert 1.00. Saturation is what let a
        single detector dominate overall_risk in the first place."""
        for subtype in gate._EXFIL_WEIGHTS:
            with self.subTest(subtype=subtype):
                scores = self.score([
                    {"type": "sensitive_data", "subtype": subtype, "severity": "high"},
                ])
                self.assertLess(
                    scores.data_exfil, 1.0,
                    f"{subtype} scores a saturated data_exfil={scores.data_exfil:.2f}",
                )


class UnknownDetectorClassesAreLoud(_ScoringCase):
    """Scoring an unrecognised class as 0.0 is right; doing it silently is how
    a real signal disappears when the detection service grows a new detector."""

    def test_an_unmapped_class_is_logged(self):
        gate._EXFIL_UNKNOWN_LABELS_SEEN.clear()
        with self.assertLogs(gate.logger, level="WARNING") as cm:
            self.score([
                {"type": "sensitive_data", "subtype": "some_future_detector",
                 "severity": "high"},
            ])
        self.assertTrue(
            any("exfil_label_unmapped" in line for line in cm.output),
            f"an unmapped sensitive_data class was dropped silently: {cm.output}",
        )

    def test_a_known_non_exfil_class_is_not_logged_as_unmapped(self):
        gate._EXFIL_UNKNOWN_LABELS_SEEN.clear()
        with self.assertLogs(gate.logger, level="WARNING") as cm:
            gate.logger.warning("anchor")  # assertLogs needs at least one record
            self.score([_ner("person_name", "Alice")])
        self.assertFalse(
            any("exfil_label_unmapped" in line for line in cm.output),
            "person_name was reported as an unknown class; it is a considered "
            "zero, and mixing the two makes the warning useless",
        )


class ADegradedScanSaysSo(_ScoringCase):
    """A verdict produced while a detector was unloaded must not be
    indistinguishable from one where every check ran."""

    def test_unavailable_detectors_are_logged(self):
        with self.assertLogs(gate.logger, level="WARNING") as cm:
            self.score(
                [],
                extra={"detectors_unavailable": [
                    {"detector": "ner_pii_model", "reason": "model_not_loaded",
                     "model": "dslim/bert-base-NER"},
                ]},
            )
        self.assertTrue(
            any("detection_degraded" in line for line in cm.output),
            f"the gate scored a URL with a dead detector and said nothing: {cm.output}",
        )


class TheOtherDimensionsStillUseConfidence(_ScoringCase):
    """prompt_injection and promptware findings DO carry a threat probability;
    this fix must not have collateralled them."""

    def test_prompt_injection_confidence_is_still_read(self):
        scores = self.score([
            {"type": "prompt_injection", "confidence": 0.93, "severity": "high"},
        ])
        self.assertAlmostEqual(scores.prompt_injection, 0.93, places=4)

    def test_promptware_confidence_is_still_read(self):
        scores = self.score([
            {"type": "promptware", "confidence": 0.88, "severity": "high"},
        ])
        self.assertAlmostEqual(scores.promptware, 0.88, places=4)


if __name__ == "__main__":
    unittest.main()
