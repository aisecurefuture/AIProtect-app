"""A PHI redaction span must never stop in the middle of an identifier.

WHY THIS EXISTS

Two defects, found by replaying the real obi/deid_roberta_i2b2 output measured
on the box through the redaction path. The first hid the second.

  1. NO PHI SPAN WAS EVER PRODUCED. `redact_spans` parameterised the forward
     map (class -> entity groups, `_group_map`) per detector but hardcoded the
     reverse one (group -> class) to the PII map, which by construction cannot
     contain a PHI group. Every PHI entity cleared the group filter, cleared
     the confidence threshold, had valid offsets, and was then dropped by a
     lookup that returned None. `NERPHIDetector.redact_spans` was a no-op that
     returned `complete=True`, so `/scan/redact` reported a finished pass on
     text with the medical record number still in it. `ner_phi` reported
     `status: loaded` throughout -- ground rule 2, "loaded is not working".

  2. THE SPAN THAT FIX PRODUCES IS A FRAGMENT. The tokenizer splits 4451227
     into "44512" (0.984) and "27" (0.424); only the first clears the 0.75
     threshold. Redacting it alone emits "record [REDACTED:phi.mrn]27" -- a
     partial identifier that LOOKS redacted, so nothing downstream flags it.
     Fixing defect 1 without defect 2 converts a total leak into a disguised
     one. Both are fixed together, and this file pins both.

Lowering the threshold does not help; it admits MORE fragments. The fix is
aggregation ("first" instead of "simple") plus span expansion, and only the
expansion is a guarantee -- aggregation is a pipeline setting that a
deployment override or a transformers upgrade can change underneath us.

RAW is the entity list measured on the box, verbatim. Offsets are computed
from the text by search rather than typed, so they are the offsets the
pipeline reports rather than a transcription of them.
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
import ml_models  # noqa: E402


TEXT = ("Patient admitted under record 4451227, seen by Dr. Alvarez at "
        "Mercy General on 04/12/2024.")

# Measured on the box: aggregation_strategy="simple", threshold 0.75.
#   ID     0.984   44512      <- clears the threshold
#   ID     0.424   27         <- does NOT; this is the fragment left behind
#   STAFF  1.000   Alvarez
#   HOSP   1.000   Mercy
#   DATE   0.989   04/        <- DATE splits identically: systemic, not a one-off
#   DATE   0.783   12/2024
RAW = [
    ("ID",    0.984, "44512"),
    ("ID",    0.424, "27"),
    ("STAFF", 1.000, "Alvarez"),
    ("HOSP",  1.000, "Mercy"),
    ("DATE",  0.989, "04/"),
    ("DATE",  0.783, "12/2024"),
]

MRN = "4451227"


def _entities(text: str, raw) -> list:
    ents, cursor = [], 0
    for group, score, word in raw:
        start = text.index(word, cursor)
        cursor = start            # fragments are adjacent, as measured
        ents.append({"entity_group": group, "score": score, "word": word,
                     "start": start, "end": start + len(word)})
    return ents


class _StubPipe:
    def __init__(self, entities):
        self._entities = entities

    def __call__(self, *_args, **_kwargs):
        return list(self._entities)


class _PHIPipelineFixture(unittest.TestCase):
    """Swap in the measured entity list for the real clinical model."""

    def _with_phi_pipeline(self, pipe):
        reg = ml_models._registry
        original = reg.ner_phi_pipeline
        reg.ner_phi_pipeline = lambda: pipe
        self.addCleanup(setattr, reg, "ner_phi_pipeline", original)
        # The PII model is not under test and is absent in CI.
        original_pii = reg.ner_pipeline
        reg.ner_pipeline = lambda: None
        self.addCleanup(setattr, reg, "ner_pipeline", original_pii)

    def setUp(self):
        self._with_phi_pipeline(_StubPipe(_entities(TEXT, RAW)))


class TestThePHIModelActuallyContributesSpans(_PHIPipelineFixture):
    """Defect 1. Without this the rest of the file passes vacuously."""

    def test_phi_entity_becomes_a_span(self):
        result = ml_models.ner_phi_detector.redact_spans(TEXT, ["phi.mrn"])
        self.assertTrue(
            result.spans,
            "The clinical model returned an ID entity above threshold with "
            "valid offsets and redact_spans produced nothing. This is the "
            "no-op that reported complete=True while the MRN went out in "
            "the clear.",
        )

    def test_both_map_directions_are_overridden_together(self):
        """Structural guard: a detector may not inherit half a mapping.

        The defect was one hardcoded lookup. A future subclass for another
        model would reintroduce it exactly the same way, and the failure is
        silent -- zero spans, complete=True.
        """
        for cls in (ml_models.NERPIIDetector, ml_models.NERPHIDetector):
            with self.subTest(detector=cls.__name__):
                groups = {g for gs in cls._group_map.values() for g in gs}
                self.assertTrue(groups, f"{cls.__name__} has an empty _group_map")
                for g in sorted(groups):
                    self.assertIn(
                        g, cls._class_map,
                        f"{cls.__name__} asks the model for group {g!r} but its "
                        f"_class_map cannot turn it back into a redact class, so "
                        f"every {g!r} entity is silently discarded",
                    )


class TestNoSpanEndsMidIdentifier(_PHIPipelineFixture):
    """Defect 2 -- the property, stated on the output string."""

    def test_the_whole_mrn_is_covered_by_one_span(self):
        result = ml_models.ner_phi_detector.redact_spans(TEXT, ["phi.mrn"])
        covered = [TEXT[s:e] for s, e, _c in result.spans]
        self.assertIn(
            MRN, covered,
            f"span covers {covered!r}; the low-confidence '27' subword is the "
            f"part that gets left behind",
        )

    def test_redacted_text_contains_no_fragment_of_the_mrn(self):
        out, counts, status = main._redact_text(TEXT, ["phi.mrn"])
        self.assertTrue(status["complete"], status)
        self.assertEqual(counts.get("phi.mrn"), 1, counts)
        self.assertNotIn(MRN, out, f"the MRN survived redaction: {out!r}")
        self.assertNotIn(
            "[REDACTED:phi.mrn]27", out,
            f"PARTIAL IDENTIFIER EMITTED: {out!r} -- this looks redacted and "
            f"is not",
        )

    def test_no_span_boundary_falls_inside_an_alphanumeric_run(self):
        """The property itself, independent of this one value."""
        result = ml_models.ner_phi_detector.redact_spans(TEXT, ["phi.mrn"])
        for s, e, cls in result.spans:
            with self.subTest(span=(s, e, cls)):
                if s > 0:
                    self.assertFalse(
                        TEXT[s - 1].isalnum() and TEXT[s].isalnum(),
                        f"span starts mid-token at {s}: ...{TEXT[max(0,s-6):e]!r}",
                    )
                if e < len(TEXT):
                    self.assertFalse(
                        TEXT[e - 1].isalnum() and TEXT[e].isalnum(),
                        f"span ends mid-token at {e}: ...{TEXT[s:e+6]!r}",
                    )


#: What the model ACTUALLY returns in production, measured on the box
#: 2026-08-05 after the fix: transformers 5.14.1, huggingface_hub 1.26.0,
#: obi/deid_roberta_i2b2, aggregation_strategy="first".
#:
#:   ID     1.000 [30:38] ' 4451227,'
#:   STAFF  1.000 [51:58] ' Alvarez'
#:   HOSP   1.000 [62:67] ' Mercy'
#:   HOSP   0.997 [68:75] ' General'
#:   DATE   1.000 [79:90] ' 04/12/2024.'
#:
#: Two things this records that the RAW fixture above cannot:
#:
#:   1. "first" really does merge the subwords -- one ID entity at 1.000,
#:      no 44512/27 split. That was an assumption until it was measured.
#:   2. The spans are GREEDY about trailing punctuation: [30:38] includes the
#:      comma, and DATE includes the sentence-final period. That comes from
#:      the MODEL, not from _expand_span_to_token_bounds, which is a no-op on
#:      these offsets (both edges already sit against whitespace). It costs a
#:      comma in the output and is deliberately left alone -- trimming risks
#:      under-redaction to buy punctuation.
#:
#: Offsets are used verbatim rather than searched for, because the `word`
#: field carries RoBERTa's leading-space marker and does not match the text
#: at its own offsets.
RAW_FIRST = [
    ("ID",    1.000, 30, 38),
    ("STAFF", 1.000, 51, 58),
    ("HOSP",  1.000, 62, 67),
    ("HOSP",  0.997, 68, 75),
    ("DATE",  1.000, 79, 90),
]


class TestAgainstTheRealMeasuredModelOutput(_PHIPipelineFixture):
    """The production shape, not the defect shape.

    RAW (above) is what the model returned BEFORE the fix and is kept because
    a redaction path must survive it. This class is what it returns AFTER, on
    the deployed box. Both are pinned: the aggregation strategy is a setting,
    and a transformers upgrade can change the word-merge heuristic underneath
    it -- the container even warns "Tokenizer does not support real words,
    using fallback heuristic". If that heuristic regresses to the split shape,
    RAW is the test that still passes; if it stays merged, this one does.
    """

    def setUp(self):
        entities = [
            {"entity_group": g, "score": s, "word": TEXT[a:b],
             "start": a, "end": b}
            for g, s, a, b in RAW_FIRST
        ]
        self._with_phi_pipeline(_StubPipe(entities))

    def test_the_merged_entity_covers_the_whole_mrn(self):
        result = ml_models.ner_phi_detector.redact_spans(TEXT, ["phi.mrn"])
        covered = [TEXT[s:e] for s, e, _c in result.spans]
        self.assertTrue(covered, "no PHI span produced")
        self.assertIn(MRN, "".join(covered), f"span covers {covered!r}")

    def test_no_fragment_survives(self):
        out, counts, status = main._redact_text(TEXT, ["phi.mrn"])
        self.assertTrue(status["complete"], status)
        self.assertEqual(counts.get("phi.mrn"), 1, counts)
        self.assertNotIn(MRN, out, out)
        self.assertNotIn("[REDACTED:phi.mrn]27", out, out)
        for tail in ("227", "27,", "7,"):
            with self.subTest(fragment=tail):
                self.assertNotIn(
                    f"[REDACTED:phi.mrn]{tail}", out,
                    f"partial identifier {tail!r} left beside the marker: {out!r}",
                )

    def test_expansion_does_not_widen_an_already_whole_span(self):
        """Guards against expansion compounding the model's greediness.

        The model's [30:38] already ends against whitespace. If expansion
        started walking past that, redactions would creep into neighbouring
        words on every entity the model returns.
        """
        s, e = ml_models._expand_span_to_token_bounds(TEXT, 30, 38)
        self.assertEqual(
            (s, e), (30, 38),
            f"expansion widened a whole span to {TEXT[s:e]!r}",
        )


class TestSpanExpansionUnits(unittest.TestCase):
    """_expand_span_to_token_bounds, including where it must NOT expand.

    Over-expansion is not free: the redactor that mangles benign text gets
    switched off by the tenant, and a switched-off redactor protects nobody
    (see the note in test_phi_detection_and_redaction.py).
    """

    def _expand(self, text, frag):
        s = text.index(frag)
        return ml_models._expand_span_to_token_bounds(text, s, s + len(frag))

    def test_expands_a_split_digit_run(self):
        text = "record 4451227, seen"
        s, e = self._expand(text, "44512")
        self.assertEqual(text[s:e], "4451227")

    def test_expands_across_internal_hyphens(self):
        """An MBI is hyphenated; half of one is still PHI."""
        text = "Medicare MBI 1EG4-TE5-MK73 on file"
        s, e = self._expand(text, "TE5")
        self.assertEqual(text[s:e], "1EG4-TE5-MK73")

    def test_expands_across_an_internal_dot(self):
        text = "Assessment: E11.9, type 2 diabetes"
        s, e = self._expand(text, "E11")
        self.assertEqual(text[s:e], "E11.9")

    def test_does_not_swallow_a_sentence_final_period(self):
        text = "admitted under record 4451227."
        s, e = self._expand(text, "44512")
        self.assertEqual(text[s:e], "4451227")

    def test_does_not_cross_whitespace(self):
        """A name is not an identifier; expansion must stop at the space."""
        text = "held by Jane Doe."
        s, e = self._expand(text, "Doe")
        self.assertEqual(text[s:e], "Doe")

    def test_a_whole_token_span_is_left_alone(self):
        text = "held by Jane Doe."
        s, e = self._expand(text, "Jane")
        self.assertEqual(text[s:e], "Jane")

    def test_is_idempotent(self):
        text = "record 4451227, seen"
        s, e = self._expand(text, "44512")
        self.assertEqual(
            ml_models._expand_span_to_token_bounds(text, s, e), (s, e))

    def test_offsets_past_the_end_do_not_raise(self):
        self.assertEqual(
            ml_models._expand_span_to_token_bounds("abc", 10, 20), (3, 3))

    def test_an_empty_span_does_not_grow_into_coverage(self):
        """A bad offset must not become a redaction of adjacent text."""
        self.assertEqual(
            ml_models._expand_span_to_token_bounds("abc", 3, 3), (3, 3))
        self.assertEqual(
            ml_models._expand_span_to_token_bounds("abc", 1, 1), (1, 1))


class TestAggregationStrategyIsNotSimple(unittest.TestCase):
    """Defence in depth: catch the setting that produced the fragments.

    Not the guarantee -- expansion is. But "simple" is what shipped, and a
    revert to it should be a deliberate act that fails a test, not a quiet
    edit.
    """

    def _captured_kwargs(self, accessor_name):
        captured = {}
        reg = ml_models._registry
        original = reg._load

        def fake_load(name, model_id, task, **kwargs):
            captured.update(kwargs)
            captured["_model_id"] = model_id
            captured["_task"] = task
            return None

        reg._load = fake_load
        try:
            getattr(reg, accessor_name)()
        finally:
            reg._load = original
        return captured

    def test_phi_pipeline_does_not_use_simple_aggregation(self):
        kwargs = self._captured_kwargs("ner_phi_pipeline")
        self.assertEqual(kwargs.get("_task"), "ner")
        self.assertNotEqual(
            kwargs.get("aggregation_strategy"), "simple",
            "'simple' does no word-level aggregation, so an identifier split "
            "across subwords stays split and only the confident fragment is "
            "redacted",
        )
        self.assertIn(kwargs.get("aggregation_strategy"),
                      ("first", "max", "average"))


class TestPHIStaysAdditive(_PHIPipelineFixture):
    """Do not regress the deliberate design in _redact_text.

    PHI NER contributes spans but is excluded from the completeness verdict,
    because every phi.* class has a regex floor. If that ever changes the
    comment at the span merge in main.py says so -- this pins the current
    contract so the change has to be deliberate.
    """

    def test_a_missing_phi_model_does_not_make_a_regex_class_incomplete(self):
        reg = ml_models._registry
        reg.ner_phi_pipeline = lambda: None
        out, _counts, status = main._redact_text(
            "MRN: 004512338 admitted 3 days ago", ["phi.mrn"])
        self.assertTrue(
            status["complete"],
            "phi.* has a regex floor; a missing clinical model must not fail "
            "closed on redaction the regex layer actually performed",
        )
        self.assertNotIn("004512338", out)

    def test_every_phi_class_still_has_a_regex_floor(self):
        """The precondition for the line above being safe."""
        for cls in (c for c in main._REDACT_CLASS_MAP if c.startswith("phi.")):
            with self.subTest(cls=cls):
                self.assertTrue(
                    main._REDACT_CLASS_MAP[cls],
                    f"{cls} has no regex patterns, so the clinical model is "
                    f"its ONLY source. PHI spans must then join the "
                    f"completeness calculation in _redact_text -- see the "
                    f"comment at the span merge.",
                )


if __name__ == "__main__":
    unittest.main()
