"""Redaction must cover the text it says it covered.

THE DEFECT. `NERPIIDetector.redact_spans` ran the NER model over
``text[:MAX_NER_INPUT_CHARS]`` -- 2,048 characters -- and then returned
``complete=True`` unconditionally. Everything past that offset was never
looked at.

WHY THAT IS A DATA-LOSS BUG AND NOT A TUNING ONE. This is the redaction path,
and `redact_spans`'s own docstring says what that means:

    "A detector that misses something produces a missed alert. A redactor that
    misses something produces *text the caller believes is safe to send
    onward* -- and `_redact_text`'s output is set as the outbound request body
    by the proxy, so it leaves the tenant boundary and reaches an external
    model provider."

So a prompt with a customer's name at character 3,000 was forwarded to OpenAI
in the clear, with ``redaction_complete: true`` in the response and a
class_counts telemetry record showing the job done. The file reasons carefully
about `complete` for inference failures and for a missing model; truncation was
simply never considered.

WHY THE FIX IS WINDOWING RATHER THAN JUST REPORTING IT HONESTLY. /scan/redact
FAILS CLOSED on ``complete=False`` -- it returns no ``redacted_text`` at all.
Reporting truncation without fixing it would therefore refuse to redact any
prompt over 2,048 characters, which is most real prompts: a silent leak traded
for a dead feature. The model has to actually see the whole body.

The 2,048 cap is not arbitrary -- it is roughly the model's token window -- so
the text is processed in overlapping windows and the entity offsets are mapped
back to the full text. The overlap exists because an entity sitting across a
window boundary would otherwise be seen by neither pass.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve()
_SERVICE = _HERE.parents[1]
_REPO = _HERE.parents[3]
sys.path.insert(0, str(_SERVICE))
sys.path.insert(0, str(_REPO / "libs" / "cyberarmor-core"))

import ml_models  # noqa: E402

FILLER = "The quarterly review covered migration timelines and vendor costs. "
NAME = "Marguerite Delacroix-Whitfield"


class _FakeNER:
    """Finds NAME wherever it appears in the text it is GIVEN.

    Deliberately honest about its own window: it reports offsets relative to
    the string it received, exactly as a real HuggingFace pipeline does. That
    is what makes the offset mapping testable -- a fake that returned absolute
    offsets would hide the bug this file is about.
    """

    def __init__(self):
        self.calls = []

    def __call__(self, text, *a, **k):
        self.calls.append(text)
        out = []
        start = text.find(NAME)
        while start != -1:
            out.append({"entity_group": "PER", "score": 0.99,
                        "start": start, "end": start + len(NAME)})
            start = text.find(NAME, start + 1)
        return out


class _Pipe:
    def __init__(self, case, pipe):
        self.pipe = pipe

    def __enter__(self):
        self._orig = ml_models._registry.ner_pipeline
        ml_models._registry.ner_pipeline = lambda: self.pipe
        return self.pipe

    def __exit__(self, *exc):
        ml_models._registry.ner_pipeline = self._orig
        return False


def _text_with_name_at(offset: int) -> str:
    """Filler with NAME planted at roughly `offset` characters in.

    The separating spaces are not cosmetic. Slicing the filler at an arbitrary
    offset lands mid-word, and _expand_span_to_token_bounds -- correctly --
    grows a span outward to whole-token boundaries, so a name flush against
    "...and" comes back as "andMarguerite Delacroix-Whitfield". That is the
    redactor doing its job on a string no real prompt contains, and asserting
    against it would be testing the fixture.
    """
    head = (FILLER * (offset // len(FILLER) + 1))[:offset].rstrip() + " "
    return head + NAME + " " + FILLER * 3


class RedactionSeesThePastOfTheFirstWindow(unittest.TestCase):

    def test_a_name_beyond_the_window_is_still_found(self):
        """THE BUG, stated as the case that leaked: a name at character 3,000.

        MAX_NER_INPUT_CHARS is 2,048, so this entity lived entirely past the
        only text the model was ever shown.
        """
        text = _text_with_name_at(3000)
        with _Pipe(self, _FakeNER()):
            result = ml_models.NERPIIDetector().redact_spans(text, ["pii.person_name"])
        found = [s for s in result.spans if text[s[0]:s[1]] == NAME]
        self.assertTrue(
            found,
            f"a person name at offset 3000 of a {len(text)}-character body was "
            f"not redacted. It would have been forwarded to the model provider "
            f"in the clear, with redaction_complete: true")

    def test_the_span_offsets_point_at_the_name_in_the_FULL_text(self):
        """Windowed offsets are relative to the window. If they are not mapped
        back, redaction masks the wrong characters -- which is worse than
        missing them, because it corrupts the prompt AND leaks the name."""
        text = _text_with_name_at(3000)
        with _Pipe(self, _FakeNER()):
            result = ml_models.NERPIIDetector().redact_spans(text, ["pii.person_name"])
        for start, end, _cls in result.spans:
            self.assertEqual(
                text[start:end], NAME,
                f"span ({start},{end}) points at {text[start:end]!r}, not the "
                f"name -- window offsets were not mapped back to the full text")

    def test_every_occurrence_across_many_windows_is_found(self):
        text = (_text_with_name_at(500) + _text_with_name_at(3000)
                + _text_with_name_at(6000))
        with _Pipe(self, _FakeNER()):
            result = ml_models.NERPIIDetector().redact_spans(text, ["pii.person_name"])
        hits = [s for s in result.spans if text[s[0]:s[1]] == NAME]
        self.assertGreaterEqual(
            len(hits), 3,
            f"only {len(hits)} of 3 planted names were found across a "
            f"{len(text)}-character body")

    def test_a_name_straddling_a_window_boundary_is_found(self):
        """The reason the windows overlap. An entity split across the seam is
        invisible to both passes without it."""
        boundary = ml_models.MAX_NER_INPUT_CHARS
        text = _text_with_name_at(boundary - len(NAME) // 2)
        with _Pipe(self, _FakeNER()):
            result = ml_models.NERPIIDetector().redact_spans(text, ["pii.person_name"])
        self.assertTrue(
            [s for s in result.spans if text[s[0]:s[1]] == NAME],
            "a name lying across the window boundary was seen by neither pass")

    def test_the_model_is_actually_shown_more_than_one_window(self):
        text = _text_with_name_at(6000)
        fake = _FakeNER()
        with _Pipe(self, fake):
            ml_models.NERPIIDetector().redact_spans(text, ["pii.person_name"])
        self.assertGreater(
            len(fake.calls), 1,
            "the whole body went through in one call -- either the cap is gone "
            "(and the model is being handed more than its token window) or the "
            "text was truncated again")

    def test_short_text_is_still_one_pass(self):
        """Windowing must not cost extra inference on ordinary prompts."""
        fake = _FakeNER()
        with _Pipe(self, fake):
            ml_models.NERPIIDetector().redact_spans("Hello " + NAME, ["pii.person_name"])
        self.assertEqual(len(fake.calls), 1)


class ItStillSaysWhenItDidNotFinish(unittest.TestCase):

    def test_a_completed_pass_reports_complete(self):
        with _Pipe(self, _FakeNER()):
            result = ml_models.NERPIIDetector().redact_spans(
                _text_with_name_at(3000), ["pii.person_name"])
        self.assertTrue(result.complete)

    def test_a_body_beyond_the_window_budget_is_not_reported_complete(self):
        """There has to be a bound -- a 10 MB body is 5,000 inference passes --
        and hitting it must be reported, not silently truncated. That is the
        original defect wearing a larger number."""
        cap = ml_models.MAX_NER_WINDOWS
        text = _text_with_name_at(cap * ml_models.MAX_NER_INPUT_CHARS + 5000)
        with _Pipe(self, _FakeNER()):
            result = ml_models.NERPIIDetector().redact_spans(text, ["pii.person_name"])
        self.assertFalse(
            result.complete,
            "a body too large to process fully was reported as completely "
            "redacted -- /scan/redact would return redacted_text and the "
            "unscanned tail would cross the tenant boundary")
        self.assertEqual(result.reason, "input_too_long")

    def test_an_inference_error_still_reports_incomplete(self):
        """The pre-existing guarantee, still held."""
        class _Boom:
            def __call__(self, *a, **k):
                raise RuntimeError("cuda is on fire")
        with _Pipe(self, _Boom()):
            result = ml_models.NERPIIDetector().redact_spans(
                _text_with_name_at(3000), ["pii.person_name"])
        self.assertFalse(result.complete)
        self.assertEqual(result.reason, "inference_error")


if __name__ == "__main__":
    unittest.main()
