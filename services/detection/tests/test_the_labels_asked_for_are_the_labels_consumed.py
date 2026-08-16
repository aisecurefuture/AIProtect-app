"""The zero-shot detector must not be asked to score a label nobody reads.

MEASURED ON THE BOX, 2026-08-07, per detector, warm median at a 2,000-char
body, against the local proxy's 5.0s INSPECTION_TIMEOUT:

    output-safety (bart-large-mnli)   2.72s     <- 75% of the whole scan
    WHOLE /scan                       3.58s

`_ZERO_SHOT_LABELS` declared FIVE candidate labels. HuggingFace's zero-shot
pipeline runs one NLI forward pass per candidate, so all five were computed.
Then:

  * "safe benign request" was discarded inside `detect()` by its own guard;
  * "prompt injection attack" and "jailbreak attempt" were dropped by the only
    consumer, `_scan_output_safety`, whose allow-list was a SECOND literal
    holding two labels.

Three of five forward passes through a 406M-parameter model, computed and
thrown away, on every scan, inside a budget that fails closed when it is
missed. Nothing bound the two literals together, and they had drifted.

WHAT THESE TESTS PIN, and why each one is here rather than being obvious:

  1. The labels asked for ARE the labels consumed. This is the actual
     invariant. It cannot be restored by inspection later because the cost of
     violating it is invisible -- the extra labels produce correct, ignored
     answers, and the only symptom is seconds.

  2. multi_label=True is still passed. The saving is only free while it holds.
     It arrives as a **kwargs key and HuggingFace silently drops kwargs it
     does not recognise; `transformers` is UNPINNED in the detection
     Dockerfile and production builds its images on the box. If it were ever
     ignored, scoring becomes one softmax across the candidate set -- and
     since the cut removed the "safe benign request" absorber, that mass would
     redistribute onto the two surviving threat labels and a fixed 0.60
     threshold would start flagging ordinary business content. This service
     has already shipped that failure once ("Tea is a drink." -> action=block,
     2026-08-06). The cut is what makes a future multi_label regression
     dangerous rather than harmless, so the flag gets a test.

  3. The benign-label guard survives even though no candidate can produce it.
     A pipeline may answer whatever it likes, and this repo's own test double
     does exactly that.
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


class _Recorder:
    """A pipeline that answers nothing and remembers how it was called."""

    def __init__(self, labels=None, scores=None):
        self.calls = []
        self._labels = labels or []
        self._scores = scores or []

    def __call__(self, *args, **kwargs):
        self.calls.append({"args": args, "kwargs": kwargs})
        return {"labels": list(self._labels), "scores": list(self._scores)}


class _Pipe:
    """Swap the registry's zero-shot pipeline for the duration of a test."""

    def __init__(self, pipe):
        self.pipe = pipe

    def __enter__(self):
        self._orig = ml_models._registry.zero_shot_pipeline
        ml_models._registry.zero_shot_pipeline = lambda: self.pipe
        return self.pipe

    def __exit__(self, *exc):
        ml_models._registry.zero_shot_pipeline = self._orig
        return False


#: Labels to offer the consumer, at a confidence nothing could ignore. The
#: union of what is asked for today plus every label the old five-entry list
#: carried, plus one that was never declared anywhere.
_PROBE_LABELS = sorted(
    set(ml_models.ZERO_SHOT_THREAT_LABELS)
    | {"prompt injection attack", "jailbreak attempt",
       ml_models.ZERO_SHOT_BENIGN_LABEL, "a label nobody ever declared"}
)


def _consumed_labels():
    """What `_scan_output_safety` actually keeps -- OBSERVED, not read.

    The first version of this returned `set(main.ZERO_SHOT_THREAT_LABELS)`:
    the constant re-exported through main, not the filter the function
    applies. That made both direction tests tautologies -- asked and consumed
    were literally the same object, so neither could ever differ -- and the
    sabotage run proved it: restoring the original defect, a hand-written
    literal in `_scan_output_safety` carrying a label the classifier is never
    asked about, failed NOTHING. A test that keeps its own copy of the mapping
    is a THIRD implementation of it, which is the defect this file exists to
    prevent, written into the thing meant to prevent it.

    So: hand the consumer every plausible label at 0.99 and see which ones
    come back out as findings. That is the consumed set, by definition, and it
    cannot agree with the ask by construction.
    """
    import main
    rogue = _Recorder(labels=list(_PROBE_LABELS),
                      scores=[0.99] * len(_PROBE_LABELS))
    with _Pipe(rogue):
        findings = main._scan_output_safety("nothing regex-worthy here")
    # Regex and code-generation findings share the `dangerous_output` type but
    # carry no `label`; only the classifier's survive this.
    return {f["label"] for f in findings if isinstance(f, dict) and f.get("label")}


class TheAskMatchesTheConsumption(unittest.TestCase):

    def test_every_label_scored_is_a_label_something_reads(self):
        with _Pipe(_Recorder()) as pipe:
            ml_models.ZeroShotThreatDetector().detect("anything")
        asked = list(pipe.calls[0]["kwargs"]["candidate_labels"])
        orphans = sorted(set(asked) - _consumed_labels())
        self.assertEqual(
            orphans, [],
            f"{len(orphans)} label(s) are scored by a 406M-parameter model and "
            f"then discarded by the only consumer: {orphans}. Each one is a "
            f"full forward pass inside a 5.0s fail-closed budget.")

    def test_every_label_read_is_a_label_actually_scored(self):
        """The other direction. A consumer waiting on a label the detector is
        never asked about is a detection that silently never fires."""
        with _Pipe(_Recorder()) as pipe:
            ml_models.ZeroShotThreatDetector().detect("anything")
        asked = set(pipe.calls[0]["kwargs"]["candidate_labels"])
        unfillable = sorted(_consumed_labels() - asked)
        self.assertEqual(
            unfillable, [],
            f"the output-safety filter waits for {unfillable}, which the "
            f"classifier is never asked to score -- those threats can never "
            f"be reported, at any confidence")

    def test_the_list_is_not_empty(self):
        """Guards the degenerate way both assertions above pass at once."""
        self.assertTrue(ml_models.ZERO_SHOT_THREAT_LABELS)
        self.assertTrue(_consumed_labels())


class TheIndependencePreconditionHolds(unittest.TestCase):

    def test_multi_label_is_still_requested(self):
        with _Pipe(_Recorder()) as pipe:
            ml_models.ZeroShotThreatDetector().detect("anything")
        self.assertIs(
            pipe.calls[0]["kwargs"].get("multi_label"), True,
            "Without multi_label=True the candidate labels are scored by ONE "
            "softmax across the set. The cut removed the 'safe benign request' "
            "absorber, so benign probability mass would redistribute onto the "
            "two threat labels and a fixed 0.60 threshold would start blocking "
            "ordinary business content.")

    def test_the_benign_absorber_is_no_longer_a_candidate(self):
        """It cost a forward pass and could never produce a finding."""
        with _Pipe(_Recorder()) as pipe:
            ml_models.ZeroShotThreatDetector().detect("anything")
        self.assertNotIn(ml_models.ZERO_SHOT_BENIGN_LABEL,
                         pipe.calls[0]["kwargs"]["candidate_labels"])

    def test_a_pipeline_that_ignores_the_ask_is_still_filtered(self):
        """The guard that makes the removal safe. A pipeline may answer with
        labels it was not asked about -- this repo's own _Benign double does
        -- and a high-scoring benign label must not become a finding."""
        rogue = _Recorder(labels=[ml_models.ZERO_SHOT_BENIGN_LABEL], scores=[0.97])
        with _Pipe(rogue):
            findings = ml_models.ZeroShotThreatDetector().detect("what time is standup")
        self.assertEqual(
            findings, [],
            "a 0.97 'safe benign request' became a threat finding -- the guard "
            "in detect() was removed as dead code")


class TheCostIsWhatWasClaimed(unittest.TestCase):

    def test_the_model_is_asked_for_exactly_two_forward_passes(self):
        """The saving is a forward-pass count, so count them.

        Not a wall-clock assertion -- that belongs on the box. This pins the
        thing the wall-clock measurement was of."""
        with _Pipe(_Recorder()) as pipe:
            ml_models.ZeroShotThreatDetector().detect("anything")
        self.assertEqual(len(pipe.calls[0]["kwargs"]["candidate_labels"]), 2)


if __name__ == "__main__":
    unittest.main()
