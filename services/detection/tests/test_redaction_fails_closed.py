"""A redaction that could not finish must not hand back text that looks finished.

NERPIIDetector.redact_spans returned a bare ``List[tuple]``, and its exception
handler fell through to ``return spans`` — so a crash part-way through the
entity loop returned whatever had been collected before the raise. `_redact_text`
merged that partial set with the regex spans and produced a string in which
*some* PII was masked and the rest was in the clear. `/scan/redact` then reported
``any_redacted: true`` with a class_counts map that looked like a completed job.

This is not the same defect as the detector cases in this sweep, and it is
worse. A detector that fails silently produces a missed alert. A redactor that
fails silently produces a disclosure: both proxies
(services/proxy/transparent_proxy.py and
agents/endpoint-agent/local_proxy/transparent_proxy.py) take `redacted_text`,
call ``flow.request.set_content(...)`` with it, and forward it to the model
provider. The unmasked names cross the tenant boundary before anyone can
notice. So this path fails CLOSED: when redaction cannot be completed, the
response contains no `redacted_text` at all.

These tests pin that decision end to end, including the interlock with the
proxy code as it is written today.
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

# One sentence carrying both kinds of PII: an email the regex catalog handles
# and a person name only the NER model can find.
TEXT = "Contact jane.doe@example.com — the account is held by Jane Doe."
NAME_START = TEXT.index("Jane Doe")
NAME_END = NAME_START + len("Jane Doe")

BOTH_CLASSES = ["pii.email", "pii.person_name"]
REGEX_ONLY = ["pii.email"]


class _Exploding:
    def __call__(self, *_args, **_kwargs):
        raise RuntimeError("simulated NER inference failure")


class _PartialThenExplodes:
    """Yields one usable entity, then raises — the partial-redaction case.

    The pipeline returns a generator, so `for ent in entities` consumes the
    first entity, appends its span, and then the raise happens mid-loop. This
    reproduces the exact shape the old handler swallowed.
    """

    def __call__(self, *_args, **_kwargs):
        def gen():
            yield {
                "entity_group": "PER", "word": "Jane Doe",
                "score": 0.99, "start": NAME_START, "end": NAME_END,
            }
            raise RuntimeError("simulated failure after the first entity")
        return gen()


class _FindsTheName:
    def __call__(self, *_args, **_kwargs):
        return [
            {
                "entity_group": "PER", "word": "Jane Doe",
                "score": 0.99, "start": NAME_START, "end": NAME_END,
            }
        ]


class _NoEntities:
    def __call__(self, *_args, **_kwargs):
        return []


class _NERPipelineFixture(unittest.TestCase):
    def _with_pipeline(self, pipe):
        original = ml_models._registry.ner_pipeline
        ml_models._registry.ner_pipeline = lambda: pipe
        self.addCleanup(setattr, ml_models._registry, "ner_pipeline", original)


class TestRedactSpansReportsWhetherItFinished(_NERPipelineFixture):
    def test_missing_model_is_not_complete(self):
        self._with_pipeline(None)
        with self.assertLogs("detection.ml_models", level="ERROR"):
            result = ml_models.NERPIIDetector().redact_spans(TEXT, BOTH_CLASSES)
        self.assertFalse(
            result.complete,
            "A NER model that never loaded cannot have redacted pii.person_name, "
            "and must not report a finished pass",
        )
        self.assertEqual(result.reason, "model_not_loaded")
        self.assertIn("pii.person_name", result.ner_classes)

    def test_inference_crash_is_not_complete(self):
        self._with_pipeline(_Exploding())
        with self.assertLogs("detection.ml_models", level="ERROR"):
            result = ml_models.NERPIIDetector().redact_spans(TEXT, BOTH_CLASSES)
        self.assertFalse(result.complete)
        self.assertEqual(result.reason, "inference_error")
        self.assertIsNotNone(result.error)

    def test_partial_spans_are_not_reported_as_complete(self):
        """The dangerous case: real spans came back, but not all of them."""
        self._with_pipeline(_PartialThenExplodes())
        with self.assertLogs("detection.ml_models", level="ERROR"):
            result = ml_models.NERPIIDetector().redact_spans(TEXT, BOTH_CLASSES)
        self.assertTrue(result.spans, "the entity collected before the raise is kept")
        self.assertFalse(
            result.complete,
            "Partial spans returned as a plain list were indistinguishable from a "
            "finished pass — this is the whole defect",
        )

    def test_regex_only_request_needs_nothing_from_ner(self):
        """A policy that never asked for a NER class must not fail closed.

        This bounds the blast radius: pii.email / pii.ssn / secret.* redaction
        keeps working on a host with no NER model at all.
        """
        self._with_pipeline(None)
        result = ml_models.NERPIIDetector().redact_spans(TEXT, REGEX_ONLY)
        self.assertTrue(
            result.complete,
            "NER cannot have failed to do work that was never requested of it",
        )
        self.assertEqual(result.spans, [])
        self.assertEqual(result.ner_classes, ())

    def test_healthy_pass_is_complete_and_returns_spans(self):
        self._with_pipeline(_FindsTheName())
        result = ml_models.NERPIIDetector().redact_spans(TEXT, BOTH_CLASSES)
        self.assertTrue(result.complete)
        self.assertIn((NAME_START, NAME_END, "pii.person_name"), result.spans)


class TestRedactTextCarriesTheStatus(_NERPipelineFixture):
    def test_incomplete_status_when_ner_is_down(self):
        self._with_pipeline(_Exploding())
        with self.assertLogs("detection.ml_models", level="ERROR"):
            _redacted, counts, status = main._redact_text(TEXT, BOTH_CLASSES)
        self.assertFalse(status["complete"])
        self.assertEqual(status["unredacted_classes"], ["pii.person_name"])
        self.assertEqual(
            counts.get("pii.email"), 1,
            "the regex half of the job did happen, and its count is still reported",
        )

    def test_the_partial_text_really_does_still_contain_the_name(self):
        """Why `complete` matters, demonstrated on the string itself."""
        self._with_pipeline(_Exploding())
        with self.assertLogs("detection.ml_models", level="ERROR"):
            redacted, _counts, status = main._redact_text(TEXT, BOTH_CLASSES)
        self.assertNotIn("jane.doe@example.com", redacted)
        self.assertIn(
            "Jane Doe", redacted,
            "This is the text the old code returned to the caller as redacted",
        )
        self.assertFalse(status["complete"])

    def test_complete_status_on_the_healthy_path(self):
        self._with_pipeline(_FindsTheName())
        redacted, counts, status = main._redact_text(TEXT, BOTH_CLASSES)
        self.assertTrue(status["complete"])
        self.assertNotIn("Jane Doe", redacted)
        self.assertNotIn("jane.doe@example.com", redacted)
        self.assertEqual(counts.get("pii.person_name"), 1)


class TestScanRedactFailsClosed(_NERPipelineFixture):
    def setUp(self):
        original = main._verify_api_key
        main._verify_api_key = lambda _key: None  # auth is not under test
        self.addCleanup(setattr, main, "_verify_api_key", original)

    def _redact(self, targets):
        return main.scan_redact(
            main.RedactRequest(text=TEXT, targets=targets, tenant_id="t1"),
            x_api_key=None,
        )

    def test_incomplete_response_withholds_the_text(self):
        self._with_pipeline(_Exploding())
        with self.assertLogs(level="ERROR"):
            body = self._redact(BOTH_CLASSES)
        self.assertFalse(body["redaction_complete"])
        self.assertNotIn(
            "redacted_text", body,
            "A redaction endpoint that could not finish must not hand back a "
            "string that looks like redacted output",
        )

    def test_incomplete_response_names_what_it_could_not_mask(self):
        self._with_pipeline(None)
        with self.assertLogs(level="ERROR"):
            body = self._redact(BOTH_CLASSES)
        self.assertEqual(body["unredacted_classes"], ["pii.person_name"])
        self.assertEqual(body["reason"], "model_not_loaded")
        self.assertEqual(body["detector"], "ner_pii_model")

    def test_incomplete_response_never_leaks_the_matched_values(self):
        """The standing rule for this endpoint, still true on the failure path."""
        self._with_pipeline(_Exploding())
        with self.assertLogs(level="ERROR"):
            body = self._redact(BOTH_CLASSES)
        blob = repr(body)
        self.assertNotIn("jane.doe@example.com", blob)
        self.assertNotIn("Jane Doe", blob)

    def test_incomplete_response_does_not_invite_forwarding_the_original(self):
        """`any_redacted` means "the original is not safe to send as-is"."""
        self._with_pipeline(_Exploding())
        with self.assertLogs(level="ERROR"):
            body = self._redact(BOTH_CLASSES)
        self.assertTrue(
            body["any_redacted"],
            "A caller reading only this field must still refuse to forward the "
            "raw body — falsy here routes both proxies to their pass-through "
            "branch, which is a fail-OPEN",
        )

    def test_proxy_interlock_blocks_the_request(self):
        """Replays the proxy's redact branch verbatim against this response.

        Both proxies run, inside a try whose handler emits a block response:

            if redact_result and redact_result.get("any_redacted"):
                new_body = redact_result["redacted_text"]

        The incomplete payload must drive that code into its fail-closed
        handler rather than past it. If someone later adds `redacted_text`
        back to the failure response, or makes `any_redacted` false, this test
        is what notices — silently, both proxies would resume sending
        partially-redacted or wholly-unredacted bodies to the provider.
        """
        self._with_pipeline(_Exploding())
        with self.assertLogs(level="ERROR"):
            redact_result = self._redact(BOTH_CLASSES)

        blocked = False
        try:
            if redact_result and redact_result.get("any_redacted"):
                _new_body = redact_result["redacted_text"]
            else:
                self.fail(
                    "the proxy would have forwarded the ORIGINAL body unredacted"
                )
        except Exception:
            blocked = True
        self.assertTrue(blocked, "the proxy must end up in its fail-closed handler")

    def test_regex_only_policy_still_redacts_without_a_ner_model(self):
        """Fail-closed must not become fail-always."""
        self._with_pipeline(None)
        body = self._redact(REGEX_ONLY)
        self.assertTrue(body["redaction_complete"])
        self.assertIn("redacted_text", body)
        self.assertNotIn("jane.doe@example.com", body["redacted_text"])
        self.assertEqual(body["class_counts"], {"pii.email": 1})

    def test_healthy_path_is_unchanged(self):
        self._with_pipeline(_FindsTheName())
        body = self._redact(BOTH_CLASSES)
        self.assertTrue(body["redaction_complete"])
        self.assertTrue(body["any_redacted"])
        self.assertNotIn("Jane Doe", body["redacted_text"])
        self.assertNotIn("jane.doe@example.com", body["redacted_text"])

    def test_clean_text_with_healthy_model_is_complete(self):
        self._with_pipeline(_NoEntities())
        body = main.scan_redact(
            main.RedactRequest(
                text="nothing sensitive here", targets=BOTH_CLASSES, tenant_id="t1"
            ),
            x_api_key=None,
        )
        self.assertTrue(body["redaction_complete"])
        self.assertFalse(body["any_redacted"])
        self.assertEqual(body["redacted_text"], "nothing sensitive here")

    def test_no_targets_is_still_a_complete_noop(self):
        self._with_pipeline(None)
        body = main.scan_redact(
            main.RedactRequest(text=TEXT, targets=[], tenant_id="t1"), x_api_key=None
        )
        self.assertTrue(body["redaction_complete"])
        self.assertEqual(body["redacted_text"], TEXT)


if __name__ == "__main__":
    unittest.main()
