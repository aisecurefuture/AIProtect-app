"""A detector the profile never asked for is not a detector that broke.

THE DEFECT THIS PREVENTS
========================
The cheap consumer tier drops two models (bart-large-mnli, obi/deid_roberta_i2b2)
to get from ~5.24 GiB / ~3.58 s per scan down to something a free tier can
afford. The obvious way to build that -- stop loading the models -- is wrong,
and wrong in the direction this codebase keeps getting hurt by:

``_scan_output_safety`` emits a ``detector_unavailable`` finding when the
zero-shot pipeline is missing. Simply removing the model would therefore make
EVERY consumer scan report ``scan_complete: false``, forever. Three losses at
once: a permanent alarm nobody can action, a `scan_complete` flag that stops
distinguishing real faults from the configuration, and a result cache that
refuses every entry because nothing is ever complete.

So a profile declines to ASK, and says so. Three states, kept apart:

    ran            -> a verdict
    FAILED         -> detector_unavailable, scan_complete false. A fault.
    not configured -> absent from the scan, named in checks_skipped_by_profile.

The properties pinned here are that the third state exists, that it is visible
on every response, and that it never renders as either of the other two.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent          # services/detection
REPO = ROOT.parent.parent                              # repo root
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(REPO / "libs" / "cyberarmor-core"))

_STACK = ("detection_main", "ml_models", "detection_profile", "scan_cache", "rate_limit")


def _load_stack(**env):
    """Import the detection stack fresh under `env`.

    The profile is read at import time -- deliberately, so a running process
    cannot drift into a different serving shape -- which means a test that
    wants a different profile has to rebuild the modules that closed over it.
    """
    for name in _STACK:
        sys.modules.pop(name, None)
    with mock.patch.dict(os.environ, env, clear=False):
        profile = importlib.import_module("detection_profile")
        ml = importlib.import_module("ml_models")
        spec = importlib.util.spec_from_file_location("detection_main", ROOT / "main.py")
        main = importlib.util.module_from_spec(spec)
        sys.modules["detection_main"] = main
        spec.loader.exec_module(main)  # type: ignore[union-attr]
    return profile, ml, main


class ProfileIsNotFailure(unittest.TestCase):
    def tearDown(self) -> None:
        for name in _STACK:
            sys.modules.pop(name, None)

    # -- the models the profile drops --------------------------------------

    def test_consumer_profile_drops_the_two_expensive_models(self):
        _, ml, _ = _load_stack(CYBERARMOR_DETECTION_PROFILE="consumer")
        self.assertNotIn("zero_shot", ml.MODEL_IDS)   # bart-large-mnli, ~1.6 GB
        self.assertNotIn("ner_phi", ml.MODEL_IDS)     # deid_roberta, ~1.4 GB
        # What remains is exactly the consumer feature set.
        self.assertEqual(
            set(ml.MODEL_IDS), {"prompt_injection", "ner_pii", "toxicity"}
        )

    def test_full_profile_is_unchanged(self):
        """The B2B deployment must not notice this change exists."""
        _, ml, _ = _load_stack(CYBERARMOR_DETECTION_PROFILE="full")
        self.assertEqual(
            set(ml.MODEL_IDS),
            {"prompt_injection", "ner_pii", "ner_phi", "toxicity", "zero_shot"},
        )
        self.assertEqual(ml.MODELS_DISABLED_BY_PROFILE, {})

    def test_default_profile_is_full(self):
        """No env var set -> the pre-existing behaviour, not the cheap one.

        A deployment that silently got the narrow profile would be missing
        coverage it believes it has, which is worse than an expensive bill.
        """
        env = {k: v for k, v in os.environ.items()
               if k != "CYBERARMOR_DETECTION_PROFILE"}
        with mock.patch.dict(os.environ, env, clear=True):
            profile, ml, _ = _load_stack()
        self.assertEqual(profile.PROFILE, "full")
        self.assertEqual(profile.skipped_detectors(), [])

    def test_an_unknown_profile_refuses_to_start(self):
        """Not a silent fallback. A typo'd profile serving the expensive config
        is a bill; serving the cheap one is missing coverage. Neither should be
        discoverable only from a graph."""
        for name in _STACK:
            sys.modules.pop(name, None)
        with mock.patch.dict(
            os.environ, {"CYBERARMOR_DETECTION_PROFILE": "conusmer"}, clear=False
        ):
            with self.assertRaises(ValueError):
                importlib.import_module("detection_profile")

    # -- /ready keeps the two facts apart ----------------------------------

    def test_ready_does_not_call_a_disabled_model_degraded(self):
        """THE CORE PROPERTY.

        `degraded_models` means "expected but missing" -- someone should look.
        A model the profile never declared must not appear there, or the
        consumer deployment pages permanently for its own configuration.
        """
        _, _, main = _load_stack(CYBERARMOR_DETECTION_PROFILE="consumer")
        body = main.ready()
        self.assertNotIn("zero_shot", body["degraded_models"])
        self.assertNotIn("ner_phi", body["degraded_models"])

    def test_ready_still_names_what_the_profile_removed(self):
        """Not reported as broken, but not vanished either -- an operator must
        be able to see that output-safety is not being run at all."""
        _, _, main = _load_stack(CYBERARMOR_DETECTION_PROFILE="consumer")
        body = main.ready()
        self.assertEqual(body["profile"], "consumer")
        self.assertIn("output_safety", body["detectors_skipped_by_profile"])
        self.assertIn("zero_shot", body["models_disabled_by_profile"])
        self.assertIn("ner_phi", body["models_disabled_by_profile"])

    # -- every scan response carries the fact ------------------------------

    def test_every_scan_names_the_checks_it_did_not_run(self):
        _, _, main = _load_stack(CYBERARMOR_DETECTION_PROFILE="consumer")
        payload = main.GenericScanRequest(content="hello there")
        body = main.scan(payload, x_api_key=main.DETECTION_API_SECRET)
        self.assertEqual(body["profile"], "consumer")
        self.assertIn("output_safety", body["checks_skipped_by_profile"])

    def test_the_key_is_present_even_when_nothing_is_skipped(self):
        """An always-present key is readable. A key that appears only in the
        narrow configuration is one a caller meets for the first time in
        production."""
        _, _, main = _load_stack(CYBERARMOR_DETECTION_PROFILE="full")
        payload = main.GenericScanRequest(content="hello there")
        body = main.scan(payload, x_api_key=main.DETECTION_API_SECRET)
        self.assertEqual(body["checks_skipped_by_profile"], [])

    def test_output_safety_route_refuses_rather_than_reporting_clean(self):
        """501, never 200-with-no-findings.

        The single-detector routes bypass the findings list, so they are the
        one path where "I did not run" could be laundered into "I found
        nothing". It must fail loudly instead.
        """
        from fastapi import HTTPException

        _, _, main = _load_stack(CYBERARMOR_DETECTION_PROFILE="consumer")
        with self.assertRaises(HTTPException) as ctx:
            main.scan_output(
                main.TextRequest(text="rm -rf /"), x_api_key=main.DETECTION_API_SECRET
            )
        self.assertEqual(ctx.exception.status_code, 501)
        self.assertEqual(
            ctx.exception.detail["reason"], "detector_not_enabled_in_profile"
        )


if __name__ == "__main__":
    unittest.main()
