"""Every rule in every preset must fire on input it is supposed to catch.

THE HAZARD
==========
The policy engine does not validate field names. It resolves `content.foo` by
looking up "foo" in whatever dict the caller passed, and never consults
`shared/policy-fields.json` -- that registry drives the policy-builder UI, not
enforcement. Proven in `spikes/spike_policy_engine.py` step 7.

So a typo in a preset rule does not raise, does not warn, and does not appear
in the engine's `problems` list. It silently never matches. On a `block` rule
that is a hole in protection that looks exactly like a configured control --
the dishonest-health defect class in its purest form, and the reason this file
exists.

THE RULE FOR ANYONE ADDING A PRESET RULE
========================================
Add its known-positive fixture here in the same commit. A rule with no fixture
is a rule nobody has ever seen work.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

API = Path(__file__).resolve().parent.parent
REPO = API.parent.parent
sys.path.insert(0, str(API))
sys.path.insert(0, str(REPO / "libs" / "policy-engine"))

import presets  # noqa: E402

AI = {"domain": "openai.com", "url": "https://chatgpt.com/c/1"}
ELSEWHERE = {"domain": "example.com", "url": "https://example.com/"}

#: rule id -> (preset it lives in, request, content) that MUST trigger it.
#: Every id in every preset has to appear here; the coverage test below fails
#: if one does not.
FIXTURES = {
    "secrets-to-ai": (presets.STANDARD, AI, {"has_secrets": True}),
    "pii-to-ai": (presets.STANDARD, AI, {"has_pii": True}),
    "pii-to-ai-strict": (presets.STRICT, AI, {"has_pii": True}),
    "malicious-url": (presets.STANDARD, ELSEWHERE, {"malicious": True}),
    "prompt-injection": (presets.STANDARD, ELSEWHERE, {"prompt_injection": True}),
    "prompt-injection-strict": (
        presets.STRICT, ELSEWHERE, {"prompt_injection": True},
    ),
    "kid-unsafe": (presets.KIDS, ELSEWHERE, {"kid_unsafe": True}),
    "monitor-rest": (presets.STANDARD, ELSEWHERE, {}),
}


class EveryRuleHasBeenSeenToFire(unittest.TestCase):
    def test_every_rule_in_every_preset_has_a_fixture(self):
        """Coverage first: a rule with no fixture is untested by definition,
        and this is the assertion that makes forgetting one impossible."""
        for preset in presets.PRESET_NAMES:
            for rid in presets.rule_ids(preset):
                with self.subTest(preset=preset, rule=rid):
                    self.assertIn(
                        rid, FIXTURES,
                        f"{rid} has no known-positive fixture. The engine does "
                        f"not validate field names, so an unfired rule is "
                        f"indistinguishable from a typo.",
                    )

    def test_each_rule_fires_on_its_fixture(self):
        for rid, (preset, request, content) in FIXTURES.items():
            with self.subTest(rule=rid):
                out = presets.evaluate(preset, request=request, content=content)
                self.assertEqual(
                    out["matched"], rid,
                    f"{rid} did not fire on input built to trigger it "
                    f"(matched {out['matched']!r} instead). Check the field "
                    f"names -- the engine will not tell you they are wrong.",
                )

    def test_a_typo_would_have_been_caught(self):
        """Demonstrates the failure this file prevents, so the mechanism is
        visible rather than asserted."""
        typo = [{
            "id": "typo", "name": "Block secrets (misspelled field)",
            "enabled": True, "priority": 10, "action": "block",
            "conditions": {"operator": "AND", "rules": [
                {"field": "content.has_secretz", "operator": "equals",
                 "value": True},
            ]},
        }]
        from policy_engine import EvaluationContext, PolicyEngine
        problems: list = []
        result = PolicyEngine().evaluate_first_match(
            typo, EvaluationContext(request=AI, content={"has_secrets": True}),
            problems,
        )
        self.assertIsNone(result, "the typo'd rule matched, which it should not")
        self.assertEqual(problems, [], "the engine reported nothing -- as warned")


class ThePresetsDifferWhereTheyShould(unittest.TestCase):
    def test_standard_warns_on_pii_and_strict_blocks(self):
        content = {"has_pii": True}
        self.assertEqual(
            presets.evaluate(presets.STANDARD, request=AI, content=content)["action"],
            "warn",
        )
        self.assertEqual(
            presets.evaluate(presets.STRICT, request=AI, content=content)["action"],
            "block",
        )

    def test_secrets_are_blocked_on_every_preset(self):
        """The one rule with no configuration in which it should be softer."""
        for preset in presets.PRESET_NAMES:
            with self.subTest(preset=preset):
                out = presets.evaluate(
                    preset, request=AI, content={"has_secrets": True}
                )
                self.assertEqual(out["action"], "block")

    def test_kids_blocks_what_the_others_never_see(self):
        content = {"kid_unsafe": True}
        self.assertEqual(
            presets.evaluate(presets.KIDS, request=ELSEWHERE, content=content)["action"],
            "block",
        )
        # Standard has no such rule, so it falls through to monitor.
        self.assertEqual(
            presets.evaluate(
                presets.STANDARD, request=ELSEWHERE, content=content
            )["action"],
            "monitor",
        )

    def test_ordinary_browsing_is_not_blocked_on_any_preset(self):
        """The false-positive direction. A consumer product that blocks normal
        pages gets uninstalled faster than one that misses a threat."""
        for preset in presets.PRESET_NAMES:
            with self.subTest(preset=preset):
                out = presets.evaluate(
                    preset, request=ELSEWHERE,
                    content={"has_pii": False, "has_secrets": False},
                )
                self.assertEqual(out["action"], "monitor")

    def test_pii_to_a_normal_site_is_not_flagged(self):
        """The rule is about AI services specifically. Typing your address
        into a shopping site is not an event."""
        out = presets.evaluate(
            presets.STANDARD, request=ELSEWHERE, content={"has_pii": True}
        )
        self.assertEqual(out["action"], "monitor")

    def test_an_unknown_preset_is_refused(self):
        with self.assertRaises(KeyError):
            presets.evaluate("paranoid", request=AI, content={})


if __name__ == "__main__":
    unittest.main()
