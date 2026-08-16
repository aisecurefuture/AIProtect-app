"""A consumer verdict must not claim more than the gate actually did.

THE DEFECT THIS PREVENTS
========================
`depth=fast` on a URL nobody has seen before is a REPUTATION-ONLY answer:
no one fetched the page. Rendering that as a green "Safe" tick is the same
defect this codebase keeps paying for -- a check that did not run presented as
a check that ran and found nothing -- except here it is presented to a person
who is deciding whether to type their password into the page.

So `safe` is a bounded claim: "nothing we checked came back bad", plus a list
of what those checks were. The sentence a person reads changes depending on
whether anybody actually opened the page.

THE MAPPING ALSO HAS TO BE TOTAL
================================
Six enforcement actions collapse into three consumer states. An action with no
mapping must never fall through to `safe` -- an unmapped action is an unknown
verdict, and unknown is not good news.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # services/url-trust-gate
REPO = ROOT.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(REPO / "libs" / "cyberarmor-core"))

import consumer_verdict as cv  # noqa: E402


class _Scores:
    """Stand-in for TrustGateScores; only attribute access is used."""

    def __init__(self, **kw):
        for field in (
            "phishing", "malware", "prompt_injection", "promptware",
            "data_exfil", "credential_harvest", "brand_impersonation",
            "overall_risk",
        ):
            setattr(self, field, float(kw.pop(field, 0.0)))
        assert not kw, f"unknown score fields: {sorted(kw)}"


def _summarise(action="allow", *, depth="standard", cache_hit=False,
               crawled=True, detonated=False, **scores):
    return cv.summarise(
        action=action, scores=_Scores(**scores), depth=depth,
        cache_hit=cache_hit, crawled=crawled, detonated=detonated,
    )


class TheMappingIsTotal(unittest.TestCase):
    def test_every_enforcement_action_has_a_verdict(self):
        for action in ("allow", "warn", "redact", "sandbox", "block",
                       "isolate", "require_approval"):
            with self.subTest(action=action):
                self.assertIn(
                    _summarise(action)["verdict"], (cv.SAFE, cv.CAUTION, cv.BLOCKED)
                )

    def test_an_unknown_action_is_not_safe(self):
        """Unknown is not good news. A new action added upstream must not
        arrive in front of a person as a green tick."""
        self.assertEqual(_summarise("some_future_action")["verdict"], cv.CAUTION)

    def test_redact_is_caution_not_safe(self):
        """Redaction means the page carried something that had to be stripped.
        'We cleaned this up for you' is a warning, not an all-clear."""
        self.assertEqual(_summarise("redact")["verdict"], cv.CAUTION)

    def test_sandbox_and_isolate_are_blocked(self):
        """There is no sandboxed browser on a phone to hand the page to, so
        the honest consumer rendering of 'only open this in a sandbox' is
        'do not open this'."""
        self.assertEqual(_summarise("sandbox")["verdict"], cv.BLOCKED)
        self.assertEqual(_summarise("isolate")["verdict"], cv.BLOCKED)


class SafeIsABoundedClaim(unittest.TestCase):
    def test_an_unfetched_page_does_not_claim_we_checked_it(self):
        """THE CORE PROPERTY."""
        out = _summarise("allow", depth="fast", crawled=False, cache_hit=False)
        self.assertEqual(out["verdict"], cv.SAFE)
        self.assertFalse(out["page_was_read"])
        self.assertIn("page_not_fetched", out["checks_performed"])
        self.assertIn("have not opened the page", out["reason"])

    def test_a_fetched_page_says_so(self):
        out = _summarise("allow", crawled=True)
        self.assertTrue(out["page_was_read"])
        self.assertIn("page_fetched_and_scanned", out["checks_performed"])
        self.assertIn("checked this page", out["reason"])

    def test_the_two_safe_sentences_are_different(self):
        """If they were the same string the distinction would be unreadable to
        the person it exists for."""
        unread = _summarise("allow", depth="fast", crawled=False)["reason"]
        read = _summarise("allow", crawled=True)["reason"]
        self.assertNotEqual(unread, read)

    def test_checks_performed_is_always_present(self):
        for action in ("allow", "warn", "block"):
            with self.subTest(action=action):
                self.assertTrue(_summarise(action)["checks_performed"])

    def test_a_sandbox_run_counts_as_reading_the_page(self):
        out = _summarise("allow", detonated=True, crawled=False)
        self.assertTrue(out["page_was_read"])
        self.assertIn("opened_in_sandbox", out["checks_performed"])


class TheReasonIsForAPerson(unittest.TestCase):
    def test_the_worst_true_signal_wins(self):
        """Both fire; the person should read the more serious one."""
        out = _summarise("block", credential_harvest=0.9, phishing=0.8)
        self.assertIn("passwords", out["reason"])

    def test_high_confidence_and_low_confidence_read_differently(self):
        strong = _summarise("block", phishing=0.9)["reason"]
        weak = _summarise("warn", phishing=0.5)["reason"]
        self.assertNotEqual(strong, weak)
        # Hedged wording on the weaker signal, definite on the stronger.
        self.assertIn("looks like", weak)

    def test_malware_is_not_described_as_phishing(self):
        self.assertIn("harmful software", _summarise("block", malware=0.9)["reason"])

    def test_hidden_ai_instructions_are_explained_without_jargon(self):
        reason = _summarise("redact", promptware=0.9)["reason"]
        self.assertIn("AI assistant", reason)
        for jargon in ("promptware", "prompt_injection", "IOC", "exfil"):
            self.assertNotIn(jargon, reason)

    def test_no_reason_leaks_internal_vocabulary(self):
        """The gate's own reasons look like 'fallback: phishing/credential
        harvest'. None of that may reach a consumer surface."""
        cases = [
            _summarise("allow"),
            _summarise("warn", overall_risk=0.6),
            _summarise("block", malware=0.9),
            _summarise("redact", prompt_injection=0.8),
            _summarise("block", credential_harvest=0.5),
        ]
        for out in cases:
            with self.subTest(reason=out["reason"]):
                lowered = out["reason"].lower()
                for token in ("fallback", "_", "score", "threshold", "policy"):
                    self.assertNotIn(token, lowered)
                self.assertTrue(out["reason"].endswith("."))
                self.assertLess(len(out["reason"]), 120)


if __name__ == "__main__":
    unittest.main()
