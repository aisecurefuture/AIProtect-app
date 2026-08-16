"""A tenant policy that says DENY must not reach the browser as a warning.

THE DEFECT
----------
``_normalise_action`` maps a policy-service verdict onto this gate's action
vocabulary. It was written against the policy service's older ACTION
vocabulary -- ``{monitor, allow, warn, block}`` -- and its docstring said so.

But its caller reads the DECISION field::

    action = _normalise_action(data.get("decision", "monitor"))   # main.py:865

``decision`` is a different vocabulary: ALLOW, DENY, ALLOW_WITH_REDACTION,
ALLOW_WITH_LIMITS, ALLOW_WITH_AUDIT_ONLY, REQUIRE_APPROVAL, QUARANTINE (the
``decision = "..."`` assignments in services/policy/main.py). Six of those
seven matched neither branch of the function and fell through to its
catch-all ``return "warn"``. Only ALLOW came out right, and only because the
two vocabularies happen to spell it identically -- so every smoke test using
an allow policy passed.

WHAT IT COST
------------
This gate runs on every top-level navigation (``url_trust_gate.js``) and on the
MITM proxy's Step 0 (``transparent_proxy.py``). So a tenant rule that said
BLOCK this URL was delivered to the browser as ``warn``, which is a
session-storage note and nothing else. QUARANTINE and REQUIRE_APPROVAL the
same. A security control, enabled, reporting a verdict it had quietly softened.

It was found on 2026-07-31 while tracing why the match-everything ISO 27001
template had not darkened every browser in the tenant. It had. This downgraded
it. The product looked like it was working because one bug was masking another
-- which is the worst way to be safe, because the day the mask is fixed the
outage arrives with no warning.

WHY "warn" IS STILL THE FALLBACK
---------------------------------
For a value neither vocabulary defines, the gate genuinely does not know what
the tenant wanted, and warn remains the conservative guess. What changed is
that it is now LOGGED, and that no KNOWN verdict lands there any more. The
defect was never the fallback; it was six known verdicts arriving at it.

No network, no policy service -- the mapping function directly.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Loaded by PATH under a unique name rather than as a bare `import main`.
# Every service in this repo has a top-level module called `main` and
# sys.modules is process-wide, so a bare import here would hand this service's
# `main` to whichever suite is collected next -- measured elsewhere in this
# repo as services/audit/tests receiving services/ai-router/main.py, which
# fails loudly, and would fail SILENTLY for any same-named symbol.
_MAIN = ROOT / "main.py"
_spec = importlib.util.spec_from_file_location("url_trust_gate_main", _MAIN)
_main = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_main)

_normalise_action = _main._normalise_action
_POLICY_DECISION_TO_ACTION = _main._POLICY_DECISION_TO_ACTION


class TestEnforcingVerdictsSurvive:
    def test_deny_blocks(self):
        """THE DEFECT. Previously 'warn'."""
        assert _normalise_action("DENY") == "block", (
            "a tenant policy saying DENY was delivered to the browser as a "
            "warning; the navigation proceeded"
        )

    def test_quarantine_isolates(self):
        assert _normalise_action("QUARANTINE") == "isolate"

    def test_require_approval_does_not_proceed_unapproved(self):
        """The gate cannot run an approval flow mid-navigation."""
        assert _normalise_action("REQUIRE_APPROVAL") == "block"

    def test_redaction_is_not_flattened_to_a_warning(self):
        assert _normalise_action("ALLOW_WITH_REDACTION") == "redact"


class TestPermissiveVerdictsAreNotSpuriouslyWarned:
    """The inverse error: warning a user on a verdict that said allow."""

    @pytest.mark.parametrize(
        "decision", ["ALLOW", "ALLOW_WITH_LIMITS", "ALLOW_WITH_AUDIT_ONLY"]
    )
    def test_allow_shaped_verdicts_allow(self, decision):
        assert _normalise_action(decision) == "allow"


class TestTheLegacyVocabularyStillWorks:
    """The older /policies/{tid}/evaluate shape must keep working.

    Both are live: nothing guarantees which endpoint a given deployment calls,
    so accepting only the new vocabulary would move the fail-open rather than
    close it.
    """

    @pytest.mark.parametrize(
        "action,expected",
        [
            ("block", "block"), ("warn", "warn"), ("allow", "allow"),
            ("monitor", "allow"), ("redact", "redact"),
            ("sandbox", "sandbox"), ("isolate", "isolate"),
        ],
    )
    def test_action_vocabulary_is_unchanged(self, action, expected):
        assert _normalise_action(action) == expected


class TestEveryShippedDecisionIsMapped:
    """A structural guard, because a behavioural one only covers what I listed.

    If services/policy/main.py gains an eighth decision value, it silently
    lands on the catch-all and this gate softens it -- exactly the defect,
    returning under a new name. This asserts the map covers the full published
    vocabulary, so adding a verdict without teaching this gate about it fails
    here rather than in a customer's browser.
    """

    SHIPPED_DECISIONS = {
        "ALLOW", "DENY", "ALLOW_WITH_REDACTION", "ALLOW_WITH_LIMITS",
        "ALLOW_WITH_AUDIT_ONLY", "REQUIRE_APPROVAL", "QUARANTINE",
    }

    def test_the_map_covers_the_published_vocabulary(self):
        missing = self.SHIPPED_DECISIONS - set(_POLICY_DECISION_TO_ACTION)
        assert not missing, (
            f"policy decisions this gate does not understand: {sorted(missing)}. "
            "Each one silently becomes 'warn'."
        )

    def test_no_enforcing_decision_maps_to_a_mere_warning(self):
        enforcing = {"DENY", "REQUIRE_APPROVAL", "QUARANTINE"}
        for decision in enforcing:
            assert _normalise_action(decision) != "warn", (
                f"{decision} came out as 'warn' -- a session-storage note "
                f"where the tenant asked for enforcement"
            )

    def test_an_unknown_verdict_still_warns(self):
        """The fallback is fine; six known verdicts reaching it was not."""
        assert _normalise_action("something_new") == "warn"
        assert _normalise_action("") == "warn"
        assert _normalise_action(None) == "warn"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
