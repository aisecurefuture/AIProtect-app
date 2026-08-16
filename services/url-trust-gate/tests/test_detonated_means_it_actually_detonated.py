"""`detonated: true` must mean a sandbox rendered the page.

FOUND BY AUDIT 2026-08-11, while checking whether sealed external-content
retrieval could be demonstrated to a regulated buyer.

    main.py:514   detonated=detonation_result is not None,   # policy input
    main.py:536   detonated=detonation_result is not None,   # EVIDENCE RECORD
    main.py:563   detonated=detonation_result is not None,   # API response

DetonationSandbox.render() NEVER RETURNS None. Every failure path returns a
DetonationResult carrying `error`:

    detonation.py:94    worker not configured
    detonation.py:113   non-200 from the worker
    detonation.py:117   401 -- e.g. the mistyped DETONATiON_WORKER_API_SECRET
    detonation.py:132   worker timeout
    detonation.py:140   worker unreachable

So `is not None` asks "was detonation ATTEMPTED", and the answer was written
into a field named `detonated`. A worker that was absent, misconfigured or
timing out produced a policy decision, an API response, and an audit record all
asserting the URL had been detonated in a sandbox when nothing rendered it.

WHY THIS ONE MATTERS MORE THAN THE USUAL INSTANCE. This codebase tracks
"reports success when the check never ran" as its recurring defect. Here it
lands in the EVIDENCE TRAIL -- the artifact whose entire purpose is to be
trustworthy after the fact, shown to an auditor at a SEC/FINRA-regulated firm.
A record that overstates what was inspected is worse than one that admits it
could not look.

Compounding it: observe_detonation_timeout() (metrics.py:69) had no caller
anywhere in the service, so url_trust_gate_detonation_timeouts_total was
permanently 0 while url_trust_gate_detonations_total counted those same
timeouts as successes. Both signals an operator would check agreed, and both
were wrong.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SVC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_SVC))

from detonation import DetonationResult  # noqa: E402


#: Every failure render() can return, with the line it comes from.
FAILURES = [
    ("detonation_worker_not_configured", "detonation.py:94"),
    ("worker_http_502", "detonation.py:113"),
    ("worker_unauthorized", "detonation.py:117 — the mistyped secret"),
    ("worker_timeout", "detonation.py:132"),
    ("worker_unreachable", "detonation.py:140"),
]


class AFailedRenderIsNotADetonation(unittest.TestCase):

    def test_every_failure_path_reports_not_succeeded(self):
        for err, where in FAILURES:
            with self.subTest(error=err):
                r = DetonationResult(error=err)
                self.assertFalse(
                    r.succeeded,
                    f"{err} ({where}) reports succeeded=True. This value "
                    f"populates the `detonated` field of an audit record.",
                )

    def test_identity_is_true_for_every_failure(self):
        """The property being replaced. Pinned so the difference is explicit:
        `is not None` cannot distinguish any of these from a real render."""
        for err, _ in FAILURES:
            with self.subTest(error=err):
                self.assertIsNotNone(
                    DetonationResult(error=err),
                    "if this ever fails, render() started returning None and "
                    "the original check would have been defensible",
                )

    def test_a_real_render_succeeds(self):
        r = DetonationResult(rendered_html="<html>hi</html>", visible_text="hi")
        self.assertTrue(r.succeeded)

    def test_an_empty_page_with_no_error_still_counts(self):
        """A page that renders to nothing is a successful render of an empty
        page. Only `error` decides."""
        self.assertTrue(DetonationResult().succeeded)


class TheGateUsesSuccessNotIdentity(unittest.TestCase):
    """Defining `succeeded` and leaving the call sites alone would leave every
    assertion above green and the audit record still lying."""

    def setUp(self):
        self.src = (_SVC / "main.py").read_text(encoding="utf-8")

    def test_no_call_site_still_tests_identity(self):
        self.assertNotIn(
            "detonated=detonation_result is not None", self.src,
            "a call site still reports `detonated` from object identity, so a "
            "failed render is still recorded as a detonation",
        )

    def test_all_three_call_sites_use_the_helper(self):
        n = self.src.count("detonated=_detonation_succeeded(detonation_result)")
        self.assertEqual(
            n, 3,
            f"expected 3 call sites (policy input, evidence record, API "
            f"response) using the success check, found {n}",
        )

    def _calls_named(self, name: str) -> int:
        """Count real CALLS to `name`, via the AST.

        Not a substring search. The first version of this test did
        `assertIn("observe_detonation_timeout()", src)` and passed after the
        call was deleted -- because the docstring above this class MENTIONS the
        function by name, and a comment satisfied the assertion. A test that its
        own prose can satisfy checks nothing.
        """
        import ast
        tree = ast.parse(self.src)
        n = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Attribute) and f.attr == name:
                    n += 1
                elif isinstance(f, ast.Name) and f.id == name:
                    n += 1
        return n

    def test_the_timeout_metric_has_a_caller(self):
        """It had none. The counter existed, was documented, and could only
        ever read 0 -- which an operator reads as 'no timeouts'."""
        self.assertGreaterEqual(
            self._calls_named("observe_detonation_timeout"), 1,
            "url_trust_gate_detonation_timeouts_total has no CALLER (checked by "
            "AST, so a mention in a comment does not count)",
        )

    def test_a_failed_detonation_is_logged(self):
        """A metric alone does not tell an operator WHICH url was not rendered,
        or why. Asserted on the log CALL, not on the string appearing anywhere."""
        import ast
        tree = ast.parse(self.src)
        logged = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in ("warning", "error"):
                for a in node.args:
                    if isinstance(a, ast.Constant) and isinstance(a.value, str) \
                            and "detonation_failed" in a.value:
                        logged = True
        self.assertTrue(
            logged,
            "no logger.warning/error carries detonation_failed, so a dead "
            "worker leaves nothing an operator can search for",
        )


if __name__ == "__main__":
    unittest.main()
