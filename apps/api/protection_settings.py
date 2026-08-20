"""What every surface does when it cannot check something.

ONE SETTING, EVERY SURFACE
==========================
`fail_mode` directs the browser extension AND the desktop agent AND (when it
exists) the local proxy. It is stored per SUBSCRIPTION, not per device, so a
customer who chose "block when you can't check" gets that on their laptop and
their phone rather than discovering the phone was failing open all along.

THE DEFECT THIS SHAPE PREVENTS (CyberArmor.ai, 2026-08-06)
==========================================================
`transparent_proxy` had one FAIL_OPEN flag and two code paths reading it. The
policy path honoured it; the redact path blocked unconditionally. An endpoint
configured fail-open had its AI traffic blocked anyway, while every operator
view of its configuration said the opposite. It surfaced to the user as
"API Error: 403" from Claude Code, they concluded their Anthropic account was
blocked, and they uninstalled the agent to get working again.

So: the value is validated in exactly one place here, interpreted in exactly
one place on each client, and served on every response a surface already
fetches -- see `main.py`. A surface never has to ask separately, which means
it never has a stale copy it did not know was stale.

THE DEFAULT DIFFERS FROM B2B, DELIBERATELY
==========================================
CyberArmor.ai defaults to fail-CLOSED: block when we cannot check, "because
that is the most secure and it helps lead the customer toward decisions that
favor security and compliance over convenience". That reasoning assumes an
administrator who chose it and an IT function to call at 9am.

A household has neither. For a consumer, fail-closed with no warning means the
web breaks and the product is uninstalled -- and on the B2B side that is what
a *technical* user actually did, within a day. So the consumer default is
OPEN, the choice is offered in the portal with its consequences written out,
and when it IS closed every block says on the machine that it was us and that
it was temporary.
"""

from __future__ import annotations

from typing import Any, Dict

FAIL_OPEN = "open"
FAIL_CLOSED = "closed"
FAIL_MODES = (FAIL_OPEN, FAIL_CLOSED)

#: See the module docstring. Changing this is a product decision.
DEFAULT_FAIL_MODE = FAIL_OPEN

#: The local proxy is off until somebody opts in at install time.
DEFAULT_DEEP_INSPECTION = False


def is_valid_fail_mode(value: Any) -> bool:
    return value in FAIL_MODES


def resolve_fail_mode(value: Any) -> str:
    """Anything unrecognised becomes the default, never `closed`.

    A stored value from a newer version, a null from a pre-migration row, or a
    typo must not silently brick every surface on the account.
    """
    return value if is_valid_fail_mode(value) else DEFAULT_FAIL_MODE


def describe(fail_mode: str) -> str:
    """One sentence, for the surface that has to explain this to a person."""
    if resolve_fail_mode(fail_mode) == FAIL_CLOSED:
        return (
            "When we can't check something, it's blocked. Safer, but if our "
            "service is unreachable some sites and AI assistants will stop "
            "working until it's back."
        )
    return (
        "When we can't check something, we let it through and tell you we "
        "couldn't check. Nothing breaks, but an unchecked link isn't a "
        "checked one."
    )


def as_dict(subscription: Any) -> Dict[str, Any]:
    """The settings block every surface receives.

    `fail_mode` is resolved rather than passed through raw: the client also
    resolves, but a client that trusted a raw null would be one bug away from
    treating it as closed.
    """
    fail_mode = resolve_fail_mode(getattr(subscription, "fail_mode", None))
    return {
        "fail_mode": fail_mode,
        "fail_mode_explanation": describe(fail_mode),
        "deep_inspection": bool(
            getattr(subscription, "deep_inspection", DEFAULT_DEEP_INSPECTION)
        ),
    }
