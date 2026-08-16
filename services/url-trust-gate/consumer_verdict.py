"""Turn an enforcement decision into something a person can act on.

The gate's native vocabulary -- ``allow | warn | redact | sandbox | block |
isolate``, with reasons like ``"fallback: phishing/credential harvest"`` -- is
written for an enforcement point. A consumer needs three states and one
sentence, and getting that translation wrong is not cosmetic: a person who
cannot tell what the app is telling them will either ignore every warning or
uninstall the product.

THREE VERDICTS
==============
    safe     nothing to do
    caution  it opens, but look before you type anything into it
    blocked  it does not open

``redact`` maps to CAUTION rather than SAFE: redaction means the page carried
something the gate stripped, and "we cleaned this up for you" is a warning, not
an all-clear. ``sandbox`` and ``isolate`` map to BLOCKED because from a phone
there is nothing to isolate into -- there is no sandboxed browser to hand the
page to, so the honest consumer rendering of "only open this in a sandbox" is
"do not open this".

WHAT WAS ACTUALLY CHECKED
=========================
Every consumer verdict carries ``checks_performed``. A ``depth=fast`` answer on
a URL nobody has seen before is a REPUTATION-ONLY answer: no one fetched the
page. That is a genuinely weaker claim than "we read this page and it was
fine", and collapsing the two would be this codebase's recurring defect wearing
consumer clothing -- a check that did not run rendering as a check that ran and
found nothing.

So ``safe`` never means "this page is safe". It means "nothing we checked came
back bad", and the response says which checks those were.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

SAFE = "safe"
CAUTION = "caution"
BLOCKED = "blocked"

#: Enforcement action -> consumer verdict.
_ACTION_TO_VERDICT: Dict[str, str] = {
    "allow": SAFE,
    "warn": CAUTION,
    "redact": CAUTION,
    "sandbox": BLOCKED,
    "isolate": BLOCKED,
    "block": BLOCKED,
    # The policy vocabulary's approval action has no consumer meaning -- there
    # is no administrator to approve anything. The gate already folds it into
    # block upstream; this entry exists so a future policy path cannot leak an
    # unmapped action through as "safe".
    "require_approval": BLOCKED,
}

#: (score field, threshold, sentence). Ordered by severity: the first match
#: wins, so the most serious true statement is the one the person reads.
#:
#: Every sentence describes what the page DOES, in words with no security
#: jargon, and none of them claim more certainty than a score implies.
_REASONS: Tuple[Tuple[str, float, str], ...] = (
    ("credential_harvest", 0.7,
     "This page is built to capture passwords or login codes."),
    ("phishing", 0.7,
     "This page is impersonating a site you trust, to get your information."),
    ("malware", 0.7,
     "This site is known for installing harmful software."),
    ("brand_impersonation", 0.7,
     "This page is pretending to be a company you know."),
    ("promptware", 0.7,
     "This page hides instructions meant to hijack an AI assistant."),
    ("prompt_injection", 0.7,
     "This page hides instructions meant to hijack an AI assistant."),
    ("data_exfil", 0.7,
     "This page tries to send your information somewhere unexpected."),
    # Softer tier: real signal, less certainty. The wording drops from
    # "is" to "looks like" on purpose.
    ("credential_harvest", 0.4, "This page asks for login details in a way that looks unsafe."),
    ("phishing", 0.4, "This page looks like an attempt to impersonate another site."),
    ("malware", 0.4, "Some sources have reported this site as unsafe."),
    ("brand_impersonation", 0.4, "This page may be imitating a brand you know."),
    ("promptware", 0.4, "This page may contain hidden text aimed at AI assistants."),
    ("prompt_injection", 0.4, "This page may contain hidden text aimed at AI assistants."),
    ("data_exfil", 0.4, "This page may share what you enter with someone else."),
)

_GENERIC_BLOCKED = "We found serious problems with this page, so we did not open it."
_GENERIC_CAUTION = "Something about this page looks risky. Be careful what you enter."
_SAFE_CHECKED = "We checked this page and found nothing harmful."
_SAFE_REPUTATION_ONLY = (
    "Nothing is known against this link, but we have not opened the page itself."
)


def _dominant_reason(scores: Any) -> Optional[str]:
    for field, threshold, sentence in _REASONS:
        if float(getattr(scores, field, 0.0) or 0.0) >= threshold:
            return sentence
    return None


def checks_performed(
    *, depth: str, cache_hit: bool, crawled: bool, detonated: bool
) -> List[str]:
    """Name what actually happened, so `safe` is a bounded claim.

    Deliberately not a boolean "checked". "We looked it up in a reputation
    feed" and "we fetched the page and read it" are different amounts of
    evidence, and the person deserves to know which one they got.
    """
    performed = ["reputation_lookup"]
    if cache_hit:
        performed.append("previous_result_reused")
    if crawled:
        performed.append("page_fetched_and_scanned")
    if detonated:
        performed.append("opened_in_sandbox")
    if depth == "fast" and not crawled and not cache_hit:
        performed.append("page_not_fetched")
    return performed


def summarise(
    *,
    action: str,
    scores: Any,
    depth: str,
    cache_hit: bool,
    crawled: bool,
    detonated: bool,
) -> Dict[str, Any]:
    """Build the consumer-facing block of a trust-gate response."""
    verdict = _ACTION_TO_VERDICT.get((action or "").lower(), CAUTION)
    performed = checks_performed(
        depth=depth, cache_hit=cache_hit, crawled=crawled, detonated=detonated
    )
    page_was_read = "page_fetched_and_scanned" in performed or "opened_in_sandbox" in performed

    reason = _dominant_reason(scores)
    if reason is None:
        if verdict == BLOCKED:
            reason = _GENERIC_BLOCKED
        elif verdict == CAUTION:
            reason = _GENERIC_CAUTION
        else:
            reason = _SAFE_CHECKED if page_was_read else _SAFE_REPUTATION_ONLY

    return {
        "verdict": verdict,
        # Exactly one sentence, no jargon. This is the string the UI shows.
        "reason": reason,
        # What this verdict is actually based on. Always present.
        "checks_performed": performed,
        # False when the verdict rests on reputation alone -- a UI can soften
        # a "safe" that nobody corroborated by reading the page.
        "page_was_read": page_was_read,
    }
