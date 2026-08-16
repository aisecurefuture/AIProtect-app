"""Loader and validator for the policy field registry (shared/policy-fields.json).

WHAT THIS EXISTS TO STOP
------------------------
A customer typed "ChatGPT.com" into the Proxy Controls box labelled Domain,
saved, and the portal showed the policy active at priority 100. It enforced
nothing: ``request.domain`` resolved on no evaluator anywhere. Saved, displayed
active, doing nothing -- the authoring-path version of this repo's tracked
defect class.

The registry names every field string a shipped authoring surface can emit and,
per field, which evaluators can actually read it. Anything that is unknown here,
or known-but-dead (``resolves_on: []``), is refused at save time with a message
naming the offending field and listing what the author could have used instead.

NO SILENT DEGRADATION AT IMPORT
-------------------------------
If the JSON cannot be found or parsed this module raises and the policy service
does not start. That is deliberate: a validator that falls back to "accept
everything" when its data file is missing reinstates the exact defect it was
built to remove, and it does so invisibly. A container that forgot to ship the
file must fail loudly at boot, not silently at 3am.

THE VALIDATOR IS A WRITE GATE, NEVER A READ GATE
------------------------------------------------
``validate_conditions`` is called from PolicyCreate/PolicyUpdate. It is never
called on a listing or an export path. Rejecting on read would break a live
tenant whose stored rows predate validation -- and GET /policies/{t}/export is
what every browser extension in that tenant syncs, so a read gate would stop
enforcement product-wide for reasons unrelated to the bad rule.
``unenforceable_reasons`` is the read-side counterpart: it MARKS, it does not
filter and it does not mutate.

WHY NOTHING HERE DROPS OR REWRITES A RULE
-----------------------------------------
services/policy/policy_engine.py:328 returns True for an empty rule list, so a
policy with zero rules is a MATCH-EVERYTHING policy, not an inert one. Any
"clean up the bad rules" migration therefore converts a dead ``block`` policy
into a tenant-wide outage. Bad rules are refused on the way in and marked where
they already exist; they are never silently repaired.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# --- locating the registry -------------------------------------------------
#
# Two layouts, both real:
#   container -- services/policy/Dockerfile COPYs the file to /app/shared/ and
#                the module to /app/, so it is a sibling directory.
#   in-repo   -- services/policy/policy_fields.py, three levels under the root.
_HERE = Path(__file__).resolve()
_CANDIDATE_PATHS = (
    _HERE.parent / "shared" / "policy-fields.json",
    # parents[2:3] is a SLICE, not an index. In the container this module is at
    # /app/policy_fields.py, which has only two parents, so `parents[2]` raised
    # IndexError while BUILDING this tuple -- before the loop in _load() could
    # try the candidate above, which is the correct one and was present all
    # along at /app/shared/policy-fields.json. The service could not start.
    #
    # A slice past the end yields an empty sequence instead of raising, so the
    # in-repo candidate simply drops out where it cannot apply. Verified in a
    # real container: imports clean and loads all 30 registry fields.
    *(parent / "shared" / "policy-fields.json" for parent in _HERE.parents[2:3]),
)


def _load() -> Dict[str, Any]:
    tried = []
    for candidate in _CANDIDATE_PATHS:
        tried.append(str(candidate))
        if candidate.is_file():
            return json.loads(candidate.read_text())
    raise RuntimeError(
        "policy field registry not found; the policy service cannot validate "
        "what it stores and will not start with validation disabled. Looked in: "
        + ", ".join(tried)
        + ". services/policy/Dockerfile must COPY shared/policy-fields.json."
    )


REGISTRY: Dict[str, Any] = _load()

#: name -> the whole entry.
FIELDS: Dict[str, Dict[str, Any]] = {f["name"]: f for f in REGISTRY["fields"]}

#: Fields at least one evaluator can read. These are the only ones a new rule
#: may be authored on.
EVALUABLE_FIELDS: Tuple[str, ...] = tuple(
    sorted(name for name, f in FIELDS.items() if f.get("resolves_on"))
)

#: Fields a shipped surface can still emit and nothing can read. Kept in the
#: registry so the rejection message can say "known and cannot be enforced"
#: rather than "unknown field", which sends an operator hunting for a typo.
DEAD_FIELDS: Tuple[str, ...] = tuple(
    sorted(name for name, f in FIELDS.items() if not f.get("resolves_on"))
)

#: Fields whose value is a registrable domain and gets the minimum-label guard.
DOMAIN_FIELDS: Tuple[str, ...] = tuple(
    sorted(name for name, f in FIELDS.items() if f.get("value_kind") == "domain")
)

#: The one evaluator that decides real traffic on the ext_authz / proxy / runtime
#: paths. A rule authored against a field this engine cannot read is not "a
#: browser rule" -- it is a rule with TWO different meanings depending on which
#: engine happens to see it, and the server-side meaning is never the one the
#: author asked for. See _validate_leaf.
_SERVER_SURFACE = "server-engine"

#: Operators whose answer on an ABSENT field is True.
#: MEASURED against services/policy/policy_engine.py::_compare 2026-07-31:
#:   not_equals   (:920)  ``actual != expected``            -> None != x  -> True
#:   not_contains (:925)  ``... if actual is not None else True``        -> True
#:   not_in       (:940)  ``actual not in expected``        -> None not in [] -> True
#: A negative operator is therefore the only operator class that turns "this
#: field was never populated" into "this rule MATCHED". Every other operator
#: fails to a non-match, which is a silent no-op rather than an outage.
NEGATIVE_OPERATORS: Tuple[str, ...] = ("not_equals", "not_contains", "not_in")

#: Operators whose value must be a collection. ``_compare``'s in/not_in branches
#: (:938, :940) both read ``isinstance(expected, list)`` and SILENTLY fall back
#: to scalar equality when it is not a list -- so ``not_in "chatgpt.com"`` does
#: not error, it quietly becomes ``not_equals``, which is a different rule.
COLLECTION_OPERATORS: Tuple[str, ...] = ("in", "not_in")

# --- artifact references ----------------------------------------------------
#
# ``$artifact:<name>`` is a REAL, supported value form, not a template hole:
# services/policy/main.py:892-896 (/evaluate) and :2493-2498 (/ext_authz/check)
# load the tenant's artifacts and call policy_engine.resolve_artifact_references,
# which substitutes the reference for the artifact's items
# (policy_engine.py:1063-1093). Refusing it would break the shipped denylist
# mechanism -- services/policy/tests/test_ext_authz_fail_open_paths.py:136 is
# built on it.
#
# The prefix is duplicated rather than imported ON PURPOSE: policy_fields.py is
# imported by policy_engine.py (policy_engine.py:56), so importing back the other
# way is a cycle. test_placeholder_values_are_rejected_at_save.py asserts the two
# constants are equal, so the duplication cannot drift silently.
ARTIFACT_PREFIX = "$artifact:"


def artifact_ref(value: Any) -> Optional[str]:
    """The artifact name in ``$artifact:<name>``, else None.

    Byte-for-byte the same rule as policy_engine.py:1035 ``_artifact_ref``. If
    these two disagree, the gate accepts a string the engine will not resolve
    (or refuses one it would), and either direction is a rule that does not mean
    what it says.
    """
    if isinstance(value, str) and value.startswith(ARTIFACT_PREFIX):
        return value[len(ARTIFACT_PREFIX):].strip()
    return None


# --- unsubstituted template placeholders ------------------------------------
#
# WHAT THIS IS NOT. It is not a ban on "$" or on braces. ``$artifact:`` above is
# resolved by real code on the request path and is exempt. Every form below is
# resolved by NOTHING anywhere in this repository -- grep for them and the only
# hits are the strings themselves. A value carrying one of these reaches
# ``_compare`` verbatim and is compared as a literal, so:
#
#   * on a POSITIVE operator it can never equal a real value  -> silent no-op,
#     the tracked defect class in its usual fail-open direction;
#   * on a NEGATIVE operator it never equals a real value either, so the rule
#     is TRUE for every request -> a blanket block.
#
# Both are "a rule that did not really evaluate still produced a confident
# verdict". Refused at the door in both directions.
_PLACEHOLDER_FORMS = (
    (re.compile(r"\$\{[^}]*\}"), "${...} shell/template substitution"),
    (re.compile(r"\{\{[^}]*\}\}"), "{{...}} mustache/jinja substitution"),
    (re.compile(r"<%[^>]*%>"), "<%...%> template substitution"),
    (re.compile(r"%\([^)]*\)[sdrf]"), "%(...)s printf-style substitution"),
    # A bare "$word:rest" that is not $artifact:. Anchored, so a value that
    # merely CONTAINS a colon after a dollar mid-string (a regex, a URL) is
    # untouched.
    (re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*:"), "$namespace: substitution"),
)


def placeholder_form(value: Any) -> Optional[str]:
    """Name the unsubstituted-placeholder form in ``value``, else None.

    ``$artifact:<name>`` is checked FIRST and returns None -- it is the one
    substitution this product actually performs.
    """
    if not isinstance(value, str):
        return None
    if artifact_ref(value) is not None:
        return None
    for pattern, label in _PLACEHOLDER_FORMS:
        if pattern.search(value):
            return label
    return None


# ---------------------------------------------------------------------------
# Domain values
# ---------------------------------------------------------------------------
#
# THE MINIMUM-LABEL GUARD. A previous attempt at domain matching compiled the
# policy value straight into the declarativeNetRequest filter "||" + value + "^".
# That construct is CORRECT -- ||chatgpt.com^ is exactly how DNR expresses "this
# domain and its subdomains". The value was never checked, so a value of "com"
# compiled to ||com^ and blocked the entire .com web. Measured in real Chromium;
# the work was reverted for it.
#
# DELIBERATELY NOT A PUBLIC SUFFIX CHECK. Two labels is the bar, so "co.uk" and
# "com.au" pass and a rule on either covers everything under that suffix. See
# shared/policy-fields.json value_kinds.public_suffix_limitation for why that is
# accepted rather than overlooked.

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")


def normalize_domain_value(value: Any) -> str:
    """Lower-case and trim an authored domain value.

    Lower-casing is not cosmetic. Operators type these by hand ("ChatGPT.com"),
    browsers hand hostnames over already lower-cased, and both the JS
    ``equalsLoose`` and the Python ``_compare`` do string comparison WITHOUT
    case folding -- so an authored capital letter is a silent no-match.
    """
    return str(value if value is not None else "").strip().lower()


def is_valid_domain_value(value: Any) -> bool:
    """True when ``value`` is a domain this product will match on.

    Rejects, all of which are things an operator asked to "block ChatGPT"
    actually types: a bare public suffix ("com"), a pasted URL
    ("https://chatgpt.com"), a URL with a path ("chatgpt.com/c/1"), a wildcard
    ("*.chatgpt.com"), a leading or trailing dot, and anything with whitespace.
    """
    candidate = normalize_domain_value(value)
    if not candidate or len(candidate) > 253:
        return False
    return bool(_DOMAIN_RE.match(candidate))


def normalize_host(host: Any) -> str:
    """Reduce a wire host value to a bare comparable hostname.

    The Envoy ext_authz producer reads the Host / x-forwarded-host header
    verbatim -- no case folding, no port strip -- and that header is chosen by
    the party the rule governs. Without this, ``Host: ChatGPT.com`` or
    ``Host: chatgpt.com:443`` turns an enforcing domain rule into a no-match at
    the attacker's option. Applied only to the derived domain comparison;
    ``request.host`` itself is left exactly as the producer wrote it so no
    existing rule changes meaning.
    """
    text = str(host if host is not None else "").strip().lower()
    if not text:
        return ""
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    if text.startswith("["):  # IPv6 literal: [::1]:443
        closing = text.find("]")
        if closing != -1:
            text = text[: closing + 1]
    elif ":" in text:
        text = text.split(":", 1)[0]
    return text.rstrip(".")


def domain_matches(authored: Any, host: Any) -> Optional[bool]:
    """Exact-or-dot-boundary match, or None when the rule cannot be run.

    Returns:
      True  -- the host is the domain or is under it.
      False -- it is not.
      None  -- the authored value is not a usable domain, so this rule DID NOT
               RUN. None is a third answer on purpose: collapsing it to False
               makes "could not be evaluated" indistinguishable from "checked
               and cleared", which is the defect class this repo tracks.

    ``host.endswith(domain)`` without the dot is the classic form of this bug --
    it matches notchatgpt.com and chatgpt.com.evil.test is caught by comparing
    the full normalised host rather than a suffix of it.
    """
    domain = normalize_domain_value(authored)
    if not is_valid_domain_value(domain):
        return None
    candidate = normalize_host(host)
    if not candidate:
        return False
    return candidate == domain or candidate.endswith("." + domain)


# ---------------------------------------------------------------------------
# Condition-tree validation
# ---------------------------------------------------------------------------

#: Request-shaped fields first. Alphabetical order alone put eight content.*
#: entries at the front of every message, which is the least useful answer to
#: "I was trying to scope this to a website".
_ALTERNATIVE_ORDER = ("request.", "user.", "route.", "prompt.", "content.")


def _alternatives(limit: int = 12) -> str:
    def rank(name: str) -> tuple:
        for index, prefix in enumerate(_ALTERNATIVE_ORDER):
            if name.startswith(prefix):
                return (index, name)
        return (len(_ALTERNATIVE_ORDER), name)

    ordered = sorted(EVALUABLE_FIELDS, key=rank)
    shown = ordered[:limit]
    suffix = "" if len(ordered) <= limit else f" (+{len(ordered) - limit} more)"
    return ", ".join(shown) + suffix


def _first_sentence(text: str, limit: int = 240) -> str:
    """Keep a rejection message short enough that an operator reads it.

    The registry notes are written for whoever maintains the registry and run to
    several sentences; the first one is the part the author of a rejected policy
    needs.
    """
    text = " ".join(str(text or "").split())
    if not text:
        return ""
    # The registry marks dead fields with a leading "DEAD." for whoever is
    # reading the JSON. On its own it tells an operator nothing, so it is
    # dropped and the sentence that explains WHY is used instead.
    for marker in ("DEAD.", "KNOWN GAP,"):
        if text.startswith(marker):
            text = text[len(marker):].strip()
            break
    head = text.split(". ", 1)[0].rstrip(".")
    return (head[:limit] + "...") if len(head) > limit else head


def _describe_field(name: str) -> str:
    """The rejection message for one bad field, naming alternatives.

    "invalid field" on its own makes the author guess, and the author is
    typically looking at a form that offered them the field in the first place.
    """
    if name in FIELDS:
        note = _first_sentence(FIELDS[name].get("note", ""))
        return (
            f"policy field {name!r} is a known field that resolves on no evaluator "
            f"in this product, so a rule using it can never fire"
            + (f" ({note})" if note else "")
            + f". Evaluable fields: {_alternatives()}."
        )
    return (
        f"policy field {name!r} is not in the policy field registry "
        f"(shared/policy-fields.json), so nothing in the product can read it. "
        f"Evaluable fields: {_alternatives()}."
    )


def _validate_group(node: Any, path: str, errors: List[str]) -> None:
    if not isinstance(node, dict):
        errors.append(f"conditions{path} must be an object, got {type(node).__name__}")
        return

    rules = node.get("rules")
    if rules is None:
        errors.append(
            f"conditions{path} has no `rules` key. The engine reads a condition "
            "group with no rules as zero rules and MATCHES EVERY REQUEST, so this "
            "shape is a match-everything policy rather than an inert one. "
            f"Keys present: {sorted(node.keys())}"
        )
        return
    if not isinstance(rules, list):
        errors.append(f"conditions{path}.rules must be a list, got {type(rules).__name__}")
        return
    if not rules:
        errors.append(
            f"conditions{path}.rules is empty. An empty rule list matches every "
            "request (policy_engine.py returns True for zero rules), so an empty "
            "condition group is a match-everything policy, not a disabled one."
        )
        return

    for index, rule in enumerate(rules):
        here = f"{path}.rules[{index}]"
        if not isinstance(rule, dict):
            errors.append(f"conditions{here} must be an object, got {type(rule).__name__}")
            continue
        if "rules" in rule:
            _validate_group(rule, here, errors)
            continue
        _validate_leaf(rule, here, errors)


def _validate_leaf(rule: Dict[str, Any], path: str, errors: List[str]) -> None:
    raw_field = rule.get("field")
    if raw_field is None:
        errors.append(
            f"conditions{path} has no `field` key, so there is nothing for the "
            f"evaluator to read. Evaluable fields: {_alternatives()}."
        )
        return
    name = str(raw_field).strip()
    if not name:
        errors.append(
            f"conditions{path} has an empty `field` string. "
            f"Evaluable fields: {_alternatives()}."
        )
        return

    entry = FIELDS.get(name)
    if entry is None or not entry.get("resolves_on"):
        errors.append(f"conditions{path}: {_describe_field(name)}")
        return

    # STORE THE NAME WE VALIDATED, NOT THE ONE WE RECEIVED.
    #
    # The registry lookup above used the stripped name; without this line the
    # rule kept the raw one. No evaluator strips -- policy_engine reads
    # rule.get("field", "") and compares node.get("field") == DOMAIN_FIELD
    # exactly -- so " request.domain " passed the gate, was stored padded, and
    # then matched nothing. That is worse than the hole this gate was built to
    # close: before it the operator got no signal, and after it they got an
    # affirmative "enforceable" verdict behind a rule that can never fire.
    #
    # Deliberately on the ACCEPTED path only. A field that resolves nowhere is
    # left exactly as authored, so the error message and the stored value agree.
    #
    # The Builder UI trims (shared/policy-builder.js), which is why this was
    # invisible; the raw API, the control-plane pass-through, seed scripts and
    # any copy-paste carrying a trailing space all reach here untrimmed.
    rule["field"] = name

    operator = rule.get("operator", "equals")
    operator = operator.strip() if isinstance(operator, str) else operator
    value = rule.get("value")
    ref = artifact_ref(value)

    # --- GATE A: an unsubstituted template placeholder ----------------------
    #
    # Checked before anything value-shaped below, because a placeholder is not a
    # malformed domain or a mistyped list -- it is a value that was never filled
    # in, and saying so is the only message that tells the author what to do.
    form = placeholder_form(value)
    if form is not None:
        errors.append(
            f"conditions{path}: {name} value {str(value)!r} is an unsubstituted "
            f"template placeholder ({form}). Nothing in this product substitutes "
            f"it, so the engine compares the literal text: on a positive operator "
            f"the rule can never fire, and on a negative operator "
            f"({', '.join(NEGATIVE_OPERATORS)}) it fires on EVERY request. "
            f"Supply the real value, or reference a tenant list with "
            f"'{ARTIFACT_PREFIX}<name>', which is resolved at evaluation time."
        )
        return

    # --- GATE B: value type must match the operator -------------------------
    #
    # policy_engine._compare:938/940 tests ``isinstance(expected, list)`` and
    # falls back to scalar equality when it is not one. So ``in``/``not_in`` with
    # a bare string does not fail -- it silently becomes equals/not_equals, a
    # DIFFERENT rule from the one the author wrote, stored and displayed as the
    # one they wrote.
    #
    # An artifact reference is accepted: _resolve_value:1093 returns the
    # artifact's ``items``, which is always a list, so by the time _compare sees
    # it the type is right.
    if operator in COLLECTION_OPERATORS and ref is None and not isinstance(value, list):
        errors.append(
            f"conditions{path}: {name} uses operator {operator!r}, which compares "
            f"against a LIST, but the value is "
            f"{type(value).__name__} ({str(value)!r}). The engine does not reject "
            f"this -- it silently degrades to "
            f"{'equals' if operator == 'in' else 'not_equals'}, so the stored rule "
            f"means something other than what it says. Use a JSON list "
            f'(e.g. ["chatgpt.com", "claude.ai"]) or "{ARTIFACT_PREFIX}<name>".'
        )
        return

    # --- GATE C: a negative operator on a field the server cannot read ------
    #
    # THIS IS THE GATE THAT REFUSES THE REPORTED POLICY, and neither Gate A nor
    # Gate B does: `route.destination not_in $artifact:approved_providers` is a
    # legitimate artifact reference (Gate A passes) of the right resolved type
    # (Gate B passes). It still blocks every request.
    #
    # MEASURED 2026-07-31 against the real PythonPolicyEngine with an
    # ext_authz-shaped context, in all four artifact states -- including the
    # artifact PRESENT and correctly populated with real provider domains:
    # action=block on host example.org, every time, problems=[]. Substituting the
    # placeholder correctly fixes nothing, because `route` is not one of the eight
    # sections EvaluationContext.to_flat_dict emits (policy_engine.py:265-281), so
    # ``actual`` is None regardless, and ``None not in [...]`` is True.
    #
    # The rule is therefore refused on the FIELD/OPERATOR pair, not on the value.
    # Any field the server engine cannot read is permanently None there; combined
    # with a negative operator that is a match-everything term on the one
    # evaluator that fronts real traffic.
    #
    # DELIBERATELY NOT SCOPE-AWARE. Scope is authored, mutable and does not
    # prevent /evaluate being called with the row; gating on it would make the
    # refusal depend on a field the author controls.
    #
    # THE ESCAPE HATCH IS A WORKING FIELD, NOT A LOST FEATURE. `request.domain`
    # resolves on ext-js, ext-dnr AND server-engine, supports in/not_in against a
    # list on both engines (policy_engine.py:849-886, background.js:1795), derives
    # the host from whatever key the producer wrote (policy_engine.py:888-907),
    # and RECORDS a "this rule did not run" problem for an unusable value instead
    # of guessing (:868-875). Measured on the same four artifact states: no match
    # + a recorded problem when unresolved, and a correct block of an unapproved
    # host when resolved.
    #
    # OVER-REJECTION, MEASURED: across all 58 shipped pack templates this refuses
    # exactly the 4 route.destination blocks. No other template, and no test in
    # services/policy/tests/, pairs a negative operator with a browser-only field.
    if operator in NEGATIVE_OPERATORS and _SERVER_SURFACE not in (entry.get("resolves_on") or []):
        server_alternatives = ", ".join(
            n for n in EVALUABLE_FIELDS
            if _SERVER_SURFACE in (FIELDS[n].get("resolves_on") or [])
        )
        errors.append(
            f"conditions{path}: {name} cannot be read by the server engine "
            f"(it resolves only on {', '.join(entry['resolves_on'])}), and "
            f"{operator!r} is a negative operator. On the server the field is "
            f"always absent, and policy_engine._compare answers a negative "
            f"operator over an absent field with True -- so this rule MATCHES "
            f"EVERY REQUEST on ext_authz, the transparent proxy and the endpoint "
            f"local proxy, whatever its value resolves to. Use a field the server "
            f"can read: {server_alternatives}. For 'traffic not going to an "
            f"approved destination', request.domain is the direct replacement: it "
            f"resolves on both engines and supports not_in against a list."
        )
        return

    if entry.get("value_kind") == "domain":
        # A LIST AND AN ARTIFACT REFERENCE ARE BOTH LEGITIMATE HERE, and refusing
        # them was a live over-rejection: policy_engine._evaluate_domain_rule:849
        # does ``candidates = expected if isinstance(expected, list) else [expected]``
        # and :884 branches on in/not_in, so a list is the SUPPORTED shape for the
        # only operators that can express an allowlist. MEASURED before this
        # change: `request.domain not_in ["chatgpt.com","claude.ai"]` -- the exact
        # shape the fixed compliance packs emit, and the shape that works on both
        # engines -- was rejected at save, while `route.destination not_in
        # "$artifact:approved_providers"`, which blocks the entire internet, was
        # accepted. The gate was refusing the cure and admitting the disease.
        #
        # An artifact reference is NOT validated for domain shape here: its items
        # live in the artifacts table, are not visible to a pure-function
        # validator, and can change after this policy is saved. The engine already
        # covers that case honestly -- an unusable item is skipped and recorded as
        # "this rule did not run" (policy_engine.py:862-875) rather than silently
        # cleared. See _reject_unresolvable_artifact_refs in main.py for the
        # existence check, which does have a database session.
        if ref is None:
            candidates = value if isinstance(value, list) else [value]
            if isinstance(value, list) and not candidates:
                errors.append(
                    f"conditions{path}: {name} has an empty list value. "
                    f"policy_engine._evaluate_domain_rule compares nothing and "
                    f"returns no-match without recording a problem, so this rule "
                    f"reads as enforcing and silently checks nothing."
                )
                return
            for candidate in candidates:
                if not is_valid_domain_value(candidate):
                    errors.append(
                        f"conditions{path}: {name} value {str(candidate)!r} is not a domain this "
                        "product can match on. A domain needs at least two dot-separated "
                        "labels and nothing else -- no scheme, no path, no wildcard, no "
                        "leading or trailing dot. A single-label value such as 'com' would "
                        "cover every host under that suffix; that exact mistake blocked the "
                        "entire .com web once and is refused here. Example: chatgpt.com "
                        "(which also covers www.chatgpt.com and api.chatgpt.com)."
                    )


def validate_conditions(conditions: Any) -> List[str]:
    """Return every reason ``conditions`` cannot be enforced; empty means fine.

    ``None`` is accepted: a policy with no condition group falls through to the
    legacy ``rules`` path in the engine, which is a separate shape with its own
    behaviour and is not this round's subject.
    """
    if conditions is None:
        return []
    errors: List[str] = []
    _validate_group(conditions, "", errors)
    return errors


def unenforceable_reasons(conditions: Any) -> List[str]:
    """Read-side marker for rows already in the database.

    Same analysis as ``validate_conditions``, different contract: this NEVER
    changes what is returned to the caller, it only annotates it. A stored rule
    that cannot fire must not keep rendering as "active at priority 100" -- that
    is precisely the founder's original experience, and leaving the pre-existing
    rows unmarked would reproduce it for every one of them.
    """
    return validate_conditions(conditions)
