"""UNEVALUATABLE policy conditions -- the third state, named and reported.

THE DEFECT THIS MODULE EXISTS TO REMOVE
---------------------------------------
``PythonPolicyEngine._evaluate_condition_group`` used to open with::

    rules = conditions.get("rules", [])
    if not rules:
        return True, []

That single line collapses four different facts into one answer:

  * "the author emptied this rule group"            {"operator":"AND","rules":[]}
  * "this blob has no rules key at all"             {"imported": true}
  * "this blob is a different schema entirely"      {"any":[ ... ]}
  * "this group has an operator but no rules"       {"operator":"AND"}

...and answers all four with **matches**. Attached to ``action:"allow"`` at a low
priority number that is a silent blanket ALLOW that outranks every real rule;
attached to ``action:"block"`` it is a global outage. Same line, both polarities.

THE RULE
--------
A condition group that expresses no evaluable constraint is UNEVALUATABLE.
Unevaluatable is a **third state** -- neither "matched" nor "did not match". An
unevaluatable policy is SKIPPED and the skip is REPORTED. "Skipped + reported",
not "no match", is the whole point: "no match" is a normal silent outcome, and a
policy that *cannot* fire must never render as a policy that fired and cleared.

Match-all does not disappear -- it becomes expressible only by saying so, with
the group operator ``ALWAYS``.

WHY THIS FILE AND NOT services/policy/policy_fields.py
------------------------------------------------------
``policy_fields.py`` carries a function with a similar shape
(``unenforceable_reasons``). It belongs to a round that was REJECTED by its own
verification and is under a standing instruction to be left untouched -- neither
built upon nor deleted. This module therefore re-implements the contract from
scratch and imports nothing from it. The two coexist; ``main.py`` calls both, and
their outputs are reported under separate names (``unenforceable`` from that
round, ``enforceable`` / ``unenforceable_reasons`` from this one).

WHAT THIS MODULE IS NOT
-----------------------
It never returns "deny". Fail-closed on an unevaluatable policy would take the
customer's bank down for exactly the reason the current bug does; fail-open is
the current bug. SKIP is the only answer that is safe in both polarities -- and
skip *alone* is this repository's tracked defect class, which is why every
consumer of this module is obliged to report what it skipped.
"""

from __future__ import annotations

from typing import Any, Dict, List, NamedTuple, Optional, Tuple

# ---------------------------------------------------------------------------
# Reason codes -- the vocabulary. One decision (skip), several reasons, because
# the operator's remedy differs: an emptied group needs its rules re-added, an
# imported stub needs the import route fixed or the policy deleted, and an
# unknown-schema blob needs manual re-authoring with correct field namespaces.
# ---------------------------------------------------------------------------

REASON_RULES_EMPTY = "conditions.rules_empty"
REASON_RULES_MISSING = "conditions.rules_missing"
REASON_IMPORTED_STUB = "conditions.imported_stub"
REASON_UNKNOWN_SCHEMA = "conditions.unknown_schema"
REASON_ABSENT = "conditions.absent"
REASON_NOT_AN_OBJECT = "conditions.not_an_object"
REASON_LEAF_NO_FIELD = "conditions.leaf_no_field"
REASON_LEAF_UNKNOWN_OPERATOR = "conditions.leaf_unknown_operator"
REASON_UNKNOWN_OPERATOR = "conditions.unknown_operator"
REASON_NESTED_UNEVALUATABLE = "conditions.nested_unevaluatable"
REASON_ALWAYS_WITH_RULES = "conditions.always_with_rules"

#: The check name every consumer records this under. One name, so an operator
#: greps for one string across headers, logs and API responses.
PROBLEM_CHECK = "policy.unevaluatable"


# ---------------------------------------------------------------------------
# The explicit match-all
# ---------------------------------------------------------------------------

ALWAYS_OPERATOR = "ALWAYS"

#: Group operators. ``ALWAYS`` is a *group* operator, sibling of AND/OR/NOT --
#: it is deliberately NOT added to the leaf vocabulary below.
GROUP_OPERATORS = frozenset({"AND", "OR", "NOT", ALWAYS_OPERATOR})

#: Leaf operators. This is exactly the published vocabulary
#: (``shared/policy-builder.js`` ``OPERATORS``) and exactly the set
#: ``PythonPolicyEngine._compare`` implements. MEASURED 2026-07-31: the two
#: lists are identical, 18 entries, and all 58 compliance-pack templates across
#: 16 frameworks use only equals / not_equals / in / not_in / exists.
LEAF_OPERATORS = frozenset({
    "equals", "not_equals",
    "contains", "not_contains",
    "starts_with", "ends_with",
    "matches", "regex",
    "in", "not_in",
    "greater_than", "greater_than_or_equals",
    "less_than", "less_than_or_equals",
    "exists", "not_exists",
    "is_empty", "is_not_empty",
})

#: THE POSITIVE AUDIT ARTIFACT. A deliberate match-all must be distinguishable
#: from the accidental one it replaces, in the audit record and not just in the
#: source. The old zero-count match reason was the accidental one's fingerprint;
#: these two strings are the deliberate one's, and they can only be produced by
#: code that actually reached the ALWAYS branch.
MATCH_ALL_RULE = "match_all (explicit)"
MATCH_ALL_REASON = "explicit match_all"

#: Depth cap. Hostile or corrupt stored data must not be able to blow the stack
#: on the request path; past this depth the tree is unevaluatable, not deep.
_MAX_DEPTH = 32


# ---------------------------------------------------------------------------
# Control-configuration policies -- rows that were never matching rules
# ---------------------------------------------------------------------------
#
# MEASURED 2026-07-31, and it is the one shape that would otherwise be reported
# wrongly by everything above.
#
# The out-of-band verification attestation rule -- the control being sold into
# the SEC/FINRA broker-dealer pilot -- is stored as a policy row with
# ``conditions: None`` and its entire configuration in the legacy ``rules``
# blob (services/policy/attestation.py, ATTESTATION_RULE_TYPE). It is read by
# ``load_attestation_config``, which walks the LOADED POLICY LIST directly and
# never consults the match. Its conditions are absent because it is not a
# matching rule; it is a configuration carrier.
#
# Two things follow, and they point in opposite directions:
#
#   * Today that row MATCHES EVERY REQUEST (conditions is falsy -> the old
#     ``else`` branch assigned matched = True), with ``action: "warn"`` at
#     priority 10. So every request for a tenant with the control enabled
#     resolved to REQUIRE_APPROVAL / "policy_warn" on /policies/evaluate. The
#     flagship control's own row was carrying the blanket-match defect. The
#     guard in this module fixes that: it stops matching.
#
#   * But reporting it as ``policy.unevaluatable`` would be false. Nothing was
#     skipped -- there was no matching rule to skip -- and the report is stamped
#     EFFECT_NOT_ENFORCED, which sets ``x-cyberarmor-degraded: true`` on the
#     ext_authz health record. MEASURED: that turns every successfully cleared
#     payment for a pilot tenant into a degraded response, permanently. A
#     degradation signal that is always on is a degradation signal nobody reads,
#     which is this repository's tracked defect arriving by the back door.
#
# So these rows are EXCLUDED from matching and are not reported as broken. This
# is not a hole: excluded means it can never match, in either polarity, so
# stamping ``type: out_of_band_verification`` on a blob cannot manufacture a
# blanket allow or a blanket block. It is strictly narrower than today.
# The SECOND carrier class, found the same way -- by running the suite and
# reading the failure rather than by reasoning about it. ``scope:
# "url-trust-gate"`` policies keep their allow/block lists in ``rules`` and are
# merged by services/url-trust-gate/tenant_lists.py off
# ``GET /policies?scope=url-trust-gate``. They too have no ``conditions``, and
# they too are not blanket-matching today (their ``rules`` blob is non-empty, so
# the old code reached ``_evaluate_legacy_rules``, which returns False for a blob
# with no ``block_hosts``/``allow_hosts``). Rejecting them at the save gate would
# have taken the URL Trust Gate's only write path offline.
#: Scopes whose rows are owned by a DIFFERENT evaluator and are not condition-
#: matched by this service at all. The scope is the row's own declaration of who
#: enforces it, which is a stronger signal than guessing from its rules keys --
#: a URL Trust Gate row with an empty ``rules`` blob is still a URL Trust Gate
#: row, and it must not be rejected at the save gate for lacking conditions it
#: was never going to have.
CONTROL_SCOPES = frozenset({
    "url-trust-gate",       # services/url-trust-gate/tenant_lists.py
    "payment-authorization",  # attestation.ATTESTATION_SCOPE
})
CONTROL_RULE_TYPES = frozenset({"out_of_band_verification"})
CONTROL_RULE_KEYS = frozenset({
    # services/url-trust-gate/tenant_lists.py
    "allow_domains", "block_domains", "allow_urls", "block_urls",
    # PythonPolicyEngine._evaluate_legacy_rules
    "allow_hosts", "block_hosts",
})


def is_control_configuration(policy: Any) -> bool:
    """True when this policy row carries a control's config instead of a rule.

    NARROW BY CONSTRUCTION, AND IT CAN ONLY EVER REMOVE A MATCH. Callers consult
    this ONLY after ``classify_conditions`` has already said the conditions are
    unevaluatable, so a carrier blob sitting beside a perfectly good condition
    tree changes nothing: the tree is evaluated and the policy matches as before.
    All this decides is whether an unevaluatable-conditions row is *reported as
    broken* or recognised as a row that was never a matching rule.

    It is therefore not a bypass: no combination of keys here can manufacture a
    match, in either polarity.
    """
    if not isinstance(policy, dict):
        return False
    if policy.get("scope") in CONTROL_SCOPES:
        return True
    rules = policy.get("rules")
    if not isinstance(rules, dict) or not rules:
        return False
    if rules.get("type") in CONTROL_RULE_TYPES:
        return True
    # Kept alongside the scope check rather than replaced by it: attestation
    # rules are found by find_attestation_policy on rules.type ALONE, so a row
    # whose scope was left at "general" is still the tenant's live control.
    return any(key in CONTROL_RULE_KEYS for key in rules)


def classify_policy(policy: Any) -> Optional[Unevaluatable]:
    """THE single entry point every consumer uses. ``None`` == this row is fine.

    One implementation, called by the evaluator, the save gate, the read-side
    annotator, the OPA purge and the census, so those five can never drift into
    disagreeing about which rows are broken -- which is how the eleven
    evaluators in this product ended up with four different answers for
    ``conditions: null``.
    """
    if not isinstance(policy, dict):
        return Unevaluatable(REASON_NOT_AN_OBJECT, "policy is not an object")
    verdict = classify_conditions(policy.get("conditions"))
    if verdict is None:
        return None
    if is_control_configuration(policy):
        return None
    return verdict


class Unevaluatable(NamedTuple):
    """Why a condition tree expresses no evaluable constraint."""

    reason_code: str
    detail: str

    def as_problem_reason(self, policy_label: str) -> str:
        """The ``reason`` string recorded on the problems channel.

        Contains the policy name and the reason code, because both are asserted
        on: a bare code cannot be traced back to a row in a 200-policy tenant,
        and a bare sentence cannot be matched mechanically.
        """
        return (
            f"{policy_label or '?'}: {self.reason_code} -- {self.detail}; "
            "this policy did not run"
        )


class UnevaluatableConditions(Exception):
    """Raised by the evaluator when a condition node cannot be evaluated.

    A BACKSTOP, NOT THE PRIMARY GUARD. ``classify_conditions`` is consulted
    before evaluation begins, so in normal operation this never fires. It exists
    because the failure it guards against -- some future edit reintroducing a
    ``return True`` on an empty collection deep in the recursion -- is silent by
    construction, and a raise is the one outcome that cannot be mistaken for a
    match.
    """

    def __init__(self, verdict: Unevaluatable) -> None:
        super().__init__(f"{verdict.reason_code}: {verdict.detail}")
        self.verdict = verdict
        self.reason_code = verdict.reason_code
        self.detail = verdict.detail


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _describe(value: Any, limit: int = 120) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _classify_group(node: Any, path: str, depth: int) -> Optional[Unevaluatable]:
    if depth > _MAX_DEPTH:
        return Unevaluatable(
            REASON_NESTED_UNEVALUATABLE,
            f"condition tree nests deeper than {_MAX_DEPTH} groups at {path}",
        )

    if not isinstance(node, dict):
        return Unevaluatable(
            REASON_NOT_AN_OBJECT,
            f"{path} is {type(node).__name__} ({_describe(node)}), not a condition group",
        )

    operator = str(node.get("operator", "AND") or "AND").upper()
    rules = node.get("rules")

    # --- the explicit match-all -------------------------------------------
    if operator == ALWAYS_OPERATOR:
        # `rules` is ignored at evaluation time by design; a non-empty rules
        # array alongside ALWAYS is caught at SAVE time (see classify_for_save)
        # because there the author is present and can be told they meant AND/OR.
        return None

    # --- no usable rule list ----------------------------------------------
    if "rules" not in node:
        if "imported" in node:
            return Unevaluatable(
                REASON_IMPORTED_STUB,
                f"{path} is an import provenance marker "
                f"({_describe({k: v for k, v in node.items() if k != 'rules'})}), "
                "not a condition group; the imported source is stored in the "
                "policy's `rules` field and no evaluator reads it",
            )
        if "operator" in node:
            return Unevaluatable(
                REASON_RULES_MISSING,
                f"{path} has operator {operator!r} but no `rules` key",
            )
        unknown = sorted(str(k) for k in node.keys())
        return Unevaluatable(
            REASON_UNKNOWN_SCHEMA,
            f"{path} has no `rules` key; unrecognised key(s): "
            f"{', '.join(unknown) if unknown else '(none)'}. NOT auto-migrated: "
            "reinterpreting a foreign schema converts a loud wrong answer into a "
            "silent one",
        )

    if not isinstance(rules, list):
        return Unevaluatable(
            REASON_RULES_MISSING,
            f"{path}.rules is {type(rules).__name__} ({_describe(rules)}), not a list",
        )

    if not rules:
        # AND-of-nothing and OR-of-nothing are the SAME answer, deliberately.
        # Letting OR fall through to ``any([]) is False`` would be "correct" by
        # accident, silently, through a different code path -- and would make the
        # two shapes diverge across implementations depending on whether each
        # author deleted the early return or replaced it.
        return Unevaluatable(
            REASON_RULES_EMPTY,
            f"{path} is an empty rule group (operator {operator!r}, zero rules); "
            "an empty rule list expresses no constraint in AND or in OR",
        )

    if operator not in {"AND", "OR", "NOT"}:
        return Unevaluatable(
            REASON_UNKNOWN_OPERATOR,
            f"{path} has group operator {operator!r}, which is not one of "
            "AND / OR / NOT / ALWAYS; it is NOT degraded to AND",
        )

    for index, child in enumerate(rules):
        child_path = f"{path}.rules[{index}]"
        if isinstance(child, dict) and "rules" in child:
            nested = _classify_group(child, child_path, depth + 1)
            if nested is not None:
                # THE DEFECT PROPAGATES UP, it is not absorbed. An empty subgroup
                # under AND widens the parent; under OR it satisfies the parent
                # outright. Either way the author's stored intent is unknowable.
                return Unevaluatable(
                    REASON_NESTED_UNEVALUATABLE,
                    f"nested group is unevaluatable ({nested.reason_code}: {nested.detail})",
                )
            continue
        leaf = _classify_leaf(child, child_path)
        if leaf is not None:
            return leaf

    return None


def _classify_leaf(rule: Any, path: str) -> Optional[Unevaluatable]:
    if not isinstance(rule, dict):
        return Unevaluatable(
            REASON_NOT_AN_OBJECT,
            f"{path} is {type(rule).__name__} ({_describe(rule)}), not a rule object",
        )

    field_path = rule.get("field")
    if not isinstance(field_path, str) or not field_path.strip():
        # POLICY-LEVEL, not leaf-level. A leaf that returns False inside an OR is
        # silently absorbed and the policy still fires on its other leaves -- the
        # author would never learn that half their policy is dead. Same precedent
        # the file already sets for an uncompilable regex.
        return Unevaluatable(
            REASON_LEAF_NO_FIELD,
            f"{path} names no field ({_describe(rule)}); it would compare "
            "absent-to-absent and match every request",
        )

    operator = rule.get("operator", "equals")
    if not isinstance(operator, str) or operator not in LEAF_OPERATORS:
        return Unevaluatable(
            REASON_LEAF_UNKNOWN_OPERATOR,
            f"{path} uses operator {operator!r} on field {field_path!r}, which is "
            f"not in the published vocabulary ({', '.join(sorted(LEAF_OPERATORS))})",
        )

    return None


def classify_leaf_rule(rule: Any, path: str = "rule") -> Optional[Unevaluatable]:
    """Public entry point for one leaf. Same answer the tree walk uses.

    Exported so the evaluator's own leaf guard and this module's tree walk
    cannot drift apart: there is exactly one implementation of "is this leaf
    evaluable", and both callers reach it.
    """
    return _classify_leaf(rule, path)


def classify_conditions(conditions: Any) -> Optional[Unevaluatable]:
    """Return why ``conditions`` cannot be evaluated, or ``None`` if it can.

    ``None`` return means "this tree expresses at least one evaluable
    constraint". It does NOT mean the tree will match.
    """
    if conditions is None:
        return Unevaluatable(
            REASON_ABSENT,
            "conditions is absent. THE PREVIOUS CONTRACT IS REVOKED: "
            "rego/cyberarmor_base.rego documented `null = always matches`, which "
            "made an absence into an assertion. An absence is not an assertion",
        )
    if isinstance(conditions, str):
        text = conditions.strip()
        if not text:
            return Unevaluatable(
                REASON_ABSENT,
                "conditions is the empty string (MEASURED: this is the stored "
                "shape in the only local policy database on this host)",
            )
        return Unevaluatable(
            REASON_NOT_AN_OBJECT,
            f"conditions is a string ({_describe(conditions)}) -- most likely a "
            "JSON parse failure that _coerce_json_field returned verbatim",
        )
    if isinstance(conditions, (list, tuple)):
        if not conditions:
            return Unevaluatable(REASON_ABSENT, "conditions is an empty list")
        return Unevaluatable(
            REASON_NOT_AN_OBJECT,
            f"conditions is a list ({_describe(conditions)}), not a condition group",
        )
    if isinstance(conditions, dict) and not conditions:
        return Unevaluatable(REASON_ABSENT, "conditions is an empty object")
    if not isinstance(conditions, dict):
        return Unevaluatable(
            REASON_NOT_AN_OBJECT,
            f"conditions is {type(conditions).__name__} ({_describe(conditions)}), "
            "not a condition group",
        )
    return _classify_group(conditions, "conditions", 0)


def classify_for_save(conditions: Any) -> Optional[Unevaluatable]:
    """``classify_conditions`` plus the checks that only make sense at save time.

    At save time the author is present and can be told. ``ALWAYS`` carrying a
    non-empty ``rules`` array is the one shape that evaluates fine but almost
    certainly is not what was meant -- so it is a 422 here and a match at
    evaluation time (a stored row's intent is not re-litigated on the request
    path).
    """
    if isinstance(conditions, dict):
        operator = str(conditions.get("operator", "") or "").upper()
        rules = conditions.get("rules")
        if operator == ALWAYS_OPERATOR and isinstance(rules, list) and rules:
            return Unevaluatable(
                REASON_ALWAYS_WITH_RULES,
                "operator ALWAYS matches every request and ignores `rules`, but "
                f"{len(rules)} rule(s) were supplied -- did you mean AND or OR?",
            )
    return classify_conditions(conditions)


def is_match_all(conditions: Any) -> bool:
    """True for the one canonical explicit match-all spelling."""
    return (
        isinstance(conditions, dict)
        and str(conditions.get("operator", "") or "").upper() == ALWAYS_OPERATOR
    )


def unevaluatable_reasons(conditions: Any) -> List[str]:
    """Read-side annotator. ``[]`` means the row can fire; non-empty means it cannot.

    Deliberately computed on every read rather than stamped into a column: a
    persisted marker becomes a fourth thing that can drift out of date.
    """
    verdict = classify_conditions(conditions)
    return [] if verdict is None else [verdict.reason_code]


def unevaluatable_detail(conditions: Any) -> Optional[str]:
    verdict = classify_conditions(conditions)
    return None if verdict is None else verdict.detail


def is_enforceable(conditions: Any) -> bool:
    return classify_conditions(conditions) is None


def annotate(record: Dict[str, Any]) -> Dict[str, Any]:
    """Attach ``enforceable`` / ``unenforceable_reasons`` to a policy dict, in place.

    MARK, DO NOT MIGRATE. Rewriting stored ``conditions`` is forbidden without
    founder sign-off: the obvious "fix" for the ``{"any":[...]}`` demo seed --
    rename the key to ``OR`` -- was MEASURED to produce a policy that no longer
    matches the prompt-injection attack it was written for. That trades a loud
    wrong answer for a silent one.
    """
    # classify_policy, not classify_conditions: an attestation rule or a URL
    # Trust Gate list IS enforcing, just not by matching. Marking a working
    # control "NOT ENFORCING" on the dashboard would be the same lie as the
    # original defect, pointing the other way.
    verdict = classify_policy(record)
    record["enforceable"] = verdict is None
    record["unenforceable_reasons"] = [] if verdict is None else [verdict.reason_code]
    return record


def census(policies: List[Dict[str, Any]]) -> Tuple[int, Dict[str, int]]:
    """``(unevaluatable_count, {reason_code: count})`` over a list of policy dicts."""
    counts: Dict[str, int] = {}
    total = 0
    for policy in policies or []:
        if not isinstance(policy, dict):
            continue
        verdict = classify_policy(policy)
        if verdict is None:
            continue
        total += 1
        counts[verdict.reason_code] = counts.get(verdict.reason_code, 0) + 1
    return total, counts
