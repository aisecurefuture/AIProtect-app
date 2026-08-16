"""Extensible Policy Evaluation Engine with OPA backend.

Evaluation backends (tried in order):
  1. OPA  – calls the running OPA sidecar via ``opa_client.evaluate()``.
            OPA evaluates ``cyberarmor/policy/matches`` using the base Rego
            module, which receives the full tenant policy list as JSON input.
            Returns the list of matching policies sorted by priority.
  2. Python – fallback recursive AND/OR/NOT engine (always available).

The Python engine is authoritative when OPA is disabled or unreachable; no
functionality is lost, but OPA adds proper policy-as-code auditability and
the ability to load hand-authored Rego policies via ``POST /policies/import``.

Condition Schema (JSON, unchanged from v0.2):
{
    "operator": "AND" | "OR" | "NOT",
    "rules": [
        {"field": "request.url", "operator": "matches", "value": "*.openai.com/*"},
        {
            "operator": "OR",
            "rules": [
                {"field": "content.has_pii", "operator": "equals", "value": true},
                {"field": "content.classification", "operator": "in",
                 "value": ["confidential"]}
            ]
        }
    ]
}
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import opa_client  # local module
from conditions_guard import (
    MATCH_ALL_REASON,
    MATCH_ALL_RULE,
    PROBLEM_CHECK,
    REASON_NOT_AN_OBJECT,
    REASON_RULES_EMPTY,
    REASON_RULES_MISSING,
    REASON_UNKNOWN_OPERATOR,
    Unevaluatable,
    UnevaluatableConditions,
    classify_conditions,
    classify_leaf_rule as _classify_leaf_rule,
    is_control_configuration,
    is_match_all,
)
from policy_fields import domain_matches, normalize_host

logger = logging.getLogger("policy.engine")

OPA_ENABLED = os.getenv("OPA_ENABLED", "true").strip().lower() in {
    "1", "true", "yes", "on"
}


# ---------------------------------------------------------------------------
# Uncompilable patterns
# ---------------------------------------------------------------------------
#
# A rule whose regular expression will not compile DID NOT RUN. It is neither a
# match nor a non-match, and encoding it as either is the "dishonest health"
# defect this repo tracks: `return False` reads as "rule cleared" and therefore
# as an allow.
#
# The engine's job here is only to (a) stop the exception escaping into the
# request path and (b) hand the caller a record of what did not run. What the
# caller does with that record -- header, log, alert -- is the caller's.


class PatternCompileError(Exception):
    """A rule's regular expression could not be compiled, so the rule did not run.

    Raised by :meth:`PythonPolicyEngine._compare` and caught by
    :meth:`PythonPolicyEngine._evaluate_leaf_rule`, which records it in the
    caller's ``problems`` list. It is deliberately NOT a ``ValueError``: the
    ``except (TypeError, ValueError)`` in ``_compare`` exists to turn genuine
    type mismatches into "no match", and a pattern that cannot compile must not
    be quietly folded into that.
    """

    def __init__(self, pattern: str, detail: str) -> None:
        super().__init__(f"pattern {pattern!r} is not a valid regular expression: {detail}")
        self.pattern = pattern
        self.detail = detail


def _try_compile(pattern: str):
    """Return ``(compiled, None)`` or ``(None, error_message)``.

    ``re.error`` (aliased ``re.PatternError`` since 3.13) subclasses neither
    ``TypeError`` nor ``ValueError``, which is why the narrow except in
    ``_compare`` never caught it.
    """
    try:
        return re.compile(pattern), None
    except re.error as exc:
        return None, str(exc)


#: The one field whose comparison is derived rather than looked up. Named as a
#: constant so the evaluator, the DNR-equivalent guards and the registry all
#: spell it the same way.
DOMAIN_FIELD = "request.domain"

#: Operators whose ordinary Python semantics turn an ABSENT field into a match.
#: ``None not in [...]`` is True, ``None != "x"`` is True, and a rule that never
#: compared anything then reads as a rule that matched.
#:
#: On 2026-07-31 that put "[ISO27001] Block Unapproved AI Providers"
#: (``route.destination not_in $artifact:approved_providers``) at action=block
#: on a live tenant. ``route`` is not an ``EvaluationContext`` section, so the
#: value was always None, so the rule matched every request -- ordinary non-AI
#: browsing included -- and shadowed every policy beneath it.
#:
#: The browser engine has guarded this since it was written
#: (``background.js`` evaluateLeafRule, with a comment naming this exact
#: template) and so has the endpoint agent's port
#: (``cyberarmor_policy_client.py``). This is that guard, ported. The three
#: engines must agree, so the operator set and the returned verdict are
#: deliberately identical to theirs: an absent field makes the leaf
#: INAPPLICABLE (no match), never a vacuous match.
#:
#: ``not_exists`` is correctly absent from this set -- it is ABOUT absence.
NEGATIVE_OPERATORS_NEEDING_A_VALUE = frozenset({
    "not_equals",
    "not_contains",
    "not_in",
})


def _policies_using_derived_field(policies: List[dict]) -> List[str]:
    """Names of policies containing a ``request.domain`` leaf rule."""
    found: List[str] = []

    def walk(node) -> bool:
        if isinstance(node, dict):
            if node.get("field") == DOMAIN_FIELD:
                return True
            return any(walk(sub) for sub in (node.get("rules") or []))
        if isinstance(node, list):
            return any(walk(sub) for sub in node)
        return False

    for policy in policies or []:
        if isinstance(policy, dict) and walk(policy.get("conditions")):
            found.append(str(policy.get("name") or policy.get("id") or "?"))
    return found


def _record_opa_derived_field_gap(
    policies: List[dict], problems: Optional[List[dict]]
) -> None:
    """Say out loud that a request.domain rule did not run on the OPA backend.

    KNOWN GAP, DELIBERATELY REPORTED RATHER THAN PAPERED OVER.

    ``request.domain`` is DERIVED: there is no ``request.domain`` key in the
    flattened context, and the matching semantics (exact-or-dot-boundary) live
    in this module's ``_evaluate_domain_rule``. The base Rego module does a flat
    ``ctx[rule.field]`` lookup (rego/cyberarmor_base.rego), so on a deployment
    where OPA is reachable -- OPA_ENABLED defaults to "true" and
    infra/docker-compose/docker-compose.yml sets it "true" -- a Domain rule
    finds nothing and silently never matches.

    That is the founder's original bug, surviving on one backend. It is NOT
    fixed here: teaching Rego domain semantics is a change to policy-as-code
    that cannot be verified on a host with no ``opa`` binary, and shipping an
    unverified Rego rewrite would be a claim rather than a control. What IS done
    is refuse to let it be silent -- the skipped rule is recorded through the
    same channel an uncompilable regex uses, so it surfaces in the ext_authz
    problems header and in the logs instead of reading as "checked and cleared".
    """
    affected = _policies_using_derived_field(policies)
    if not affected:
        return
    logger.warning(
        "policy_domain_rule_not_evaluated_on_opa policies=%s", ",".join(affected)
    )
    _record_problem(
        problems,
        "policy.rule_domain_backend",
        f"{len(affected)} policy(ies) use {DOMAIN_FIELD} but this request was decided by "
        f"the OPA backend, whose Rego module cannot evaluate a derived field; "
        f"those rules did not run ({', '.join(affected[:5])})",
    )


def _record_problem(problems: Optional[List[dict]], check: str, reason: str) -> None:
    """Append one ``{check, reason}`` entry if the caller supplied a list.

    ``problems`` is an out-parameter, not engine state: the engines are module
    singletons, so anything accumulated on them would leak across requests. A
    caller that passes nothing gets today's behaviour minus the crash, and no
    record -- which is why ``main.py`` passes a per-request list.
    """
    if problems is None:
        return
    problems.append({"check": check, "reason": reason})

# ---------------------------------------------------------------------------
# Shared data types
# ---------------------------------------------------------------------------


@dataclass
class PolicyEvalResult:
    """Result of evaluating a single policy against a context."""

    matched: bool
    policy_id: str
    policy_name: str
    action: str          # allow | monitor | warn | redact | block (general)
                          # url-trust-gate also: sandbox | isolate
    reason: str = ""
    matched_rules: List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)
    # Path B: list of DLP class names this policy wants redacted on match.
    # Empty when action != "redact" or when the author left it blank.
    redact_classes: List[str] = field(default_factory=list)


@dataclass
class EvaluationContext:
    """Context object passed through policy evaluation.

    Fields are accessed via dot notation in policy conditions:
        "request.url"        → context.request["url"]
        "content.has_pii"    → context.content["has_pii"]
        "user.department"    → context.user["department"]
    """

    request: Dict[str, Any] = field(default_factory=dict)
    content: Dict[str, Any] = field(default_factory=dict)
    user: Dict[str, Any] = field(default_factory=dict)
    endpoint: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # --- sections that exist so their namespaces can EVER be evaluated -------
    #
    # `identity`, `event` and `response` are in shared/policy-fields.json and
    # authorable in the Builder, and until now the flattener did not include
    # them -- so a rule on identity.user_id or response.pii could not resolve
    # even if a caller supplied the data. Five registry fields resolved on
    # nothing at all for that reason.
    #
    # ADDING THE SECTION IS NECESSARY BUT NOT SUFFICIENT. A field only truly
    # resolves once some enforcement path POPULATES it.
    #
    #   * response.* -- CORRECTION, 2026-07-31. An earlier version of this
    #     comment said "no response-side evaluation exists anywhere... the
    #     response has not been generated yet", and that was wrong in a way that
    #     misdirected the fix. Post-response hooks DO exist and DO enforce:
    #     services/proxy/transparent_proxy.py `response()` -> `_inspect_response()`
    #     is the only registered mitmproxy addon, holds the fully decoded body,
    #     calls detection /scan with direction="response", and REPLACES the
    #     response on a block. agents/endpoint-agent/local_proxy has the same
    #     shape. It also already extracts citation URLs from the answer and runs
    #     them through the URL Trust Gate. What is missing is not a hook -- it is
    #     that neither proxy calls the policy engine from its RESPONSE path, so
    #     every response decision today comes from detection's platform-wide
    #     threshold constants and no tenant can author a rule.
    #   * event.*    -- emitted by the shipped compliance packs and read by
    #     nothing. These describe an audited event after the fact, which is a
    #     different evaluation moment from inline enforcement.
    #   * identity.user_id -- emitted by the Proxy Controls User box in both
    #     portals. Needs an AUTHENTICATED producer: taking it from a request
    #     header would let the caller assert its own identity, which is the
    #     same trap as trusting a client-supplied content-type on the payment
    #     path.
    #
    # `resolves_on` in shared/policy-fields.json is therefore deliberately NOT
    # updated here. That list is a CLAIM about what reads a field, and marking
    # these resolved before a producer exists would be the defect this repo
    # tracks -- an affirmative statement that a rule is enforceable behind one
    # that still cannot fire. The conformance test stays red on purpose until
    # a real producer lands.
    identity: Dict[str, Any] = field(default_factory=dict)
    event: Dict[str, Any] = field(default_factory=dict)
    response: Dict[str, Any] = field(default_factory=dict)

    def to_flat_dict(self) -> Dict[str, Any]:
        """Flatten to a single dict with dot-notation keys for rule evaluation."""
        result: Dict[str, Any] = {}
        for prefix, section in [
            ("request",  self.request),
            ("content",  self.content),
            ("user",     self.user),
            ("identity", self.identity),
            ("event",    self.event),
            ("response", self.response),
            ("endpoint", self.endpoint),
            ("metadata", self.metadata),
        ]:
            if isinstance(section, dict):
                for k, v in section.items():
                    result[f"{prefix}.{k}"] = v
        return result


# ---------------------------------------------------------------------------
# OPA evaluation backend
# ---------------------------------------------------------------------------


class OPABackend:
    """Evaluates policies by forwarding the full policy list + context to OPA.

    OPA runs the ``cyberarmor/policy/matches`` rule from the base Rego module
    and returns all matching policies sorted by priority (ascending).
    """

    _RULE_PATH = "cyberarmor/policy/matches"

    def evaluate(
        self, policies: List[dict], context: EvaluationContext
    ) -> Optional[List[PolicyEvalResult]]:
        """Return sorted matching results from OPA, or None if OPA is unavailable."""
        if not OPA_ENABLED or not opa_client.is_available():
            return None

        input_data = {
            "policies": policies,
            "context": context.to_flat_dict(),
        }
        try:
            raw = opa_client.evaluate(self._RULE_PATH, input_data)
        except Exception as exc:
            logger.warning("OPA evaluation failed: %s", exc)
            return None

        if raw is None:
            return None

        # raw is the value of the ``matches`` rule – a list of match objects
        if not isinstance(raw, list):
            logger.warning("OPA returned unexpected type for matches: %s", type(raw))
            return None

        # Build a lookup so we can fall back to DB-source fields when OPA's
        # compiled module doesn't emit them (older Rego compilers, custom
        # imported policies, etc). This is defense-in-depth — without it,
        # any field added to the policy schema after the Rego compiler last
        # shipped is silently lost on the OPA path.
        by_id: Dict[str, dict] = {p.get("id"): p for p in policies if isinstance(p, dict)}

        results: List[PolicyEvalResult] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            pid = str(item.get("policy_id", ""))
            src = by_id.get(pid) or {}
            results.append(
                PolicyEvalResult(
                    matched=True,
                    policy_id=pid,
                    policy_name=str(item.get("policy_name", "") or src.get("name", "")),
                    action=str(item.get("action") or src.get("action") or "monitor"),
                    reason="opa_match",
                    matched_rules=[],
                    compliance_frameworks=list(
                        item.get("compliance_frameworks")
                        or src.get("compliance_frameworks")
                        or []
                    ),
                    redact_classes=list(
                        item.get("redact_classes")
                        or src.get("redact_classes")
                        or []
                    ),
                )
            )

        # OPA's base module already sorts by priority; re-sort here for safety
        results.sort(key=lambda r: next(
            (p.get("priority", 100) for p in policies if p.get("id") == r.policy_id),
            100,
        ))
        return results

    def evaluate_first_match(
        self, policies: List[dict], context: EvaluationContext
    ) -> Optional[PolicyEvalResult]:
        results = self.evaluate(policies, context)
        if results is None:
            return None  # OPA unavailable – signal fallback needed
        return results[0] if results else None


# ---------------------------------------------------------------------------
# Python evaluation backend  (always-available fallback)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Action vocabulary -- KEEP IN AGREEMENT WITH
# extensions/chromium-shared/background.js `_ACTION_SEVERITY`.
#
# The server used to have no such table. Its decision normalizer handled four
# actions (block, warn, monitor, redact) and sent everything else to
# `else: decision = "ALLOW"; reason = "policy_allow"`. The browser ranked ten.
# So six actions -- block_upload, isolate, sandbox, audit-only, route, and any
# typo -- enforced in Chrome and FAILED OPEN on the endpoint agent, the
# transparent proxy and Envoy ext_authz, while reporting a reason that claimed
# a policy had deliberately permitted the request.
#
# Parity is asserted by
# services/policy/tests/test_action_surface_applicability.py, which reads the
# browser table out of background.js rather than restating it -- a second copy
# of a list is a second thing to drift.
ACTION_SEVERITY: Dict[str, int] = {
    "block": 6,
    "block_upload": 5,
    "isolate": 5,
    "sandbox": 4,
    "redact": 3,
    "warn": 2,
    "monitor": 1,
    "allow": 0,
    "audit-only": 0,
    "route": 0,
}

# Which surfaces an action can actually ACT on. An action absent from this map
# applies everywhere, which is the safe default because it preserves existing
# behaviour. Only actions with a dedicated consumer that is ignored elsewhere
# belong here.
ACTION_SURFACES: Dict[str, frozenset] = {
    "block_upload": frozenset({"upload"}),
}

_SURFACE_KEY = "type"


def _action_applies_to_surface(
    policy: dict,
    context: "EvaluationContext",
    problems: Optional[List[dict]] = None,
) -> bool:
    """Can this policy's action do anything on the surface that asked?

    Diverges DELIBERATELY from the browser on one case. background.js treats an
    absent ``request.type`` as "applies", reasoning that an unclassified caller
    is a gap in the map rather than a fact about the policy, and that a
    wrongly-dropped enforcement action is worse than a wrongly-kept one. That
    holds there because Chrome HAS an upload-enforcement path.

    Here it does not. No server-side caller sends ``request.type`` at all --
    only tests do -- and there is no upload-specific enforcement anywhere on
    the server. Treating absent as "applies" would mean block_upload keeps
    deciding every request, which is the production defect verbatim. So an
    unlabelled caller drops the action AND records a problem, rather than
    choosing silently between two wrong answers.
    """
    action = str(policy.get("action", "") or "")
    surfaces = ACTION_SURFACES.get(action)
    if surfaces is None:
        return True

    surface = None
    request = getattr(context, "request", None)
    if isinstance(request, dict):
        surface = request.get(_SURFACE_KEY)

    if surface and str(surface) in surfaces:
        return True

    label = policy.get("name", "") or policy.get("id", "") or "?"
    if surface:
        detail = (
            f"policy {label!r} has action {action!r}, which only applies on "
            f"{sorted(surfaces)}; this request is {str(surface)!r}. Skipped so a "
            "policy that can act on this surface decides instead."
        )
    else:
        detail = (
            f"policy {label!r} has action {action!r}, which only applies on "
            f"{sorted(surfaces)}, and this caller sent no request.{_SURFACE_KEY}. "
            "Skipped rather than allowed. The caller should label its surface."
        )
    logger.warning(
        "policy_action_surface_skip policy_name=%s action=%s surface=%s",
        label, action, surface or "<unset>",
    )
    _record_problem(problems, PROBLEM_CHECK, detail)
    return False


class PythonPolicyEngine:
    """Pure-Python recursive AND/OR/NOT condition evaluator.

    This is the original PolicyEngine implementation, kept as a complete
    fallback that requires no external dependencies.
    """

    def evaluate(
        self,
        policies: List[dict],
        context: EvaluationContext,
        problems: Optional[List[dict]] = None,
    ) -> List[PolicyEvalResult]:
        flat = context.to_flat_dict()
        results: List[PolicyEvalResult] = []
        sorted_policies = sorted(policies, key=lambda p: p.get("priority", 100))

        for policy in sorted_policies:
            if not policy.get("enabled", True):
                continue

            # SURFACE APPLICABILITY, consulted before conditions.
            #
            # An action only decides a surface that can enforce it. block_upload
            # is meaningless on a prompt or a navigation -- nothing there can
            # block an upload -- so it must not participate in the decision.
            #
            # Measured in production 2026-07-31: `block-upload-to-chatgpt` won
            # every request on the founder's tenant and the normalizer turned
            # block_upload into ALLOW, shadowing `redact pii in content` at
            # priority 100. Dropping it here is what lets the next policy win.
            #
            # DROPPED, NOT DOWNGRADED. Returning a match with a softer action
            # would be the silent downgrade this repo already banned for redact
            # ("enforced as BLOCK where text cannot be rewritten, never a
            # warning"). Skipping is reported through the same problems channel
            # an unevaluatable row uses, so it is visible rather than absent.
            if not _action_applies_to_surface(policy, context, problems):
                continue

            conditions = policy.get("conditions")
            label = policy.get("name", "") or policy.get("id", "")

            # THE GUARD. Consulted BEFORE any evaluation, so an unevaluatable
            # policy never reaches a code path that could return True.
            #
            # It replaces three separate fail-open sites that all lived in this
            # function's blast radius:
            #   1. `if conditions:` -- a truthiness test, so None and {} fell to
            #      an else-branch that assigned matched = True outright.
            #   2. _evaluate_condition_group's `if not rules: return True, []`.
            #   3. an empty leaf {} defaulting its way to equals(None, None).
            verdict = classify_conditions(conditions)
            if verdict is not None:
                # It does not match either way -- the only question is whether
                # this is a BROKEN row or a row that was never a matching rule.
                #
                # Control-configuration rows (the attestation rule; a URL Trust
                # Gate allow/block list) carry their behaviour in the legacy
                # `rules` blob and are read by their own loaders. They have no
                # conditions because they were never meant to match -- and until
                # this guard existed the attestation rule MATCHED EVERY REQUEST
                # with action="warn", so the blanket-match defect was sitting on
                # the flagship control itself.
                #
                # Reported for a broken row; recognised silently for a carrier,
                # because a carrier skipped nothing. The distinction earns its
                # keep: `problems` is stamped EFFECT_NOT_ENFORCED into the
                # ext_authz health record, and MEASURED, reporting carriers there
                # marks every successfully cleared payment degraded, forever. A
                # degradation signal that is always on is one nobody reads.
                if is_control_configuration(policy):
                    logger.debug(
                        "policy_is_control_configuration policy=%s rules_keys=%s",
                        label or "?", sorted((policy.get("rules") or {}).keys()),
                    )
                    continue
                self._report_unevaluatable(policy, verdict, problems)
                continue

            try:
                if is_match_all(conditions):
                    # The explicit match-all. Its audit artifact is deliberately
                    # a POSITIVE one: a caller can tell "the author asked for
                    # every request" from "the engine matched nothing and said
                    # so anyway", which is the distinction the defect erased.
                    matched, matched_rules = True, [MATCH_ALL_RULE]
                    reason = MATCH_ALL_REASON
                else:
                    matched, matched_rules = self._evaluate_condition_group(
                        conditions, flat, problems, label
                    )
                    reason = self._match_reason(matched_rules)
            except UnevaluatableConditions as exc:
                # Backstop. classify_conditions already walked this tree, so
                # reaching here means the two disagreed -- a bug in this module,
                # not in the tenant's data. Reported through the same channel and
                # the policy is still skipped: the one thing that must never
                # happen is a disagreement resolving to "match".
                logger.error(
                    "policy_conditions_guard_disagreement policy=%s reason_code=%s detail=%s",
                    label or "?", exc.reason_code, exc.detail,
                )
                self._report_unevaluatable(policy, exc.verdict, problems)
                continue

            if matched:
                results.append(
                    PolicyEvalResult(
                        matched=True,
                        policy_id=policy.get("id", ""),
                        policy_name=policy.get("name", ""),
                        action=policy.get("action", "monitor"),
                        reason=reason,
                        matched_rules=matched_rules,
                        compliance_frameworks=policy.get("compliance_frameworks") or [],
                        redact_classes=policy.get("redact_classes") or [],
                    )
                )

        return results

    @staticmethod
    def _match_reason(matched_rules: List[str]) -> str:
        """Describe a match without ever claiming zero rules were matched.

        The zero-count phrasing is the defect's fingerprint -- it is what the
        engine wrote into the audit record while authorising traffic that no rule
        had examined. It stays reachable after the fix through a satisfied
        ``NOT`` group, which legitimately names no matching rule, so the honest
        case gets its own words rather than borrowing the dishonest one's. A
        verifier greps the source for that phrasing; it must not appear.
        """
        if matched_rules:
            return f"Matched {len(matched_rules)} rule(s)"
        return "matched: NOT group satisfied (no rule to name)"

    @staticmethod
    def _report_unevaluatable(
        policy: dict,
        verdict: Unevaluatable,
        problems: Optional[List[dict]],
    ) -> None:
        """Skip loudly. All four channels start here.

        A silent skip is the same defect wearing the opposite sign: the founder's
        complaint was not only that nothing was enforced, it was that the
        dashboard showed the policies as active while nothing was enforced.
        """
        label = policy.get("name", "") or policy.get("id", "") or "?"
        logger.warning(
            "policy_unevaluatable_conditions tenant_id=%s policy_id=%s policy_name=%s "
            "action=%s priority=%s reason_code=%s detail=%s",
            policy.get("tenant_id", "") or "?",
            policy.get("id", "") or "?",
            label,
            policy.get("action", "") or "?",
            policy.get("priority", ""),
            verdict.reason_code,
            verdict.detail,
        )
        _record_problem(problems, PROBLEM_CHECK, verdict.as_problem_reason(label))

    def evaluate_first_match(
        self,
        policies: List[dict],
        context: EvaluationContext,
        problems: Optional[List[dict]] = None,
    ) -> Optional[PolicyEvalResult]:
        results = self.evaluate(policies, context, problems)
        return results[0] if results else None

    # ------------------------------------------------------------------
    # Condition evaluation
    # ------------------------------------------------------------------

    def _evaluate_condition_group(
        self,
        conditions: dict,
        flat_context: dict,
        problems: Optional[List[dict]] = None,
        policy_label: str = "",
    ) -> tuple[bool, list[str]]:
        if not isinstance(conditions, dict):
            raise UnevaluatableConditions(Unevaluatable(
                REASON_NOT_AN_OBJECT,
                f"condition group is {type(conditions).__name__}, not an object",
            ))

        operator = str(conditions.get("operator", "AND") or "AND").upper()

        # The explicit match-all, valid as a nested subgroup too.
        if is_match_all(conditions):
            return True, [MATCH_ALL_RULE]

        # WAS: `rules = conditions.get("rules", [])` followed by
        #      `if not rules: return True, []`.
        #
        # That default turned "this schema has no rules key" ({"imported":true},
        # {"any":[...]}, {"operator":"AND"}) into the same value as "this group
        # was emptied" ({"operator":"AND","rules":[]}), and then answered both
        # with MATCH -- before `operator` was consulted at all, which is why
        # AND-of-nothing and OR-of-nothing were indistinguishable.
        #
        # These raise rather than return False. Returning False would read as
        # "rule checked, did not match", i.e. an allow, which is the silent skip
        # this whole change exists to remove.
        if "rules" not in conditions:
            raise UnevaluatableConditions(Unevaluatable(
                REASON_RULES_MISSING,
                f"condition group with operator {operator!r} has no `rules` key",
            ))
        rules = conditions.get("rules")
        if not isinstance(rules, list):
            raise UnevaluatableConditions(Unevaluatable(
                REASON_RULES_MISSING,
                f"`rules` is {type(rules).__name__}, not a list",
            ))
        if not rules:
            raise UnevaluatableConditions(Unevaluatable(
                REASON_RULES_EMPTY,
                f"empty rule group (operator {operator!r}, zero rules)",
            ))
        if operator not in {"AND", "OR", "NOT"}:
            # No silent degrade to AND. An unrecognised operator with a real rule
            # list used to fall through this function's final `else` to
            # `all(results)`; a future ALWAYS-aware author reading that would
            # never learn their group operator was ignored.
            raise UnevaluatableConditions(Unevaluatable(
                REASON_UNKNOWN_OPERATOR,
                f"group operator {operator!r} is not AND / OR / NOT / ALWAYS",
            ))

        all_matched_rules: List[str] = []
        results: List[bool] = []

        for rule in rules:
            if not isinstance(rule, dict):
                # `"rules" in rule` used to raise TypeError on a non-dict entry,
                # and on the ext_authz path an escaping exception meets
                # envoy.yaml's failure_mode_allow -- i.e. it allows everything.
                raise UnevaluatableConditions(Unevaluatable(
                    REASON_NOT_AN_OBJECT,
                    f"rule entry is {type(rule).__name__}, not an object",
                ))
            if "rules" in rule:
                matched, sub_rules = self._evaluate_condition_group(
                    rule, flat_context, problems, policy_label
                )
                results.append(matched)
                if matched:
                    all_matched_rules.extend(sub_rules)
            else:
                matched = self._evaluate_leaf_rule(
                    rule, flat_context, problems, policy_label
                )
                results.append(matched)
                if matched:
                    all_matched_rules.append(
                        f"{rule.get('field', '?')} "
                        f"{rule.get('operator', '?')} "
                        f"{rule.get('value', '?')}"
                    )

        if operator == "AND":
            group_matched = all(results)
        elif operator == "OR":
            group_matched = any(results)
        elif operator == "NOT":
            group_matched = not any(results)
        else:  # pragma: no cover - the operator was validated above
            raise UnevaluatableConditions(Unevaluatable(
                REASON_UNKNOWN_OPERATOR,
                f"group operator {operator!r} reached the dispatch unvalidated",
            ))

        return group_matched, all_matched_rules if group_matched else []

    def _evaluate_leaf_rule(
        self,
        rule: dict,
        flat_context: dict,
        problems: Optional[List[dict]] = None,
        policy_label: str = "",
    ) -> bool:
        field_path = rule.get("field", "")
        operator = rule.get("operator", "equals")
        expected = rule.get("value")

        # SHAPE G, and it reaches here by a DIFFERENT mechanism than the empty
        # group above: a leaf `{}` defaults its way to operator "equals", looks
        # up the empty-string key (never present, so None) and compares it to an
        # absent `value` (also None). Two absences compare equal, so the rule
        # matched every request. Fail-open by default value, not by empty
        # collection, so the empty-group guard does not cover it.
        leaf_verdict = _classify_leaf_rule(rule, "rule")
        if leaf_verdict is not None:
            raise UnevaluatableConditions(leaf_verdict)

        if field_path == DOMAIN_FIELD:
            return self._evaluate_domain_rule(
                operator, expected, flat_context, problems, policy_label
            )

        actual = flat_context.get(field_path)

        # An absent field is not "not equal to", "not containing" or "not in"
        # anything. Comparing against it did not run a check, so it must not
        # produce a match -- see NEGATIVE_OPERATORS_NEEDING_A_VALUE.
        #
        # Returning False alone would only move the failure from loud to quiet,
        # which is the trade this codebase keeps losing. So the leaf is ALSO
        # recorded: "did not run" must never be indistinguishable from
        # "checked and cleared", the same treatment PatternCompileError gets
        # twenty lines below.
        if actual is None and operator in NEGATIVE_OPERATORS_NEEDING_A_VALUE:
            logger.warning(
                "policy_rule_field_absent policy=%s field=%s operator=%s",
                policy_label or "?", field_path or "?", operator,
            )
            _record_problem(
                problems,
                "policy.rule_field_absent",
                f"policy '{policy_label or '?'}' tests "
                f"'{field_path or '?'}' with '{operator}', but no producer on "
                f"this surface populates that field; the rule did not run "
                f"(it would otherwise have matched every request)",
            )
            return False

        try:
            return self._compare(actual, operator, expected)
        except PatternCompileError as exc:
            # This leaf did not run. It is reported as non-matching so the rest
            # of the policy set still evaluates, and it is RECORDED so that
            # "non-matching" is never mistaken for "checked and cleared".
            # Caught here and nowhere else: if this escapes, the original
            # fail-open returns under a new name.
            logger.warning(
                "policy_rule_pattern_uncompilable policy=%s field=%s detail=%s",
                policy_label or "?", field_path or "?", exc.detail,
            )
            _record_problem(
                problems,
                "policy.rule_pattern",
                f"policy '{policy_label or '?'}' rule on field "
                f"'{field_path or '?'}' has an invalid regular expression "
                f"({exc.detail}); this rule did not run",
            )
            return False

    # ------------------------------------------------------------------
    # request.domain
    # ------------------------------------------------------------------

    def _evaluate_domain_rule(
        self,
        operator: str,
        expected: Any,
        flat_context: dict,
        problems: Optional[List[dict]] = None,
        policy_label: str = "",
    ) -> bool:
        """Match ``request.domain`` as the domain AND everything under it.

        FOUNDER DECISION 2026-07-30, binding: request.domain is a first-class
        evaluable field with subdomain semantics and is NOT an alias of
        request.hostname, which stays exact. Both fields are real.

            chatgpt.com  MATCHES      chatgpt.com, www.chatgpt.com, api.chatgpt.com
            chatgpt.com  DOES NOT     notchatgpt.com, evil-chatgpt.com,
                                      chatgpt.com.evil.test

        DERIVED, NOT CARRIED. No producer writes a `domain` key; the comparison
        is taken from the host value each producer already puts on the wire.
        request.domain is not a different VALUE from the host, it is a different
        way of COMPARING to it, so the semantics belong in the operator and not
        in ten context builders that can each forget to populate one more key --
        which is the precise failure mode this whole change exists to remove.

        THE HOST IS NORMALISED HERE AND ONLY HERE. main.py reads the Host /
        x-forwarded-host header verbatim, so `Host: ChatGPT.com` and
        `Host: chatgpt.com:443` would otherwise turn an enforcing rule into a
        no-match at the choice of the party the rule governs. `request.host`
        itself is deliberately left untouched so no existing rule changes
        meaning.

        A MALFORMED VALUE DID NOT RUN, AND SAYS SO. ``domain_matches`` returns
        None for a value that is not a usable domain (a single label such as
        "com", a pasted URL, a wildcard). Returning False alone would make
        "this rule could not be evaluated" and "this rule was checked and
        passed" the same observable -- the defect class this repo tracks -- so
        the skip is recorded through the same ``problems`` channel an
        uncompilable regex uses.
        """
        host = self._derive_host(flat_context)

        if operator == "exists":
            return bool(host)
        if operator == "not_exists":
            return not host

        candidates = expected if isinstance(expected, list) else [expected]
        if operator not in {"equals", "not_equals", "in", "not_in"}:
            _record_problem(
                problems,
                "policy.rule_domain_operator",
                f"policy '{policy_label or '?'}' uses operator '{operator}' on "
                f"{DOMAIN_FIELD}, which only supports equals/not_equals/in/not_in/"
                f"exists/not_exists; this rule did not run",
            )
            return False

        matches: List[bool] = []
        for candidate in candidates:
            verdict = domain_matches(candidate, host)
            if verdict is None:
                logger.warning(
                    "policy_rule_domain_value_unusable policy=%s value=%r",
                    policy_label or "?", candidate,
                )
                _record_problem(
                    problems,
                    "policy.rule_domain_value",
                    f"policy '{policy_label or '?'}' has a {DOMAIN_FIELD} rule whose "
                    f"value {str(candidate)!r} is not a usable domain (a domain needs "
                    f"at least two dot-separated labels; a single label such as 'com' "
                    f"would cover every host under that suffix); this rule did not run",
                )
                continue
            matches.append(verdict)

        if not matches:
            # Every authored value was unusable, so nothing was actually
            # compared. Non-matching, and recorded above as not-run.
            return False

        if operator in {"equals", "in"}:
            return any(matches)
        return not any(matches)

    @staticmethod
    def _derive_host(flat_context: dict) -> str:
        """The host this request is for, from whichever key the producer wrote.

        ``request.host`` is what all three server producers set (ext_authz from
        the Host header, the proxy and runtime services from the parsed URL).
        ``request.hostname`` is accepted because /policies/evaluate takes a
        caller-supplied context and an agent may send that shape.
        ``request.url`` is the last resort.
        """
        for key in ("request.domain", "request.host", "request.hostname"):
            value = flat_context.get(key)
            if value:
                host = normalize_host(value)
                if host:
                    return host
        url = flat_context.get("request.url")
        if url and "://" in str(url):
            return normalize_host(url)
        return ""

    def _compare(self, actual: Any, operator: str, expected: Any) -> bool:
        """Evaluate one leaf comparison.

        Raises :class:`PatternCompileError` when ``operator == "regex"`` and the
        pattern will not compile. It is NOT folded into the ``except (TypeError,
        ValueError): return False`` below, because ``return False`` means "rule
        did not match" means allow -- the silent skip that is the defect.
        """
        try:
            if operator == "equals":
                return actual == expected
            elif operator == "not_equals":
                return actual != expected
            elif operator == "contains":
                return str(expected) in str(actual) if actual is not None else False
            elif operator == "not_contains":
                return str(expected) not in str(actual) if actual is not None else True
            elif operator == "starts_with":
                return str(actual or "").startswith(str(expected))
            elif operator == "ends_with":
                return str(actual or "").endswith(str(expected))
            elif operator == "matches":
                return fnmatch.fnmatch(str(actual or ""), str(expected))
            elif operator == "regex":
                compiled, err = _try_compile(str(expected))
                if compiled is None:
                    raise PatternCompileError(str(expected), str(err))
                return bool(compiled.search(str(actual or "")))
            elif operator == "in":
                return actual in expected if isinstance(expected, list) else actual == expected
            elif operator == "not_in":
                return actual not in expected if isinstance(expected, list) else actual != expected
            elif operator == "greater_than":
                return float(actual) > float(expected)
            elif operator == "less_than":
                return float(actual) < float(expected)
            elif operator == "greater_than_or_equals":
                return float(actual) >= float(expected)
            elif operator == "less_than_or_equals":
                return float(actual) <= float(expected)
            elif operator == "exists":
                return actual is not None
            elif operator == "not_exists":
                return actual is None
            elif operator == "is_empty":
                return actual is None or actual == "" or actual == []
            elif operator == "is_not_empty":
                return actual is not None and actual != "" and actual != []
        except (TypeError, ValueError):
            return False
        return False

    def _evaluate_legacy_rules(self, rules: dict, flat_context: dict) -> bool:
        url = flat_context.get("request.url", "")
        blocked_hosts = rules.get("block_hosts", [])
        for host in blocked_hosts:
            if host in url:
                return True
        allowed_hosts = rules.get("allow_hosts", [])
        if allowed_hosts:
            for host in allowed_hosts:
                if host in url:
                    return False
            return True
        return False


# ---------------------------------------------------------------------------
# Unified facade  (OPA with Python fallback)
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Unified policy evaluation facade.

    Tries OPA first; falls back to the Python engine if OPA is disabled,
    unreachable, or returns None.
    """

    def __init__(self) -> None:
        self._opa = OPABackend()
        self._python = PythonPolicyEngine()

    def evaluate(
        self,
        policies: List[dict],
        context: EvaluationContext,
        problems: Optional[List[dict]] = None,
    ) -> List[PolicyEvalResult]:
        # OPA path. ``problems`` is not forwarded: OPA never calls _compare, so
        # it produces none of these entries. An uncompilable pattern on a
        # reachable-OPA deployment is OPA's error to report and is NOT covered
        # here -- see the note in resolve_artifact_references.
        if OPA_ENABLED:
            opa_results = self._opa.evaluate(policies, context)
            if opa_results is not None:
                _record_opa_derived_field_gap(policies, problems)
                return opa_results
        # Python fallback
        return self._python.evaluate(policies, context, problems)

    def evaluate_first_match(
        self,
        policies: List[dict],
        context: EvaluationContext,
        problems: Optional[List[dict]] = None,
    ) -> Optional[PolicyEvalResult]:
        # OPA path
        if OPA_ENABLED:
            result = self._opa.evaluate_first_match(policies, context)
            if result is not None:
                _record_opa_derived_field_gap(policies, problems)
                return result
            # result == None means OPA unavailable; fall through
        # Python fallback
        return self._python.evaluate_first_match(policies, context, problems)


# ---------------------------------------------------------------------------
# Artifact reference resolution
# ---------------------------------------------------------------------------


_ARTIFACT_PREFIX = "$artifact:"


def _artifact_ref(value: Any) -> Optional[str]:
    if isinstance(value, str) and value.startswith(_ARTIFACT_PREFIX):
        return value[len(_ARTIFACT_PREFIX):].strip()
    return None


def _resolve_value(
    value: Any,
    operator: str,
    artifacts: Dict[str, Any],
    problems: Optional[List[dict]] = None,
) -> tuple[Any, str]:
    """Resolve $artifact:<name> references in a rule value.

    Returns (resolved_value, effective_operator). The operator is overridden
    to ``regex`` when the referenced artifact is of kind ``regex``.

    For a ``regex`` artifact the items are compiled INDIVIDUALLY and only the
    ones that compile are joined into the alternation. Joining first meant one
    malformed entry in a list the tenant uploaded made the whole alternation
    uncompilable, which took their entire enforcement path down. Every rejected
    item is appended to ``problems`` by name and index; nothing is dropped
    silently.

    No compiled-pattern cache is introduced here. ``re`` already memoises
    compilation internally, and the previous code compiled on every ``re.search``
    call anyway, so this is the same work re-shaped.
    """
    name = _artifact_ref(value)
    if name:
        art = artifacts.get(name) or {}
        kind = art.get("kind")
        items = list(art.get("items") or [])
        if kind == "regex":
            good: List[str] = []
            for idx, item in enumerate(items):
                compiled, err = _try_compile(str(item))
                if compiled is None:
                    _record_problem(
                        problems,
                        "policy.artifact_pattern",
                        f"artifact '{name}' item {idx} is not a valid regular "
                        f"expression ({err}); that entry is not enforced",
                    )
                    continue
                good.append(str(item))
            if items and not good:
                # "(?!)" never matches. That is the safe construction, but a
                # denylist that can never match is an open door, so it must not
                # read as a rule that ran and cleared.
                _record_problem(
                    problems,
                    "policy.artifact_pattern",
                    f"artifact '{name}' has no usable pattern, so every rule "
                    f"referencing it now matches nothing",
                )
            joined = "|".join(f"(?:{p})" for p in good) if good else "(?!)"
            return joined, "regex"
        return items, operator
    if isinstance(value, list):
        expanded: List[Any] = []
        for item in value:
            ref = _artifact_ref(item)
            if ref:
                expanded.extend((artifacts.get(ref) or {}).get("items") or [])
            else:
                expanded.append(item)
        return expanded, operator
    return value, operator


def resolve_artifact_references(
    conditions: Optional[Dict[str, Any]],
    artifacts: Dict[str, Any],
    problems: Optional[List[dict]] = None,
) -> Optional[Dict[str, Any]]:
    """Return a deep-copied condition tree with $artifact: references resolved.

    The original input is not mutated. If ``artifacts`` is empty or no
    reference is found, a structural copy is still returned for safety.

    ``problems`` is an optional out-parameter. When supplied, each artifact
    pattern that would not compile is appended to it as ``{"check", "reason"}``
    and left out of the resolved alternation. Callers that pass nothing get the
    filtering but keep no record of it -- which is why the ext_authz handler
    passes a per-request list. This filtering runs before either backend, so it
    applies on the OPA path too; what does NOT apply on the OPA path is the
    inline-pattern half (``_compare``), which OPA never reaches. Not verified
    against a running OPA.
    """
    if not conditions:
        return conditions

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            # Condition group: {operator, rules: [...]}
            if "rules" in node and isinstance(node["rules"], list):
                return {**{k: v for k, v in node.items() if k != "rules"},
                        "rules": [walk(r) for r in node["rules"]]}
            # Leaf rule: {field, operator, value}
            if "field" in node or "value" in node:
                value = node.get("value")
                op = node.get("operator", "equals")
                resolved_value, effective_op = _resolve_value(
                    value, op, artifacts, problems
                )
                out = dict(node)
                out["value"] = resolved_value
                out["operator"] = effective_op
                return out
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(x) for x in node]
        return node

    return walk(conditions)


# Singleton instance (consumed by main.py via ``from policy_engine import engine``)
engine = PolicyEngine()
