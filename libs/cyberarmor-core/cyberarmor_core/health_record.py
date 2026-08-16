"""One way to build a status / health / provenance record, in which the
DEGRADED case cannot be written so that it renders like the HEALTHY case.

WHY THIS EXISTS
---------------
This repo tracks a defect class it calls "dishonest health": code that reports
clean / healthy / success when the check never actually ran. It has been found
nine times. Every one of those nine was found by hand testing; not one was
caught by a test suite. Over four consecutive remediation rounds, every round
introduced a NEW instance of the defect the round was written to eliminate.

The shape is always the same. A new feature adds a status, health or provenance
field. The healthy path fills it in. The degraded path either omits it, or
fills it with the same value the healthy path would have used, and the record
that reaches the operator is byte-identical either way:

  * ``notifier_health(channel="none")`` -> ``delivering=True, degraded=False``
  * a request budget skipped policy evaluation -> ``action=allow``, identical
    to a genuine allow
  * a local evaluator that never reproduced the attestation control ->
    provenance identical to a decision where every control ran
  * ``telemetry_buffer_size`` -> the same number after one dropped event and
    after one hundred thousand
  * ``identity_confidence="unproven"`` next to ``id_source="ioplatform_uuid"``
    and ``pairing_state="proven"``
  * ``chain_intact=true`` after an event was DELETED from an append-only log

So the answer cannot be more review or more discipline -- both have already
been applied nine times and failed nine times. It has to be MECHANICAL: make
the wrong thing impossible to express.

WHAT THIS TYPE MAKES IMPOSSIBLE
-------------------------------
1. ``checks_run`` and ``checks_unavailable`` are undefaulted positional fields.
   Omitting either is a ``TypeError`` at the call site, not a silently empty
   list. This is copied directly from ``services/policy/attestation.py``'s
   ``AttestationDecision``, which is the only place in the tree where omitting
   an honesty field is already a hard error.

2. Every entry in ``checks_unavailable`` carries a ``reason`` AND an
   ``effect``. A bare check name tells an operator that something did not run
   and nothing about what that cost them. Blank strings are rejected.

3. ``degraded`` is a derived property, not a field. There is no constructor
   argument, no setter, and no ``facts`` key that can reach it -- reserved
   names are rejected. A caller CANNOT declare an unavailable check and then
   assert the record is healthy anyway.

4. A degraded record cannot serialise identically to a clean one, because
   ``status`` is derived from ``checks_unavailable`` inside ``to_dict`` and
   there is no code path that emits ``status="ok"`` while
   ``checks_unavailable`` is non-empty. ``to_dict`` re-asserts that invariant
   on every call rather than trusting itself.

5. ``HealthRecord(surface, (), ())`` -- "I declare that I checked nothing, and
   I am fine" -- raises. That record is the defect in its purest form: it reads
   as a clean pass and contains no evidence of anything. Declaring that there
   was genuinely nothing to check is still expressible, but only deliberately,
   via :meth:`HealthRecord.nothing_to_check`, and it serialises as
   ``status="not_applicable"``, which is a third value an operator's UI must
   handle rather than a green tick.

WHY THIS VOCABULARY AND NOT A NEW ONE
-------------------------------------
The survey that preceded this module found EIGHT independently invented names
for one idea already in the tree: ``checks_run``/``checks_unavailable``
(attestation), ``analyzers_run``/``analyzers_unavailable`` (the specs),
``scan_complete``/``detectors_unavailable`` (detection),
``checks{ran,...}``/``not_checked``/``limitations`` (audit chain),
``scan_status``/``scan_failed``/``redact_status`` (endpoint proxy),
``delivering``/``delivery_verifiable`` (notifier), ``degraded_models`` /
``ml_model_status`` (detection ready), ``evaluated``/``skip_reason``
(local_eval). Each was invented during a remediation round, because there was
nothing to reuse. That is precisely why round N+1 reinvents it badly.

``checks_run`` / ``checks_unavailable`` wins because ``attestation.py`` already
uses it, its docstring already says it mirrors ``analyzers_run`` /
``analyzers_unavailable`` in ``services/detection``, and every spec in
``docs/specs/`` is written in that vocabulary. ``scan_complete`` is derivable
(``not checks_unavailable``). This module adds no new words.

DEPENDENCIES: stdlib only, on purpose. Same discipline as
``services/policy/attestation.py`` and ``cyberarmor_core/policy_eval.py``. See
the packaging note on the vendored copy in
``agents/endpoint-agent/_health_record.py``.

KEEP IN SYNC with agents/endpoint-agent/_health_record.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

__all__ = [
    "SCHEMA",
    "STATUS_OK",
    "STATUS_DEGRADED",
    "STATUS_NOT_APPLICABLE",
    "EFFECT_UNKNOWN",
    "EFFECT_FAILED_OPEN",
    "EFFECT_FAILED_CLOSED",
    "EFFECT_NOT_ENFORCED",
    "EFFECT_EVIDENCE_LOST",
    "UnavailableCheck",
    "HealthRecord",
]

#: Bump only when the serialised shape changes incompatibly. Present in every
#: record so a consumer can refuse a shape it does not understand instead of
#: reading missing keys as falsy -- an absent ``degraded`` key evaluates to
#: False in every language this record crosses, which is the failure mode this
#: whole module exists to prevent.
SCHEMA = "cyberarmor.health/1"

STATUS_OK = "ok"
STATUS_DEGRADED = "degraded"
#: Genuinely nothing to check. NOT the same as "everything checked and fine",
#: and deliberately not the same word, because a control the tenant never
#: bought and a control that broke need different humans. Mirrors
#: ``attestation.OUTCOME_CONTROL_NOT_ENABLED`` vs ``OUTCOME_INDETERMINATE``.
STATUS_NOT_APPLICABLE = "not_applicable"

#: Suggested ``effect`` values. Deliberately NOT an enum: the point of the
#: field is that a human wrote down what the omission cost, and a closed
#: vocabulary would push authors toward the nearest label instead. Any
#: non-empty string is accepted; these exist so most call sites do not have to
#: invent one.
EFFECT_UNKNOWN = "state_unknown"
EFFECT_FAILED_OPEN = "failed_open"
EFFECT_FAILED_CLOSED = "failed_closed"
EFFECT_NOT_ENFORCED = "not_enforced"
EFFECT_EVIDENCE_LOST = "evidence_lost"

#: Keys a caller may not put in ``facts``. Every one of them is derived from
#: the checks, and letting a caller supply their own value is exactly the
#: override this type exists to forbid.
_RESERVED_FACT_KEYS = frozenset({
    "schema", "surface", "status", "degraded",
    "checks_run", "checks_unavailable", "not_applicable_reason",
})


def _clean(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string, got {type(value).__name__}")
    text = value.strip()
    if not text:
        raise ValueError(
            f"{label} must be a non-empty string. A blank {label} is how a "
            f"degraded record ends up looking like a clean one."
        )
    return text


@dataclass(frozen=True)
class UnavailableCheck:
    """One check that did NOT run, why, and what that cost.

    All three fields are required. ``check`` alone is the shape this repo keeps
    shipping: an operator reading "mlDetector" learns that something is absent
    and nothing about whether the request was blocked, allowed, or silently
    passed through unscanned.
    """

    check: str
    reason: str
    effect: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "check", _clean(self.check, "check"))
        object.__setattr__(self, "reason", _clean(self.reason, "reason"))
        object.__setattr__(self, "effect", _clean(self.effect, "effect"))

    @classmethod
    def coerce(cls, value: Any) -> "UnavailableCheck":
        """Accept an UnavailableCheck, a mapping, or a 3-tuple.

        Friction is the enemy here: a guardrail nobody reaches for is a
        guardrail that does not run. A bare string is deliberately NOT accepted
        -- that is the "name with no reason" case this type exists to reject.
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, Mapping):
            missing = {"check", "reason", "effect"} - set(value)
            if missing:
                raise TypeError(
                    f"checks_unavailable entry is missing {sorted(missing)}. "
                    f"Every unavailable check needs a name, a reason and an "
                    f"effect: {{'check': ..., 'reason': ..., 'effect': ...}}"
                )
            return cls(check=value["check"], reason=value["reason"], effect=value["effect"])
        if isinstance(value, (tuple, list)) and len(value) == 3:
            return cls(check=value[0], reason=value[1], effect=value[2])
        if isinstance(value, str):
            raise TypeError(
                f"checks_unavailable entry {value!r} is a bare name. A name "
                f"without a reason tells an operator that something did not "
                f"run and nothing about what that cost them. Use "
                f"UnavailableCheck(check=..., reason=..., effect=...)."
            )
        raise TypeError(f"cannot read a checks_unavailable entry from {value!r}")

    def to_dict(self) -> Dict[str, str]:
        return {"check": self.check, "reason": self.reason, "effect": self.effect}


@dataclass(frozen=True)
class HealthRecord:
    """A status claim plus the evidence for how much that claim is worth.

    ``checks_run`` and ``checks_unavailable`` are POSITIONAL AND UNDEFAULTED.
    That is the whole mechanism: a call site that forgets one does not compile
    a silently empty list, it raises TypeError.

        >>> HealthRecord("notifier")
        Traceback (most recent call last):
        TypeError: ... missing 2 required positional arguments: 'checks_run'
        and 'checks_unavailable'
    """

    surface: str
    checks_run: Tuple[str, ...]
    checks_unavailable: Tuple[UnavailableCheck, ...]
    #: Free-form payload -- counters, ages, ids. Never consulted for status.
    #: Excluded from :meth:`fingerprint` on purpose; see that method.
    facts: Mapping[str, Any] = field(default_factory=dict)
    #: Set ONLY by :meth:`nothing_to_check`.
    not_applicable_reason: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "surface", _clean(self.surface, "surface"))

        run: Tuple[str, ...] = tuple(
            _clean(c, "checks_run entry") for c in (self.checks_run or ())
        )
        if len(set(run)) != len(run):
            dupes = sorted({c for c in run if run.count(c) > 1})
            raise ValueError(f"checks_run lists {dupes} more than once")
        object.__setattr__(self, "checks_run", run)

        unavailable = tuple(
            UnavailableCheck.coerce(c) for c in (self.checks_unavailable or ())
        )
        object.__setattr__(self, "checks_unavailable", unavailable)

        both = {c.check for c in unavailable} & set(run)
        if both:
            raise ValueError(
                f"{sorted(both)} appear in BOTH checks_run and "
                f"checks_unavailable. A check either ran or it did not; a "
                f"record that claims both is unreadable."
            )

        if self.not_applicable_reason is not None:
            object.__setattr__(
                self, "not_applicable_reason",
                _clean(self.not_applicable_reason, "not_applicable_reason"))
            if run or unavailable:
                raise ValueError(
                    "not_applicable_reason is for a surface with genuinely "
                    "nothing to check. This record declares checks, so it is "
                    "not that."
                )
        elif not run and not unavailable:
            raise ValueError(
                f"HealthRecord({self.surface!r}, (), ()) declares that nothing "
                f"was checked and that everything is fine. That record is the "
                f"defect this type exists to prevent: it is indistinguishable "
                f"from a surface where every check passed. Either name the "
                f"checks that ran, name the ones that did not and why, or use "
                f"HealthRecord.nothing_to_check(surface, reason=...) if there "
                f"is genuinely nothing to check here."
            )

        facts = dict(self.facts or {})
        reserved = _RESERVED_FACT_KEYS & set(facts)
        if reserved:
            raise ValueError(
                f"facts may not contain {sorted(reserved)} -- those are derived "
                f"from the checks, and letting a caller supply them is exactly "
                f"the override this type forbids."
            )
        object.__setattr__(self, "facts", facts)

    # -- alternate constructors -------------------------------------------

    @classmethod
    def nothing_to_check(cls, surface: str, *, reason: str) -> "HealthRecord":
        """A surface with genuinely nothing to check -- a control the tenant
        never enabled, a platform-specific probe on the wrong platform.

        Serialises as ``status="not_applicable"``. It is a THIRD value, not a
        green tick, because ``attestation.py`` already learned this lesson:
        "conflating 'you did not buy this control' with 'this control broke'
        would be its own dishonesty" -- and conflating either with "this
        control ran and cleared you" is worse.
        """
        return cls(surface, (), (), not_applicable_reason=reason)

    @classmethod
    def combine(cls, surface: str, records: Sequence["HealthRecord"],
                *, facts: Optional[Mapping[str, Any]] = None) -> "HealthRecord":
        """Roll several records up into one WITHOUT being able to drop a
        degradation on the way through.

        This exists because the survey's first structural finding was that the
        failure is usually at the BOUNDARY, not the emission site: four
        surfaces already emit correct honesty fields and a fifth surface drops
        them. ``services/detection`` emits ``scan_complete`` /
        ``detectors_unavailable`` and NOTHING in the tree reads them --
        ``services/runtime`` reduces the whole result to ``len(findings)``.

        A rollup built with this cannot lose an unavailable check, because the
        union is computed here and ``degraded`` is derived from it.
        """
        records = list(records)
        if not records:
            raise ValueError(
                f"combine({surface!r}, []) has no inputs, so it can only ever "
                f"report clean. If the inputs could not be collected, say so "
                f"with an unavailable check."
            )
        run: list = []
        for r in records:
            for c in r.checks_run:
                name = f"{r.surface}.{c}"
                if name not in run:
                    run.append(name)
        unavailable = [
            UnavailableCheck(f"{r.surface}.{c.check}", c.reason, c.effect)
            for r in records for c in r.checks_unavailable
        ]
        na = [r for r in records if r.status == STATUS_NOT_APPLICABLE]
        if not run and not unavailable:
            # Every input said "nothing to check". The rollup says the same,
            # and carries each input's reason -- it does NOT become "ok".
            return cls.nothing_to_check(
                surface,
                reason="; ".join(
                    f"{r.surface}: {r.not_applicable_reason}" for r in na) or
                "every input reported nothing to check",
            )
        return cls(surface, tuple(run), tuple(unavailable), facts=dict(facts or {}))

    # -- derived truth -----------------------------------------------------

    @property
    def degraded(self) -> bool:
        """Derived. There is no field, no setter and no facts key for this."""
        return bool(self.checks_unavailable)

    @property
    def status(self) -> str:
        if self.checks_unavailable:
            return STATUS_DEGRADED
        if self.not_applicable_reason is not None:
            return STATUS_NOT_APPLICABLE
        return STATUS_OK

    @property
    def scan_complete(self) -> bool:
        """``services/detection``'s vocabulary, derived rather than duplicated,
        so a surface already speaking that dialect can adopt this type without
        changing its wire shape."""
        return not self.checks_unavailable

    def fingerprint(self) -> Tuple[Any, ...]:
        """The CATEGORICAL shape of this record.

        Deliberately excludes ``facts``. Reasoning copied from
        ``cyberarmor_core/local_eval.py``: facts carry continuously varying
        values (ages, counters, ids), so including them would make the "every
        degraded state is distinguishable" test pass no matter what -- a test
        that cannot fail is the same dishonest-health bug this module exists to
        prevent, applied to the test suite instead of the code. What must
        differ between a clean pass and a degraded one is the CLASSIFICATION,
        not an incidental number.

        ``reason`` is included and ``effect`` is not: two different degradations
        that look the same to an operator are also a failure, and the reason is
        what an operator reads.
        """
        return (
            self.surface,
            self.status,
            tuple(sorted(self.checks_run)),
            tuple(sorted((c.check, c.reason) for c in self.checks_unavailable)),
            self.not_applicable_reason,
        )

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe. Every honesty key is ALWAYS present, including when empty.

        "Always present, never omitted when empty" is
        ``AttestationDecision.to_dict``'s invariant and it is load-bearing: an
        absent key reads as falsy in Python, JavaScript and SQL alike, so an
        omitted ``degraded`` renders as a green tick on every surface it
        reaches.
        """
        out: Dict[str, Any] = {
            "schema": SCHEMA,
            "surface": self.surface,
            "status": self.status,
            "degraded": self.degraded,
            "checks_run": list(self.checks_run),
            "checks_unavailable": [c.to_dict() for c in self.checks_unavailable],
            "not_applicable_reason": self.not_applicable_reason,
            "facts": dict(self.facts),
        }
        # Re-asserted on every call rather than trusted. This is the one
        # invariant the whole module rests on, and a future edit that breaks it
        # would restore the exact defect: a degraded record that serialises
        # like a clean one.
        if bool(out["checks_unavailable"]) != (out["status"] == STATUS_DEGRADED):
            raise AssertionError(
                f"HealthRecord invariant broken for {self.surface!r}: "
                f"status={out['status']!r} with "
                f"{len(out['checks_unavailable'])} unavailable checks"
            )
        if out["degraded"] != (out["status"] == STATUS_DEGRADED):
            raise AssertionError(
                f"HealthRecord invariant broken for {self.surface!r}: "
                f"degraded={out['degraded']!r} status={out['status']!r}"
            )
        return out

    def __str__(self) -> str:  # pragma: no cover -- operator convenience
        if not self.checks_unavailable:
            return f"{self.surface}: {self.status} ({len(self.checks_run)} checks ran)"
        first = self.checks_unavailable[0]
        return (f"{self.surface}: DEGRADED -- {len(self.checks_unavailable)} of "
                f"{len(self.checks_run) + len(self.checks_unavailable)} checks did not "
                f"run (e.g. {first.check}: {first.reason} -> {first.effect})")
