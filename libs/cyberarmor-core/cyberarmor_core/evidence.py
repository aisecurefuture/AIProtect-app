"""Compliance evidence that carries WHERE IT CAME FROM, so that a score
earned from platform observation cannot serialise like a score typed into a
request body.

WHY THIS EXISTS
---------------
``services/compliance/frameworks/base.py::_assess_control`` was a pure
presence check over ``Dict[str, Any]``. The ``Any`` was consulted only for
presence, never for meaning, so there was nowhere to record where a value came
from. Measured against shipped HEAD: an evidence dict fabricated by hand passed
18/18 NIST-CSF controls for ``score_pct 100.0``, and its serialised assessment
was byte-identical to one derived entirely from the tenant's own telemetry.
``AssessmentResult.to_dict`` then dropped ``Finding.evidence`` entirely, so the
artefact an auditor reads contained no provenance at all.

This module gives the evidence dict somewhere to put provenance, and makes the
three states -- observed / attested / asserted -- rank against each other so
that a merge cannot silently let the weaker one win.

WHY IT LIVES IN cyberarmor_core AND NOT IN services/compliance
--------------------------------------------------------------
It is a wire contract between two separately containerised services.
``services/control-plane`` derives evidence and ``services/compliance`` scores
it, and neither image copies the other's source tree (see their Dockerfiles).
``libs/cyberarmor-core`` is already on ``PYTHONPATH`` in both, and is where
``health_record.py`` already lives. A copy in each tree would drift, and a
drifting provenance vocabulary is how the eight-independent-names problem
described in ``health_record.py`` started.

RELATIONSHIP TO HealthRecord
----------------------------
This type copies ``HealthRecord``'s MECHANISM and rejects its SHAPE, on
purpose:

  * MECHANISM copied: every honesty field is positional and undefaulted, so a
    call site that forgets ``provenance`` raises ``TypeError`` instead of
    defaulting to "observed". ``source`` must be non-empty prose, for the same
    reason ``UnavailableCheck.reason`` must be. Serialisations carry a
    ``schema`` string so a consumer can refuse a shape rather than read a
    missing key as falsy.

  * SHAPE rejected: ``HealthRecord`` is one record per surface and its status
    axis answers "did the check run?". This surface needs a label per
    (control, evidence key) and its axis is "who says so?". Those are
    orthogonal -- a check that ran perfectly can still be reporting a claim the
    customer typed in -- and overloading ``degraded`` to mean "some of this is
    asserted" would be its own dishonesty. ``HealthRecord`` is still used
    unmodified for the evidence-COLLECTION layer; see ``EvidenceSet.collection``.

WHAT THE PROVENANCE LABEL IS AND IS NOT WORTH
---------------------------------------------
Read this before trusting ``platform_observed`` for anything.

``EvidenceSet.from_wire(..., honour_labels=True)`` believes the labels in the
envelope it is handed. It is therefore worth exactly as much as the channel it
arrived on. Concretely, in this platform:

  * A tenant admin POSTing ``/customer/compliance/assess`` CANNOT produce an
    observed label. The control plane relabels every key of ``body["evidence"]``
    as ``caller_asserted`` before forwarding, and ``offer()`` will not let it
    displace a key the platform derived. That is the hole this module was
    written to close, and it is closed.
  * A legacy flat dict (``{"mfa_enabled": true}``) -- the shape stored rows,
    the demo scripts and the request-scoped simulation path all use -- is
    ALWAYS coerced to ``caller_asserted``. There is no code path that promotes
    an unlabelled value to observed. Unknown provenance is asserted, never
    observed.
  * A holder of the compliance service's own API key CAN assert
    ``platform_observed`` in an envelope. This module does not defend against
    that and does not claim to. That is a service-credential compromise, and
    the same credential already authorises writing attestations and reading
    every report. Closing it needs a signature on the envelope, which is new
    surface and is not in this change.
"""

from __future__ import annotations

from collections.abc import Mapping as _ABCMapping
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

__all__ = [
    "SCHEMA",
    "PROVENANCE_OBSERVED",
    "PROVENANCE_ATTESTED",
    "PROVENANCE_ASSERTED",
    "PROVENANCE_ABSENT",
    "PROVENANCE_INDETERMINATE",
    "PROVENANCE_RANK",
    "EvidenceValueError",
    "EvidenceItem",
    "MissingEvidence",
    "EvidenceSet",
]

#: Bump only on an incompatible change to the serialised shape. Present in
#: every serialisation for the reason ``health_record.SCHEMA`` gives: an absent
#: key is falsy in Python, JavaScript and SQL alike, so a consumer that cannot
#: find provenance must be able to tell "this record predates provenance" from
#: "this record says the evidence was observed".
SCHEMA = "cyberarmor.evidence/1"

#: The platform saw this for itself -- telemetry it recorded, a policy it holds,
#: an audit row it wrote.
PROVENANCE_OBSERVED = "platform_observed"
#: A named human signed for it, against a durable attestation record with an
#: author and a timestamp. Weaker than observation, stronger than an anonymous
#: dict, and the only channel through which a genuinely manual control can be
#: satisfied.
PROVENANCE_ATTESTED = "customer_attested"
#: A request body said so. Nobody signed, nothing is attached. This is evidence
#: of a claim, not evidence of a fact.
PROVENANCE_ASSERTED = "caller_asserted"

#: The two NON-satisfying states. They are deliberately NOT constructible as an
#: :class:`EvidenceItem` -- see :class:`MissingEvidence`, which has no
#: ``satisfied`` field at all, so no call site can build one that reads as a
#: green tick.
PROVENANCE_ABSENT = "absent"
PROVENANCE_INDETERMINATE = "indeterminate"

#: Strength order, used by :meth:`EvidenceSet.offer`. Higher wins a collision.
#: This mapping is the whole reason ``{**derived, **caller}`` cannot come back:
#: dict-unpack order made the LAST writer win, which was always the caller.
PROVENANCE_RANK: Dict[str, int] = {
    PROVENANCE_OBSERVED: 3,
    PROVENANCE_ATTESTED: 2,
    PROVENANCE_ASSERTED: 1,
}

_SATISFYING_PROVENANCE = frozenset(PROVENANCE_RANK)
_MISSING_PROVENANCE = frozenset({PROVENANCE_ABSENT, PROVENANCE_INDETERMINATE})

#: Accepted prefix for an embedded collection record. Checked rather than
#: assumed so a hand-rolled dict cannot pose as a HealthRecord.
_HEALTH_SCHEMA_PREFIX = "cyberarmor.health/"
_HEALTH_STATUS_DEGRADED = "degraded"


class EvidenceValueError(ValueError):
    """An evidence value that cannot be read as a claim about the world.

    Carries ``key`` so an API boundary can turn it into a 400 that names the
    offending key, rather than letting it surface as a 500 from deep inside
    scoring. Raised for values such as ``0``, ``1``, ``"yes"``, ``[]`` and
    ``{}`` -- every one of which PASSED a control against shipped HEAD, because
    the presence check was ``val is None or val is False or val == ""`` and
    ``0 is False`` is ``False`` (identity, not equality).
    """

    def __init__(self, key: str, message: str) -> None:
        super().__init__(message)
        self.key = key


def _clean(value: Any, label: str, key: str) -> str:
    if not isinstance(value, str):
        raise EvidenceValueError(
            key, f"{label} for evidence key {key!r} must be a string, "
                 f"got {type(value).__name__}")
    text = value.strip()
    if not text:
        raise EvidenceValueError(
            key, f"{label} for evidence key {key!r} must be a non-empty string. "
                 f"A provenance label with no stated source is the "
                 f"'name with no reason' shape UnavailableCheck already rejects.")
    return text


@dataclass(frozen=True)
class EvidenceItem:
    """One evidence key, what it claims, and who says so.

    EVERY FIELD IS POSITIONAL AND UNDEFAULTED. That is the mechanism, copied
    from ``HealthRecord``: a call site that forgets ``provenance`` raises
    ``TypeError`` at construction. It does not quietly default to observed.

        >>> EvidenceItem("mfa_enabled", True)
        Traceback (most recent call last):
        TypeError: ... missing 3 required positional arguments ...
    """

    key: str
    #: Strict ``bool``, validated by identity. See :class:`EvidenceValueError`.
    satisfied: bool
    #: One of ``platform_observed`` / ``customer_attested`` / ``caller_asserted``.
    provenance: str
    #: Non-empty prose naming what produced this. "telemetry: 412 ai_* events in
    #: window", "attestation nist-csf/PR.AT-01 by jane@acme". Same requirement
    #: and same rationale as ``UnavailableCheck.reason``.
    source: str
    #: ISO-8601. When the claim was made or the observation taken.
    recorded_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", _clean(self.key, "key", str(self.key)))
        # Identity, not truthiness. `0`, `[]`, `{}` and `["nothing"]` are not
        # False under `is`, and `[] == ""` is False, so under the old presence
        # check every one of them bought a passing control. There is exactly one
        # line standing between that and a compliance report, and this is it.
        if self.satisfied is not True and self.satisfied is not False:
            raise EvidenceValueError(
                self.key,
                f"evidence value for {self.key!r} must be a strict bool, got "
                f"{self.satisfied!r} ({type(self.satisfied).__name__}). A value "
                f"like 0 or [] passed the old presence check and bought a "
                f"passing control while holding nothing.")
        if self.provenance not in _SATISFYING_PROVENANCE:
            raise EvidenceValueError(
                self.key,
                f"provenance for {self.key!r} must be one of "
                f"{sorted(_SATISFYING_PROVENANCE)}, got {self.provenance!r}. "
                f"'{PROVENANCE_ABSENT}' and '{PROVENANCE_INDETERMINATE}' are "
                f"deliberately not constructible here -- use MissingEvidence, "
                f"which has no satisfied field.")
        object.__setattr__(self, "source", _clean(self.source, "source", self.key))
        object.__setattr__(
            self, "recorded_at", _clean(self.recorded_at, "recorded_at", self.key))

    @property
    def rank(self) -> int:
        return PROVENANCE_RANK[self.provenance]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "satisfied": self.satisfied,
            "provenance": self.provenance,
            "source": self.source,
            "recorded_at": self.recorded_at,
        }

    @classmethod
    def coerce(
        cls,
        key: str,
        raw: Any,
        *,
        provenance: str,
        source: str,
        recorded_at: str,
        honour_label: bool = True,
    ) -> "EvidenceItem":
        """Read an :class:`EvidenceItem` out of a wire value.

        ``provenance``/``source``/``recorded_at`` are the labels to apply when
        ``raw`` does not carry its own. They are keyword-only and undefaulted so
        that no caller can coerce a value without stating where it came from.

        ``honour_label=False`` IGNORES any provenance the payload carries and
        forces ``provenance``, keeping the rejected claim in the item's
        ``source``. Every channel whose callers are not the platform MUST pass
        it. Without it, a tenant admin can hand-write
        ``{"satisfied": true, "provenance": "platform_observed", ...}`` in a
        request body and score it as though the platform had observed it --
        measured, and it defeated the entire fix.

        Accepted:
          * an :class:`EvidenceItem`
          * a serialised item -- a mapping carrying its own ``provenance``
          * ``True`` / ``False``
          * ``None`` / ``""``  -> ``satisfied=False``. Same outcome as the old
            presence check (the control fails), but recorded as "we looked and
            the answer was no" rather than as silence.

        Everything else raises :class:`EvidenceValueError`. That rejection is
        the point: it is the ``0``-buys-a-pass hole.
        """
        if isinstance(raw, EvidenceItem):
            if raw.key != key:
                raise EvidenceValueError(
                    key, f"evidence item is keyed {raw.key!r} but was offered "
                         f"under {key!r}")
            labelled = raw
        elif isinstance(raw, _ABCMapping):
            if "provenance" not in raw:
                raise EvidenceValueError(
                    key, f"evidence value for {key!r} is a mapping with no "
                         f"'provenance'. An unlabelled mapping passed the old "
                         f"presence check and scored as though the platform had "
                         f"observed it.")
            labelled = cls(
                key,
                raw.get("satisfied"),
                str(raw.get("provenance")),
                str(raw.get("source") or ""),
                str(raw.get("recorded_at") or ""),
            )
        elif raw is True or raw is False:
            return cls(key, raw, provenance, source, recorded_at)
        elif raw is None or raw == "":
            return cls(key, False, provenance, source, recorded_at)
        else:
            raise EvidenceValueError(
                key,
                f"evidence value for {key!r} is {raw!r} ({type(raw).__name__}), "
                f"which is neither a bool nor a labelled evidence item. Send true "
                f"or false. Values like 0, 1, 'yes' and [] used to pass this "
                f"control while proving nothing.")

        if honour_label or labelled.provenance == provenance:
            return labelled
        # The claim is not deleted, it is demoted and quoted. An examiner
        # reading the record can see that the tenant asked to be believed.
        return cls(
            key, labelled.satisfied, provenance,
            f"{labelled.source} [claimed {labelled.provenance} on a channel "
            f"that cannot vouch for it; recorded as {provenance}]",
            labelled.recorded_at)


@dataclass(frozen=True)
class MissingEvidence:
    """An evidence key that produced no claim, and why.

    THERE IS NO ``satisfied`` FIELD. :attr:`satisfied` is a read-only property
    that is always ``False``, so there is no constructor argument, no setter and
    no wire key by which "we never got this" can be turned into a green tick.
    Same construction as ``HealthRecord.degraded``.

    ``absent`` and ``indeterminate`` are different states and are deliberately
    different words, for the reason ``attestation.py`` already records:
    conflating "you do not have this" with "we could not find out" would be its
    own dishonesty. ``absent`` fails the control -- that is a finding about the
    customer. ``indeterminate`` does not -- that is a finding about us.
    """

    key: str
    provenance: str
    #: Non-empty prose. For ``indeterminate`` this is the collector failure an
    #: examiner will read; a bare label would tell them a control did not
    #: resolve and nothing about why.
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", _clean(self.key, "key", str(self.key)))
        if self.provenance not in _MISSING_PROVENANCE:
            raise EvidenceValueError(
                self.key,
                f"MissingEvidence provenance must be one of "
                f"{sorted(_MISSING_PROVENANCE)}, got {self.provenance!r}")
        object.__setattr__(self, "reason", _clean(self.reason, "reason", self.key))

    @property
    def satisfied(self) -> bool:
        """Derived and always False. No field, no setter, no wire key."""
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "satisfied": False,
            "provenance": self.provenance,
            "source": self.reason,
            "recorded_at": None,
        }


Resolved = Union[EvidenceItem, MissingEvidence]


class EvidenceSet(_ABCMapping):
    """A provenance-carrying evidence dict, plus the record of how it was
    collected.

    A ``Mapping[str, EvidenceItem]`` so that existing readers keep working, but
    ``offer()`` REPLACES ``update()``: there is no method on this type by which
    a weaker claim overwrites a stronger one. A loser is not dropped, it is
    recorded in :attr:`superseded`, which is how the record ends up able to say
    "the caller asserted encryption_at_rest and we ignored it because we
    observed it ourselves" -- the sentence an examiner actually wants.

    :attr:`collection` carries a ``HealthRecord`` serialisation for the
    collectors that produced these items. It rides INSIDE this object rather
    than beside it as a second return value, because a tuple can be
    destructured and its second element dropped at a boundary, and
    ``health_record.combine``'s docstring records that the boundary is where
    these losses actually happen.
    """

    __slots__ = ("_items", "_superseded", "_unresolved", "_collection")

    def __init__(self) -> None:
        self._items: Dict[str, EvidenceItem] = {}
        self._superseded: List[Tuple[EvidenceItem, str]] = []
        self._unresolved: Dict[str, str] = {}
        self._collection: Optional[Dict[str, Any]] = None

    # -- Mapping protocol --------------------------------------------------

    def __getitem__(self, key: str) -> EvidenceItem:
        return self._items[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:  # pragma: no cover -- operator convenience
        return (f"EvidenceSet(items={len(self._items)}, "
                f"superseded={len(self._superseded)}, "
                f"unresolved={len(self._unresolved)}, "
                f"collection={'set' if self._collection else 'none'})")

    def __eq__(self, other: Any) -> bool:
        """VALUE equality, deliberately.

        Identity equality would make every "these two states must differ"
        assertion pass no matter what the code did -- the dishonest-health bug
        applied to the test suite. ``collection`` is included because a
        degraded collection is exactly one of the states that must not compare
        equal to a clean one.
        """
        if not isinstance(other, EvidenceSet):
            return NotImplemented
        return (
            self._items == other._items
            and sorted(
                (i.to_dict()["key"], i.provenance, w) for i, w in self._superseded
            ) == sorted(
                (i.to_dict()["key"], i.provenance, w) for i, w in other._superseded
            )
            and self._unresolved == other._unresolved
            and self._collection == other._collection
        )

    __hash__ = None  # mutable

    # -- accessors ---------------------------------------------------------

    @property
    def superseded(self) -> Tuple[Tuple[EvidenceItem, str], ...]:
        return tuple(self._superseded)

    @property
    def unresolved(self) -> Dict[str, str]:
        return dict(self._unresolved)

    @property
    def collection(self) -> Optional[Dict[str, Any]]:
        return dict(self._collection) if self._collection is not None else None

    # -- construction ------------------------------------------------------

    def offer(self, item: EvidenceItem) -> None:
        """Offer an item. The STRONGER provenance wins; the loser is recorded.

        Deliberately not called ``update``/``__setitem__``: the defect this
        replaces was ``{**derived, **caller}``, where dict-unpack order made the
        last writer win and the last writer was always the caller. Ties go to
        the INCUMBENT -- a second claim of equal strength does not displace the
        first, it is recorded as superseded, so re-offering asserted evidence
        cannot churn the record.
        """
        if not isinstance(item, EvidenceItem):
            raise TypeError(
                f"offer() takes an EvidenceItem, got {type(item).__name__}. A "
                f"bare value has no provenance, which is the defect this type "
                f"exists to prevent.")
        incumbent = self._items.get(item.key)
        if incumbent is None:
            self._items[item.key] = item
            return
        if item.rank > incumbent.rank:
            self._items[item.key] = item
            self._superseded.append((incumbent, item.provenance))
        else:
            self._superseded.append((item, incumbent.provenance))

    def mark_unresolved(self, key: str, reason: str) -> None:
        """Record that a collector which WOULD have produced ``key`` did not run.

        This is what stops a collector outage from rendering as a finding about
        the customer. It does NOT overwrite an item: if another collector
        independently observed the key, :meth:`resolve` still returns that item.
        The marker is kept either way, because "the policy service was down and
        this key came from telemetry instead" is worth reading.
        """
        self._unresolved[_clean(key, "key", str(key))] = _clean(
            reason, "unresolved reason", str(key))

    def set_collection(self, record: Any) -> None:
        """Attach the ``HealthRecord`` for the collectors behind these items.

        Accepts a ``HealthRecord`` (anything with ``to_dict``) or its dict form.
        The record's own invariant is re-checked here rather than trusted,
        because this type is reachable from a request body and a hand-rolled
        ``{"status": "ok"}`` must not be able to claim a clean collection.
        """
        if record is None:
            self._collection = None
            return
        data = record.to_dict() if hasattr(record, "to_dict") else record
        if not isinstance(data, _ABCMapping):
            raise TypeError(
                f"collection record must be a HealthRecord or its dict form, "
                f"got {type(record).__name__}")
        schema = str(data.get("schema") or "")
        if not schema.startswith(_HEALTH_SCHEMA_PREFIX):
            raise ValueError(
                f"collection record schema {schema!r} is not a "
                f"{_HEALTH_SCHEMA_PREFIX}* record. Refusing a shape this code "
                f"cannot check rather than reading its missing keys as falsy.")
        unavailable = data.get("checks_unavailable")
        status = data.get("status")
        # The one invariant HealthRecord.to_dict re-asserts on every call. It is
        # re-asserted here too, on the receiving side, because a record that
        # crossed a wire was serialised by code this process did not run.
        if bool(unavailable) != (status == _HEALTH_STATUS_DEGRADED):
            raise ValueError(
                f"collection record claims status={status!r} with "
                f"{len(unavailable or [])} unavailable checks. A degraded "
                f"collection that serialises as clean is the defect this "
                f"whole module exists to prevent.")
        if bool(data.get("degraded")) != (status == _HEALTH_STATUS_DEGRADED):
            raise ValueError(
                f"collection record claims degraded={data.get('degraded')!r} "
                f"with status={status!r}")
        self._collection = dict(data)

    # -- resolution --------------------------------------------------------

    def resolve(self, key: str) -> Resolved:
        """What this set knows about ``key``: an item, or why there is none.

        Precedence is item-before-unresolved on purpose. A key marked
        unresolved by a failed collector but independently observed by a
        working one IS known; downgrading it to indeterminate would understate
        what the platform actually proved.
        """
        item = self._items.get(key)
        if item is not None:
            return item
        reason = self._unresolved.get(key)
        if reason is not None:
            return MissingEvidence(key, PROVENANCE_INDETERMINATE, reason)
        return MissingEvidence(
            key, PROVENANCE_ABSENT,
            "no collector produced this key and no attestation or assertion "
            "supplied it")

    def counts_by_provenance(self) -> Dict[str, int]:
        """Derived on every call, never stored -- a stored counter is a second
        source of truth that can disagree with the items."""
        counts = {p: 0 for p in PROVENANCE_RANK}
        for item in self._items.values():
            counts[item.provenance] += 1
        return counts

    # -- serialisation -----------------------------------------------------

    def to_wire(self) -> Dict[str, Any]:
        """JSON-safe envelope. Every honesty key is ALWAYS present, empty or not.

        "Always present, never omitted when empty" is
        ``AttestationDecision.to_dict``'s invariant and it is load-bearing here
        for the same reason: an omitted ``superseded`` reads as "nothing was
        overridden" in every language this record crosses.
        """
        return {
            "schema": SCHEMA,
            "items": {k: v.to_dict() for k, v in sorted(self._items.items())},
            "superseded": [
                dict(item.to_dict(), superseded_by=winner)
                for item, winner in self._superseded
            ],
            "unresolved": dict(sorted(self._unresolved.items())),
            "by_provenance": self.counts_by_provenance(),
            "collection": self.collection,
        }

    @classmethod
    def from_wire(
        cls,
        value: Any,
        *,
        default_provenance: str,
        default_source: str,
        recorded_at: str,
        honour_labels: bool = True,
    ) -> "EvidenceSet":
        """Build a set from an envelope, a legacy flat dict, or nothing.

        ``default_provenance`` is keyword-only and undefaulted so that no caller
        can parse evidence without stating what an UNLABELLED value is worth.
        Every caller in this repo passes ``PROVENANCE_ASSERTED`` there: a value
        that did not say where it came from is a claim, never an observation.
        Promoting an unlabelled value to observed would restore the defect in
        one line, so there is no path here that does it.

        ``honour_labels=False`` downgrades any label the payload carries to
        ``default_provenance`` and records the downgrade in ``superseded``. Used
        for channels whose callers are not the control plane -- see
        ``/evidence/{tenant_id}``.
        """
        out = cls()
        if isinstance(value, EvidenceSet):
            return value
        if value is None:
            return out
        if not isinstance(value, _ABCMapping):
            raise TypeError(
                f"evidence must be a mapping or an EvidenceSet, got "
                f"{type(value).__name__}")

        schema = value.get("schema")
        is_envelope = (
            isinstance(schema, str)
            and schema.startswith("cyberarmor.evidence/")
            and isinstance(value.get("items"), _ABCMapping)
        )
        if not is_envelope:
            # Legacy flat dict: {key: true}. This is what stored evidence rows,
            # the demo scripts and every pre-provenance caller send. Unknown
            # provenance is asserted -- see the module docstring.
            for key, raw in value.items():
                out.offer(EvidenceItem.coerce(
                    key, raw, provenance=default_provenance,
                    source=default_source, recorded_at=recorded_at))
            return out

        major = schema.split("/", 1)[1].split(".", 1)[0]
        if major != SCHEMA.split("/", 1)[1].split(".", 1)[0]:
            raise ValueError(
                f"evidence envelope schema {schema!r} is not readable by "
                f"{SCHEMA!r}. Refusing an unknown shape rather than reading its "
                f"missing keys as falsy.")

        for key, raw in value["items"].items():
            item = EvidenceItem.coerce(
                key, raw, provenance=default_provenance,
                source=default_source, recorded_at=recorded_at)
            if not honour_labels and item.provenance != default_provenance:
                downgraded = EvidenceItem(
                    item.key, item.satisfied, default_provenance,
                    f"{item.source} [claimed {item.provenance} on a channel "
                    f"whose callers are not the platform; downgraded]",
                    item.recorded_at)
                out.offer(downgraded)
                out._superseded.append((item, default_provenance))
                continue
            out.offer(item)

        for key, reason in (value.get("unresolved") or {}).items():
            out.mark_unresolved(key, reason)
        for entry in (value.get("superseded") or []):
            if not isinstance(entry, _ABCMapping):
                continue
            loser = EvidenceItem.coerce(
                str(entry.get("key")), entry, provenance=default_provenance,
                source=default_source, recorded_at=recorded_at)
            out._superseded.append((loser, str(entry.get("superseded_by") or "")))
        if value.get("collection") is not None:
            out.set_collection(value["collection"])
        return out

    @classmethod
    def from_items(cls, items) -> "EvidenceSet":
        """Convenience for call sites and tests that already have items."""
        out = cls()
        for item in items:
            out.offer(item)
        return out
