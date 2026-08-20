"""What a subscription entitles someone to, and what happens when it lapses.

Every number here comes from ``shared/tiers.json``. None is written twice --
see that file's header for why the second copy is the dangerous one.

THE FOUR STATES
===============
A subscription is not a boolean. Collapsing it to ``active: true/false`` is what
makes downgrades and expiries silently remove protection, so the states are
explicit and each one has a defined answer to "is this person protected?":

    trialing   protected. Inside the 14-day trial, no charge yet.
    active     protected. Paid and current.
    grace      protected. Payment failed, or a downgrade left more devices
               enrolled than the new tier allows. Protection continues while
               the person decides. This state exists precisely so that neither
               event can quietly turn protection off.
    lapsed     NOT protected, and the person has been told. The only state in
               which protection stops, and it is never arrived at silently.

THE RULE THAT SHAPES ALL OF IT
==============================
Protection never stops as a side effect. Not of a failed card, not of a
downgrade, not of hitting a device cap. Every one of those routes through
``grace`` first, and the transition out of ``grace`` is either an explicit
choice by the person or the expiry of a deadline they were told about.

A security product that quietly stops protecting is worse than one that never
protected: the person is relying on it. This is the same defect class the
detection service refuses -- a check that did not run rendering as a check that
ran and found nothing -- expressed as a billing state machine.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import resources

#: Searched for, not counted to. `parents[2]` is correct in the repository and
#: raises IndexError in the image, where these modules are flattened into
#: /app -- see resources.py.
_TIERS_PATH = resources.find_resource(
    "shared", "tiers.json", env_var="AIPROTECT_TIERS_PATH"
)

TRIALING = "trialing"
ACTIVE = "active"
GRACE = "grace"
LAPSED = "lapsed"

#: States in which the product actually protects the person.
PROTECTED_STATES = frozenset({TRIALING, ACTIVE, GRACE})

#: How long `grace` lasts before a subscription lapses.
#:
#: 14 days, matching the trial. Long enough to survive a expired card and a
#: holiday; short enough that "grace" is not a synonym for "free". Confirm
#: against real dunning data once there is any -- this is a starting value,
#: not a measured one.
GRACE_PERIOD_DAYS = 14


class TierNotFound(KeyError):
    pass


def _load() -> Dict[str, Any]:
    return json.loads(_TIERS_PATH.read_text(encoding="utf-8"))


#: Loaded once. The file is deployment configuration, not runtime state.
_DATA: Dict[str, Any] = _load()


def reload_tiers() -> None:
    """Re-read tiers.json. For tests; production restarts instead."""
    global _DATA
    _DATA = _load()


def tier_names() -> List[str]:
    return list(_DATA["upgrade_path"])


def tier(name: str) -> Dict[str, Any]:
    try:
        return _DATA["tiers"][name]
    except KeyError as exc:
        raise TierNotFound(
            f"unknown tier {name!r}; known: {', '.join(tier_names())}"
        ) from exc


def device_limit(tier_name: str) -> int:
    return int(tier(tier_name)["devices"])


def people_limit(tier_name: str) -> int:
    return int(tier(tier_name)["people"])


def trial_days() -> int:
    return int(_DATA["trial"]["days"])


def trial_reminder_days() -> int:
    return int(_DATA["trial"]["reminder_days_before_charge"])


def next_tier(tier_name: str) -> Optional[str]:
    """The tier someone at their cap should be offered.

    There is no per-device add-on, so upgrading is the ONLY way to add
    devices. A cap refusal that does not name the next tier is a dead end.
    """
    path = tier_names()
    idx = path.index(tier_name)
    return path[idx + 1] if idx + 1 < len(path) else None


# ---------------------------------------------------------------------------
# Entitlement resolution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Entitlement:
    """What this subscription currently allows, and why.

    ``reason`` is never empty when ``protected`` is False. A client showing a
    person "you are not protected" without being able to say why cannot tell
    them how to fix it.
    """

    state: str
    tier_name: str
    devices_allowed: int
    people_allowed: int
    protected: bool
    reason: str
    #: Set while trialing or in grace, so a UI can count down honestly.
    deadline: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "tier": self.tier_name,
            "devices_allowed": self.devices_allowed,
            "people_allowed": self.people_allowed,
            "protected": self.protected,
            "reason": self.reason,
            "deadline": self.deadline.isoformat() if self.deadline else None,
        }


def resolve(
    *,
    state: str,
    tier_name: str,
    trial_ends_at: Optional[datetime] = None,
    grace_ends_at: Optional[datetime] = None,
    now: Optional[datetime] = None,
) -> Entitlement:
    """Turn stored subscription fields into a decision.

    Deliberately a pure function of its arguments: entitlement is consulted on
    effectively every request, and a version that reached for a clock or a
    database would be impossible to test at the boundaries that matter (the
    minute a trial ends, the minute grace expires).
    """
    now = now or datetime.now(timezone.utc)
    limits = tier(tier_name)
    allowed_devices = int(limits["devices"])
    allowed_people = int(limits["people"])

    def built(st: str, protected: bool, reason: str, deadline=None) -> Entitlement:
        return Entitlement(
            state=st,
            tier_name=tier_name,
            devices_allowed=allowed_devices,
            people_allowed=allowed_people,
            protected=protected,
            reason=reason,
            deadline=deadline,
        )

    if state == TRIALING:
        if trial_ends_at and now >= trial_ends_at:
            # The trial ran out. That is not the same as being unprotected --
            # billing decides what happens next, and until it does the person
            # keeps their protection. Never drop coverage on a timer alone.
            return built(GRACE, True,
                         "Your trial has ended. Confirm payment to continue.",
                         grace_ends_at or (now + timedelta(days=GRACE_PERIOD_DAYS)))
        return built(TRIALING, True, "", trial_ends_at)

    if state == ACTIVE:
        return built(ACTIVE, True, "")

    if state == GRACE:
        if grace_ends_at and now >= grace_ends_at:
            return built(LAPSED, False,
                         "Your subscription ended and your devices are no "
                         "longer protected.")
        return built(GRACE, True,
                     "There is a problem with your subscription. Your devices "
                     "are still protected for now.",
                     grace_ends_at)

    if state == LAPSED:
        return built(LAPSED, False,
                     "Your subscription ended and your devices are no longer "
                     "protected.")

    # An unknown state is a bug, and the safe direction is to keep protecting
    # while it is investigated. Failing closed here would take protection away
    # from a paying customer because of a typo in a migration.
    return built(GRACE, True,
                 "We could not confirm your subscription. Your devices are "
                 "still protected while we check.",
                 now + timedelta(days=GRACE_PERIOD_DAYS))


# ---------------------------------------------------------------------------
# Device caps
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnrollmentDecision:
    """Whether one more device may be enrolled.

    NOTE WHAT IS ABSENT: there is no "evicted" field, and there never will be.
    At the cap the answer is no -- see docs/MULTI-DEVICE.md rule 1. Silently
    dropping the least-recently-seen device to make room would leave a real
    device unprotected with nobody told, which is the one failure this product
    cannot afford.
    """

    allowed: bool
    reason: str
    devices_in_use: int
    devices_allowed: int
    #: The tier to offer when they are at the cap. There is no per-device
    #: add-on, so this is the only route to more devices.
    upgrade_to: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "devices_in_use": self.devices_in_use,
            "devices_allowed": self.devices_allowed,
            "upgrade_to": self.upgrade_to,
        }


def can_enroll_device(
    *, entitlement: Entitlement, devices_in_use: int
) -> EnrollmentDecision:
    if not entitlement.protected:
        return EnrollmentDecision(
            allowed=False,
            reason=entitlement.reason,
            devices_in_use=devices_in_use,
            devices_allowed=entitlement.devices_allowed,
            upgrade_to=None,
        )

    if devices_in_use >= entitlement.devices_allowed:
        nxt = next_tier(entitlement.tier_name)
        if nxt:
            offer = (
                f" {tier(nxt)['display_name']} covers "
                f"{device_limit(nxt)} devices."
            )
        else:
            offer = " Remove a device you no longer use to add this one."
        return EnrollmentDecision(
            allowed=False,
            reason=(
                f"You're using all {entitlement.devices_allowed} devices on "
                f"your plan.{offer}"
            ),
            devices_in_use=devices_in_use,
            devices_allowed=entitlement.devices_allowed,
            upgrade_to=nxt,
        )

    return EnrollmentDecision(
        allowed=True,
        reason="",
        devices_in_use=devices_in_use,
        devices_allowed=entitlement.devices_allowed,
        upgrade_to=None,
    )


def downgrade_requires_grace(*, to_tier: str, devices_in_use: int) -> bool:
    """Would this downgrade leave more devices enrolled than the tier allows?

    If so the subscription enters ``grace`` rather than the API deactivating
    the excess. Which devices to keep is the person's decision, and taking it
    from them by picking the N most recent is how a phone silently stops being
    protected. docs/MULTI-DEVICE.md rule 3.
    """
    return devices_in_use > device_limit(to_tier)
