"""Enrolling, joining, and revoking devices and the surfaces on them.

The rules this file enforces are in docs/MULTI-DEVICE.md. Three of them are
easy to implement backwards, and each one fails silently when you do:

  rule 1  At the cap, REFUSE the new device. Never evict an old one to make
          room -- that leaves a real device unprotected with nobody told.
  rule 2  A wiped device must not burn a second slot. Handled by OFFERING a
          match, never by deciding one: a wrong automatic match merges two
          real machines and the person cannot see that it happened.
  rule 4  Revoking a device revokes every surface on it. A lost laptop is lost
          entirely, and revoking it one surface at a time is a way to miss one.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

import entitlements
from models import Device, JoinCode, Subscription, Surface

#: How long a join code is valid. Long enough to walk to the other machine,
#: short enough that a code glimpsed on a screen is not a standing invitation.
JOIN_CODE_TTL_MINUTES = 15

#: Surfaces we know how to install. Matches the `source` vocabulary the trust
#: gate already carries, so attribution lines up end to end.
KNOWN_SURFACES = ("browser-extension", "desktop-agent", "mobile-app")


def _hash_credential(raw: str) -> str:
    """SHA-256 is correct here, and deliberately not a slow KDF.

    These are 256-bit random tokens we generate, not passwords a person chose.
    There is no dictionary to attack, so key stretching buys nothing and would
    add latency to every authenticated request from every device.
    """
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _new_credential() -> Tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    return raw, _hash_credential(raw)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Counting
# ---------------------------------------------------------------------------


def surfaces_of(db: DbSession, device: Device) -> List[Surface]:
    """Every surface on a device, QUERIED rather than read off the relationship.

    Not a style choice, and not equivalent. `device.surfaces` is a collection
    loaded once; a surface added later in the same session -- by `join_surface`,
    say -- is not in it. `revoke_device` iterating that stale collection
    revoked one of two surfaces and reported success, which is exactly the
    failure rule 4 exists to prevent: a live credential on a machine the person
    was told had been removed.

    Caught by test_revoking_a_device_revokes_every_surface_on_it. The query
    cannot go stale, so it is the query that is used everywhere it matters.
    """
    return list(db.scalars(select(Surface).where(Surface.device_id == device.id)))


def active_devices(db: DbSession, subscription_id: str) -> List[Device]:
    return list(
        db.scalars(
            select(Device).where(
                Device.subscription_id == subscription_id,
                Device.revoked_at.is_(None),
            )
        )
    )


def active_device_count(db: DbSession, subscription_id: str) -> int:
    """What counts against the cap.

    Devices, not surfaces. A laptop with the extension and the agent is one.
    """
    return len(active_devices(db, subscription_id))


# ---------------------------------------------------------------------------
# Enrolment
# ---------------------------------------------------------------------------


@dataclass
class EnrolledDevice:
    device: Device
    surface: Surface
    #: Returned ONCE, at enrolment. Only the hash is stored, so a person who
    #: loses this re-enrols rather than recovering it.
    credential: str


class EnrollmentRefused(Exception):
    """Carries the decision so the caller can show the person their options."""

    def __init__(self, decision: entitlements.EnrollmentDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


def enroll_device(
    db: DbSession,
    *,
    subscription: Subscription,
    name: str,
    surface_kind: str,
    platform: Optional[str] = None,
    machine_hint: Optional[str] = None,
    member_id: Optional[str] = None,
    now: Optional[datetime] = None,
) -> EnrolledDevice:
    """Enrol a NEW device with its first surface.

    Raises EnrollmentRefused at the cap -- rule 1. The exception carries the
    upgrade target, because with no per-device add-on an upgrade is the only
    way to add devices and a refusal without a route forward is a dead end.
    """
    if surface_kind not in KNOWN_SURFACES:
        raise ValueError(
            f"unknown surface {surface_kind!r}; known: {', '.join(KNOWN_SURFACES)}"
        )

    ent = entitlements.resolve(
        state=subscription.state,
        tier_name=subscription.tier,
        trial_ends_at=subscription.trial_ends_at,
        grace_ends_at=subscription.grace_ends_at,
        now=now,
    )
    decision = entitlements.can_enroll_device(
        entitlement=ent,
        devices_in_use=active_device_count(db, subscription.id),
    )
    if not decision.allowed:
        raise EnrollmentRefused(decision)

    device = Device(
        subscription_id=subscription.id,
        member_id=member_id,
        name=name,
        platform=platform,
        machine_hint=machine_hint,
    )
    db.add(device)
    db.flush()

    raw, hashed = _new_credential()
    surface = Surface(device_id=device.id, kind=surface_kind, credential_hash=hashed)
    db.add(surface)
    db.flush()

    return EnrolledDevice(device=device, surface=surface, credential=raw)


def suggest_existing_device(
    db: DbSession, *, subscription_id: str, machine_hint: Optional[str]
) -> Optional[Device]:
    """Find a revoked device that MIGHT be this machine, re-enrolling.

    Returns a candidate to OFFER -- "is this the same iPhone you enrolled in
    March?" -- and nothing more. Rule 2 is explicit that this must not decide:
    a wrong automatic match merges two real machines into one, and unlike the
    extra slot it would have saved, that failure is invisible to the person it
    happens to.
    """
    if not machine_hint:
        return None
    return db.scalars(
        select(Device)
        .where(
            Device.subscription_id == subscription_id,
            Device.machine_hint == machine_hint,
            Device.revoked_at.is_not(None),
        )
        .order_by(Device.revoked_at.desc())
    ).first()


def reclaim_device(
    db: DbSession, *, device: Device, surface_kind: str
) -> EnrolledDevice:
    """Re-activate a previously revoked device after the person confirmed it.

    Called only when someone answered yes to the offer from
    `suggest_existing_device`. Reuses the slot rather than consuming a new one,
    which is the whole point of rule 2 -- reinstalls and factory resets are
    ordinary life, and a product that charges a slot for each of them looks
    broken well before the person blames their own habits.
    """
    device.revoked_at = None
    device.last_seen_at = _now()

    for existing in surfaces_of(db, device):
        if existing.kind == surface_kind:
            raw, hashed = _new_credential()
            existing.credential_hash = hashed
            existing.revoked_at = None
            existing.last_seen_at = _now()
            db.flush()
            return EnrolledDevice(device=device, surface=existing, credential=raw)

    raw, hashed = _new_credential()
    surface = Surface(device_id=device.id, kind=surface_kind, credential_hash=hashed)
    db.add(surface)
    db.flush()
    return EnrolledDevice(device=device, surface=surface, credential=raw)


# ---------------------------------------------------------------------------
# Surfaces: joining a second install to an existing device
# ---------------------------------------------------------------------------


def create_join_code(db: DbSession, *, device: Device) -> JoinCode:
    """Issue a code from a surface already installed on this machine."""
    code = JoinCode(
        code=JoinCode.new_code(),
        device_id=device.id,
        expires_at=_now() + timedelta(minutes=JOIN_CODE_TTL_MINUTES),
    )
    db.add(code)
    db.flush()
    return code


class JoinFailed(Exception):
    pass


def join_surface(
    db: DbSession, *, subscription_id: str, code: str, surface_kind: str
) -> EnrolledDevice:
    """Attach a new surface to the device that issued `code`.

    THIS CONSUMES NO SUBSCRIPTION SLOT. That is the point: the second install
    on a laptop is a surface, not a device. It also means the new surface
    inherits the same `device_id`, so it shares the device's rate-limit bucket
    instead of quietly doubling it.
    """
    if surface_kind not in KNOWN_SURFACES:
        raise ValueError(f"unknown surface {surface_kind!r}")

    row = db.get(JoinCode, (code or "").strip().upper())
    if row is None:
        raise JoinFailed("That code is not valid.")
    if row.used_at is not None:
        raise JoinFailed("That code has already been used.")
    if _now() >= row.expires_at:
        raise JoinFailed("That code has expired. Generate a new one.")

    device = db.get(Device, row.device_id)
    if device is None or device.subscription_id != subscription_id:
        # Wrong account. Same message as an invalid code on purpose -- a
        # distinct one would confirm that a code belongs to somebody else.
        raise JoinFailed("That code is not valid.")
    if not device.active:
        raise JoinFailed("That device is no longer enrolled.")

    for existing in surfaces_of(db, device):
        if existing.kind == surface_kind and existing.active:
            raise JoinFailed(
                f"This device already has {surface_kind} installed."
            )

    raw, hashed = _new_credential()
    surface = Surface(device_id=device.id, kind=surface_kind, credential_hash=hashed)
    db.add(surface)
    row.used_at = _now()
    db.flush()
    return EnrolledDevice(device=device, surface=surface, credential=raw)


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def revoke_device(db: DbSession, *, device: Device) -> int:
    """Revoke a device AND every surface on it. Rule 4.

    Returns the number of surfaces revoked. Revoking surface-by-surface from
    the UI is how one gets missed, and a missed surface on a lost laptop is a
    live credential with a screen that says it was removed.

    The row survives, revoked: the Activity feed still has to attribute past
    events to a device that is no longer enrolled. The subscription slot is
    freed immediately regardless.
    """
    now = _now()
    device.revoked_at = now
    revoked = 0
    for surface in surfaces_of(db, device):
        if surface.active:
            surface.revoked_at = now
            revoked += 1
    db.flush()
    return revoked


def revoke_surface(db: DbSession, *, surface: Surface) -> None:
    """Revoke ONE install, leaving the device and its other surfaces alone.

    Uninstalling the browser extension must not turn off the desktop agent on
    the same machine.
    """
    surface.revoked_at = _now()
    db.flush()


def authenticate_surface(
    db: DbSession, *, credential: str
) -> Optional[Tuple[Device, Surface]]:
    """Resolve a device credential, refusing revoked devices and surfaces.

    Both checks are load-bearing. A surface can be revoked on its own, and a
    device revocation must invalidate surfaces whose own row a caller might
    still hold a credential for.
    """
    hashed = _hash_credential(credential or "")
    surface = db.scalars(
        select(Surface).where(Surface.credential_hash == hashed)
    ).first()
    if surface is None or not surface.active:
        return None
    device = db.get(Device, surface.device_id)
    if device is None or not device.active:
        return None
    surface.last_seen_at = _now()
    device.last_seen_at = _now()
    return device, surface
