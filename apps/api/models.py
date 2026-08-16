"""Consumer data model: accounts, subscriptions, devices, surfaces.

WHAT IS NOT HERE
================
No tenant. No organisation. No role hierarchy. This product has a person, the
people they share a plan with, and the things they own. `make
verify-consumer-scope` fails the build if `tenant_id` appears anywhere under
apps/ -- see README.md rule 1.

THE SHAPE THAT MATTERS
======================
    Account          a person who can sign in
      └─ Subscription    one per owning account; tier + billing state
           ├─ Member          Family only: other people on the plan
           └─ Device          a thing you point at: *this laptop*
                └─ Surface        an install on it: extension, agent, app

`Device` and `Surface` are separate tables and that is the entire
one-device-many-surfaces decision made concrete (docs/MULTI-DEVICE.md). A
laptop running the browser extension and the desktop agent is ONE Device row
with TWO Surface rows: one subscription slot, one rate-limit bucket, two
separately revocable credentials.

Getting this wrong in either direction is expensive. Merge them and a laptop
burns three slots. Split the *slot* per surface and the device rate limit
silently triples, with no ceiling underneath to catch it.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, String, Text,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Account(Base):
    """A person who can sign in."""

    __tablename__ = "accounts"

    id = Column(String, primary_key=True, default=lambda: _uid("acct"))
    email = Column(String, nullable=False, unique=True, index=True)
    display_name = Column(String, nullable=True)

    # Optional second factor. The consumer default is passwordless email codes;
    # TOTP is opt-in for people who want it. Secret is stored encrypted via
    # cyberarmor_core.crypto.totp.TOTPCipher -- never in the clear.
    totp_secret_encrypted = Column(Text, nullable=True)
    totp_enabled = Column(Boolean, nullable=False, default=False)

    # Federated sign-in subject ids. Nullable because email-code sign-in is the
    # baseline and neither provider is required.
    apple_subject = Column(String, nullable=True, unique=True, index=True)
    google_subject = Column(String, nullable=True, unique=True, index=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    #: Set when a person asks for deletion. The row survives briefly so an
    #: in-flight billing webhook has something to land on; the purge job is
    #: what actually removes it. GDPR/CCPA erasure, not a soft-delete flag
    #: that quietly means "hidden".
    deletion_requested_at = Column(DateTime(timezone=True), nullable=True)

    subscription = relationship(
        "Subscription", back_populates="owner", uselist=False,
        cascade="all, delete-orphan",
    )


class Subscription(Base):
    """Tier and billing state. One per owning account."""

    __tablename__ = "subscriptions"

    id = Column(String, primary_key=True, default=lambda: _uid("sub"))
    owner_account_id = Column(
        String, ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )

    #: A key in shared/tiers.json. Never a device count -- the count is derived
    #: from the tier so the two cannot disagree.
    tier = Column(String, nullable=False, default="personal")

    #: trialing | active | grace | lapsed. See entitlements.py; `grace` is the
    #: state that keeps a failed payment or an oversized downgrade from
    #: silently removing protection.
    state = Column(String, nullable=False, default="trialing")

    trial_ends_at = Column(DateTime(timezone=True), nullable=True)
    grace_ends_at = Column(DateTime(timezone=True), nullable=True)

    #: apple | google | stripe. Which store or processor owns the truth about
    #: this subscription; reconciliation needs to know who to ask.
    billing_source = Column(String, nullable=True)
    billing_reference = Column(String, nullable=True)

    #: Stripe identifiers. Indexed because a webhook arrives knowing only
    #: these -- there is no account id in the payload, so this is how an event
    #: finds the subscription it is about.
    stripe_customer_id = Column(String, nullable=True, unique=True, index=True)
    stripe_subscription_id = Column(String, nullable=True, unique=True, index=True)

    #: `created` of the most recent Stripe event applied to this row. An event
    #: older than this is a late delivery and is ignored: Stripe guarantees
    #: delivery, not order, and letting a stale `past_due` land after a
    #: recovered `active` would put a paying customer into grace.
    last_billing_event_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at = Column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )

    owner = relationship("Account", back_populates="subscription")
    members = relationship(
        "Member", back_populates="subscription", cascade="all, delete-orphan"
    )
    devices = relationship(
        "Device", back_populates="subscription", cascade="all, delete-orphan"
    )


class Member(Base):
    """Another person on a Family plan."""

    __tablename__ = "members"
    __table_args__ = (UniqueConstraint("subscription_id", "email"),)

    id = Column(String, primary_key=True, default=lambda: _uid("mem"))
    subscription_id = Column(
        String, ForeignKey("subscriptions.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    email = Column(String, nullable=False)
    account_id = Column(String, ForeignKey("accounts.id"), nullable=True)

    #: standard | strict | kids. The preset applied to this member's devices.
    #: "kids" is the parental control: the owner sets it, the member cannot
    #: change it.
    preset = Column(String, nullable=False, default="standard")
    #: Only the owner may change a member's preset or remove them.
    is_owner = Column(Boolean, nullable=False, default=False)

    invited_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    accepted_at = Column(DateTime(timezone=True), nullable=True)

    subscription = relationship("Subscription", back_populates="members")


class Device(Base):
    """A thing a person points at. Consumes exactly one subscription slot."""

    __tablename__ = "devices"

    id = Column(String, primary_key=True, default=lambda: _uid("dev"))
    subscription_id = Column(
        String, ForeignKey("subscriptions.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    #: Which member this device belongs to, for Family preset assignment.
    member_id = Column(String, ForeignKey("members.id"), nullable=True)

    #: What the person calls it. Shown in Activity: "Blocked on your iPhone".
    name = Column(String, nullable=False)
    #: ios | android | macos | windows | linux. Informational.
    platform = Column(String, nullable=True)

    #: Best-effort machine hint used ONLY to *offer* "is this the same iPhone
    #: you enrolled in March?" when someone re-enrolls after a wipe. Never used
    #: to merge two devices automatically -- a wrong match silently collapses
    #: two real machines into one, which is worse than the extra slot it saves.
    #: docs/MULTI-DEVICE.md rule 2.
    machine_hint = Column(String, nullable=True, index=True)

    enrolled_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)

    #: Revocation is a timestamp, not a delete: the Activity feed still needs
    #: to attribute past events to a device that is no longer enrolled.
    #: A revoked device frees its slot immediately.
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    subscription = relationship("Subscription", back_populates="devices")
    surfaces = relationship(
        "Surface", back_populates="device", cascade="all, delete-orphan"
    )

    @property
    def active(self) -> bool:
        return self.revoked_at is None


class Surface(Base):
    """One install on a device. Does NOT consume a subscription slot."""

    __tablename__ = "surfaces"
    __table_args__ = (UniqueConstraint("device_id", "kind"),)

    id = Column(String, primary_key=True, default=lambda: _uid("srf"))
    device_id = Column(
        String, ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    #: browser-extension | desktop-agent | mobile-app. Matches the `source`
    #: the trust gate already carries, so attribution lines up end to end.
    kind = Column(String, nullable=False)

    #: Per-surface credential, hashed. Uninstalling the extension must be able
    #: to revoke it without touching the agent on the same machine -- so the
    #: credential lives here and not on Device.
    credential_hash = Column(String, nullable=False)

    installed_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    device = relationship("Device", back_populates="surfaces")

    @property
    def active(self) -> bool:
        return self.revoked_at is None


class JoinCode(Base):
    """Short-lived code that attaches a NEW surface to an EXISTING device.

    This is how two installs on one machine arrive at the same `device_id`
    (docs/MULTI-DEVICE.md question 4). The alternative -- deriving a machine
    fingerprint and letting surfaces converge on it silently -- was rejected as
    the primary mechanism: a wrong match merges two real machines, and the
    failure is invisible. An explicit six-character code shown in the surface
    that is already enrolled cannot mis-merge.

    `machine_hint` still exists on Device, but only to *offer* a match for
    confirmation, never to decide one.
    """

    __tablename__ = "join_codes"

    code = Column(String, primary_key=True)
    device_id = Column(
        String, ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)

    @staticmethod
    def new_code() -> str:
        # Digits + unambiguous uppercase letters. No O/0, I/1, S/5: this gets
        # read off one screen and typed into another, sometimes by a child.
        alphabet = "ABCDEFGHJKLMNPQRTUVWXYZ2346789"
        return "".join(secrets.choice(alphabet) for _ in range(6))


class LoginCode(Base):
    """Passwordless email sign-in code."""

    __tablename__ = "login_codes"

    id = Column(String, primary_key=True, default=lambda: _uid("lc"))
    email = Column(String, nullable=False, index=True)
    #: Hashed, never stored in the clear: this table is a set of live
    #: credentials until each row expires.
    code_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    #: Bounded so a captured code cannot be brute-forced within its lifetime.
    attempts = Column(Integer, nullable=False, default=0)


class ProcessedWebhookEvent(Base):
    """Every Stripe event id we have already applied.

    Stripe delivers AT LEAST ONCE and retries for up to three days on any
    non-2xx. Without this table a retried `customer.subscription.deleted`
    re-lapses a subscription the customer has since fixed, and a retried
    checkout completion could extend a trial twice. The primary key IS the
    idempotency mechanism: the insert fails on a duplicate, so a re-delivery
    cannot reach the handler at all.
    """

    __tablename__ = "processed_webhook_events"

    #: Stripe's `evt_...` id.
    id = Column(String, primary_key=True)
    event_type = Column(String, nullable=False)
    #: Stripe's own `created`, not ours. Used to reject events that arrive
    #: out of order -- Stripe makes no ordering guarantee, and a late
    #: `past_due` overwriting a current `active` would put a paying customer
    #: into grace.
    event_created = Column(DateTime(timezone=True), nullable=False)
    received_at = Column(DateTime(timezone=True), nullable=False, default=_now)


class Session(Base):
    """A signed-in session. Long-lived refresh for mobile, short access token."""

    __tablename__ = "sessions"

    id = Column(String, primary_key=True, default=lambda: _uid("sess"))
    account_id = Column(
        String, ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    refresh_token_hash = Column(String, nullable=False, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    #: Which surface/app this session was created from, for "sign out
    #: everywhere" to be able to show a person what they are signing out.
    user_agent = Column(String, nullable=True)
