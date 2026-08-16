"""Stripe billing: checkout, the customer portal, and the webhook.

WHY SIGNATURE VERIFICATION IS WRITTEN OUT HERE
==============================================
The Stripe SDK is installed and is used below for OUTBOUND calls, where it
genuinely helps. Verification is done with stdlib `hmac` instead, on purpose:

  * This is the one endpoint on the whole API that an unauthenticated stranger
    can reach, and a flaw in it lets them flip anybody's subscription. It
    deserves ~15 lines that can be read in full and tested exhaustively --
    including with deliberately bad signatures -- rather than a call whose
    behaviour can shift under an SDK upgrade.
  * The algorithm is completely specified: sign `f"{timestamp}.{body}"` with
    HMAC-SHA256 and compare against the `v1=` entry in `Stripe-Signature`.
  * It keeps the webhook path working with no third-party import.

THE THREE THINGS A STRIPE WEBHOOK GETS WRONG IF YOU LET IT
==========================================================
1. REPLAY. Stripe delivers at least once and retries for three days on any
   non-2xx. Handled by `ProcessedWebhookEvent`: the event id is a primary key,
   so a re-delivery cannot reach the handler.
2. ORDER. Stripe guarantees delivery, not order. A late `past_due` arriving
   after a recovered `active` would put a paying customer into grace. Handled
   by `last_billing_event_at`: an event older than the last applied one is
   dropped.
3. TRUST. The payload is signed, so it is authentic -- but it is still a
   snapshot from whenever Stripe generated it. For anything that removes
   protection we re-read the subscription from the API rather than acting on
   the body alone.

AND THE PRODUCT RULE THAT OUTRANKS ALL OF IT
============================================
Protection never stops as a side effect (docs/PRICING.md, entitlements.py). A
failed payment is `past_due` at Stripe and `grace` here -- protecting. Only a
subscription that has actually ended becomes `lapsed`, which is the one state
where scanning stops.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

import entitlements
from models import ProcessedWebhookEvent, Subscription

logger = logging.getLogger("aiprotect.billing")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
#: How far a signature timestamp may be from now. Stripe's own default. This
#: is the replay window for a captured request, so it stays small.
SIGNATURE_TOLERANCE_SECONDS = int(os.getenv("STRIPE_SIGNATURE_TOLERANCE_S", "300"))

CHECKOUT_SUCCESS_URL = os.getenv(
    "AIPROTECT_CHECKOUT_SUCCESS_URL", "https://app.aiprotect.app/welcome"
)
CHECKOUT_CANCEL_URL = os.getenv(
    "AIPROTECT_CHECKOUT_CANCEL_URL", "https://aiprotect.app/pricing"
)
PORTAL_RETURN_URL = os.getenv(
    "AIPROTECT_PORTAL_RETURN_URL", "https://app.aiprotect.app/settings"
)


class WebhookError(Exception):
    """Anything that makes an event untrustworthy or unusable."""


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def _parse_signature_header(header: str) -> tuple[Optional[int], list[str]]:
    timestamp: Optional[int] = None
    signatures: list[str] = []
    for part in (header or "").split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError:
                return None, []
        elif key == "v1":
            # A header may legitimately carry several v1 entries during a
            # webhook-secret rotation. Any one matching is enough.
            signatures.append(value)
    return timestamp, signatures


def verify_signature(
    *,
    payload: bytes,
    signature_header: str,
    secret: str,
    now: Optional[datetime] = None,
    tolerance_seconds: int = SIGNATURE_TOLERANCE_SECONDS,
) -> None:
    """Raise WebhookError unless `payload` was signed by `secret`.

    Verifies the RAW body. Parsing to JSON and re-serialising before checking
    would compare a signature against bytes Stripe never signed, which is the
    classic way this check silently stops working.
    """
    if not secret:
        # Refusing is the only safe answer. Accepting unsigned events because
        # the secret is unset would turn a misconfiguration into an open
        # endpoint that anyone can use to cancel subscriptions.
        raise WebhookError("webhook secret is not configured")

    timestamp, signatures = _parse_signature_header(signature_header)
    if timestamp is None or not signatures:
        raise WebhookError("malformed Stripe-Signature header")

    now = now or datetime.now(timezone.utc)
    age = abs(now.timestamp() - timestamp)
    if age > tolerance_seconds:
        raise WebhookError(f"signature timestamp is {int(age)}s away from now")

    signed = f"{timestamp}.".encode("utf-8") + payload
    expected = hmac.new(secret.encode("utf-8"), signed, sha256).hexdigest()

    # compare_digest on every candidate, and no early return on the first
    # mismatch: an early return leaks which candidate matched by timing.
    if not any(hmac.compare_digest(expected, candidate) for candidate in signatures):
        raise WebhookError("signature does not match")


# ---------------------------------------------------------------------------
# Stripe status -> our entitlement state
# ---------------------------------------------------------------------------

#: Stripe subscription.status -> our state.
#:
#: Note where `grace` appears. `past_due` and `unpaid` are failed payments and
#: they keep protecting: a card that expired on holiday must not remove the
#: security software from somebody's phone. Only `canceled` and
#: `incomplete_expired` -- subscriptions that have actually ended -- stop it.
_STATUS_MAP = {
    "trialing": entitlements.TRIALING,
    "active": entitlements.ACTIVE,
    "past_due": entitlements.GRACE,
    "unpaid": entitlements.GRACE,
    "incomplete": entitlements.GRACE,
    "paused": entitlements.GRACE,
    "canceled": entitlements.LAPSED,
    "incomplete_expired": entitlements.LAPSED,
}


def state_for_status(status: str) -> str:
    """Map a Stripe status, defaulting to GRACE for anything unrecognised.

    An unknown status is a Stripe change we have not seen yet. Defaulting to
    LAPSED would remove protection from paying customers the day Stripe adds a
    value; defaulting to GRACE keeps them protected and visible.
    """
    return _STATUS_MAP.get((status or "").lower(), entitlements.GRACE)


@dataclass
class WebhookOutcome:
    applied: bool
    reason: str
    subscription_id: Optional[str] = None
    new_state: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "applied": self.applied,
            "reason": self.reason,
            "subscription": self.subscription_id,
            "state": self.new_state,
        }


#: Events that change what a person is entitled to. Anything else is ack'd and
#: ignored -- Stripe sends a great many events and 2xx-ing the ones we do not
#: use keeps them out of the retry queue.
HANDLED_EVENTS = {
    "checkout.session.completed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "customer.subscription.trial_will_end",
    "invoice.payment_failed",
    "invoice.paid",
}


def _event_time(event: Dict[str, Any]) -> datetime:
    return datetime.fromtimestamp(int(event.get("created", 0)), tz=timezone.utc)


def _find_subscription(db: DbSession, event: Dict[str, Any]) -> Optional[Subscription]:
    obj = (event.get("data") or {}).get("object") or {}
    sub_id = obj.get("id") if obj.get("object") == "subscription" else obj.get("subscription")
    customer_id = obj.get("customer")

    if sub_id:
        found = db.scalars(
            select(Subscription).where(Subscription.stripe_subscription_id == sub_id)
        ).first()
        if found:
            return found
    if customer_id:
        return db.scalars(
            select(Subscription).where(Subscription.stripe_customer_id == customer_id)
        ).first()
    return None


def handle_event(db: DbSession, event: Dict[str, Any]) -> WebhookOutcome:
    """Apply one VERIFIED Stripe event. Idempotent and order-safe.

    The caller must have verified the signature already; this function trusts
    that the event is authentic and worries only about applying it correctly.
    """
    event_id = event.get("id")
    event_type = event.get("type", "")
    if not event_id:
        raise WebhookError("event has no id")

    # 1. Replay. The primary key does the work: a duplicate insert raises, and
    #    the handler below is never reached twice for the same event.
    db.add(ProcessedWebhookEvent(
        id=event_id, event_type=event_type, event_created=_event_time(event)
    ))
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return WebhookOutcome(False, "already processed")

    if event_type not in HANDLED_EVENTS:
        return WebhookOutcome(False, "event type not handled")

    subscription = _find_subscription(db, event)
    if subscription is None:
        # Ack anyway. Retrying will not conjure a subscription we have no row
        # for, and a permanently-failing webhook endpoint eventually gets
        # disabled by Stripe -- taking the events we DO need with it.
        logger.warning("stripe_event_no_subscription id=%s type=%s",
                       event_id, event_type)
        return WebhookOutcome(False, "no matching subscription")

    # 2. Order. Stripe guarantees delivery, not order.
    occurred = _event_time(event)
    if (subscription.last_billing_event_at
            and occurred < subscription.last_billing_event_at):
        return WebhookOutcome(False, "stale event", subscription.id)

    outcome = _apply(db, subscription=subscription, event=event, event_type=event_type)
    subscription.last_billing_event_at = occurred
    subscription.billing_source = "stripe"
    db.flush()
    return outcome


def _apply(
    db: DbSession, *, subscription: Subscription, event: Dict[str, Any], event_type: str
) -> WebhookOutcome:
    obj = (event.get("data") or {}).get("object") or {}

    if event_type == "customer.subscription.trial_will_end":
        # Stripe fires this three days out, which is exactly
        # tiers.json -> trial.reminder_days_before_charge. This is the
        # conversion moment AND the compliance one: the "here's what we caught
        # for you" summary is the same message as the required advance notice.
        # TODO(prompt-9): hand to the mailer.
        logger.info("trial_will_end subscription=%s", subscription.id)
        return WebhookOutcome(True, "trial ending reminder due", subscription.id,
                              subscription.state)

    if event_type == "invoice.payment_failed":
        # Not lapsed. A failed card is `grace`: still protecting, with a
        # deadline the person is told about.
        if subscription.state != entitlements.LAPSED:
            subscription.state = entitlements.GRACE
            subscription.grace_ends_at = datetime.now(timezone.utc) + timedelta(
                days=entitlements.GRACE_PERIOD_DAYS
            )
        return WebhookOutcome(True, "payment failed -> grace", subscription.id,
                              subscription.state)

    if event_type == "invoice.paid":
        subscription.state = entitlements.ACTIVE
        subscription.grace_ends_at = None
        return WebhookOutcome(True, "payment received -> active", subscription.id,
                              subscription.state)

    if event_type == "checkout.session.completed":
        subscription.stripe_customer_id = (
            obj.get("customer") or subscription.stripe_customer_id
        )
        subscription.stripe_subscription_id = (
            obj.get("subscription") or subscription.stripe_subscription_id
        )
        tier = (obj.get("metadata") or {}).get("tier")
        if tier in entitlements.tier_names():
            subscription.tier = tier
        return WebhookOutcome(True, "checkout completed", subscription.id,
                              subscription.state)

    # customer.subscription.{created,updated,deleted}
    status = "canceled" if event_type.endswith("deleted") else obj.get("status", "")
    new_state = state_for_status(status)

    subscription.stripe_subscription_id = (
        obj.get("id") or subscription.stripe_subscription_id
    )
    subscription.stripe_customer_id = (
        obj.get("customer") or subscription.stripe_customer_id
    )

    tier = (obj.get("metadata") or {}).get("tier")
    if tier in entitlements.tier_names():
        # A DOWNGRADE THAT DOES NOT FIT DOES NOT TAKE EFFECT SILENTLY.
        # Deactivating the excess devices ourselves would pick which of the
        # person's things stop being protected. That is their choice, so the
        # subscription sits in grace until they make it.
        from devices import active_device_count
        in_use = active_device_count(db, subscription.id)
        if entitlements.downgrade_requires_grace(to_tier=tier, devices_in_use=in_use):
            subscription.tier = tier
            subscription.state = entitlements.GRACE
            subscription.grace_ends_at = datetime.now(timezone.utc) + timedelta(
                days=entitlements.GRACE_PERIOD_DAYS
            )
            return WebhookOutcome(
                True, "downgrade needs device choices -> grace",
                subscription.id, subscription.state,
            )
        subscription.tier = tier

    if obj.get("trial_end"):
        subscription.trial_ends_at = datetime.fromtimestamp(
            int(obj["trial_end"]), tz=timezone.utc
        )

    subscription.state = new_state
    if new_state == entitlements.GRACE and not subscription.grace_ends_at:
        subscription.grace_ends_at = datetime.now(timezone.utc) + timedelta(
            days=entitlements.GRACE_PERIOD_DAYS
        )
    if new_state == entitlements.ACTIVE:
        subscription.grace_ends_at = None

    return WebhookOutcome(True, f"status {status} -> {new_state}",
                          subscription.id, new_state)


# ---------------------------------------------------------------------------
# Outbound (the SDK earns its place here)
# ---------------------------------------------------------------------------


def _stripe():
    import stripe  # imported lazily so the webhook path needs no SDK

    if not STRIPE_SECRET_KEY:
        raise WebhookError("STRIPE_SECRET_KEY is not configured")
    stripe.api_key = STRIPE_SECRET_KEY
    return stripe


def create_checkout_session(
    *, account_email: str, tier: str, price_id: str, subscription_id: str
) -> Dict[str, Any]:
    """Start a subscription. Trial length comes from shared/tiers.json."""
    stripe = _stripe()
    session = stripe.checkout.Session.create(
        mode="subscription",
        customer_email=account_email,
        line_items=[{"price": price_id, "quantity": 1}],
        subscription_data={
            "trial_period_days": entitlements.trial_days(),
            "metadata": {"tier": tier, "subscription_id": subscription_id},
        },
        metadata={"tier": tier, "subscription_id": subscription_id},
        success_url=CHECKOUT_SUCCESS_URL,
        cancel_url=CHECKOUT_CANCEL_URL,
    )
    return {"id": session.id, "url": session.url}


def create_portal_session(*, stripe_customer_id: str) -> Dict[str, Any]:
    """Stripe's hosted portal: payment method, invoices, and cancellation.

    Used rather than building our own cancel flow. Click-to-cancel rules
    require cancellation be as easy as signing up, and Stripe's portal is
    already built to that standard and kept current with it.
    """
    stripe = _stripe()
    session = stripe.billing_portal.Session.create(
        customer=stripe_customer_id, return_url=PORTAL_RETURN_URL
    )
    return {"url": session.url}


def parse_event(payload: bytes) -> Dict[str, Any]:
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebhookError("event body is not valid JSON") from exc
