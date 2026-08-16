"""The webhook is the only endpoint a stranger can reach. It has to hold.

Everything else on this API sits behind a session. `/billing/webhook` is open
to the internet by necessity, and what it does is change what people are
entitled to -- so a flaw in it lets anyone cancel anybody's subscription, or
grant themselves Family for free.

Four separate things have to be true, and each fails silently on its own:

  SIGNATURE  an unsigned or wrongly-signed body is never processed
  REPLAY     Stripe delivers at least once and retries for three days; the
             same event applied twice must not double-apply
  ORDER      Stripe guarantees delivery, NOT order; a late `past_due` must not
             overwrite a recovered `active`
  PROTECTION a failed payment is grace, not lapsed -- a card that expired on
             holiday must not remove security software from a phone
"""

from __future__ import annotations

import hmac
import json
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

API = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(API))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

import billing  # noqa: E402
import devices as dv  # noqa: E402
import entitlements as ent  # noqa: E402
from models import Account, Base, Subscription  # noqa: E402

SECRET = "whsec_test_secret"


def _db():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _subscription(db, *, state=ent.ACTIVE, tier="personal"):
    acct = Account(email="a@example.com")
    db.add(acct)
    db.flush()
    sub = Subscription(
        owner_account_id=acct.id, tier=tier, state=state,
        stripe_customer_id="cus_123", stripe_subscription_id="sub_123",
    )
    db.add(sub)
    db.flush()
    return sub


def _sign(payload: bytes, *, secret=SECRET, timestamp=None) -> str:
    ts = timestamp if timestamp is not None else int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + payload, sha256).hexdigest()
    return f"t={ts},v1={sig}"


def _event(event_type, *, evt_id="evt_1", created=None, obj=None):
    return {
        "id": evt_id,
        "type": event_type,
        "created": created if created is not None else int(time.time()),
        "data": {"object": obj or {
            "object": "subscription", "id": "sub_123",
            "customer": "cus_123", "status": "active",
        }},
    }


class ASignatureIsRequired(unittest.TestCase):
    def test_a_correct_signature_passes(self):
        body = b'{"hello":"world"}'
        billing.verify_signature(
            payload=body, signature_header=_sign(body), secret=SECRET
        )

    def test_a_wrong_secret_is_refused(self):
        body = b'{"hello":"world"}'
        header = _sign(body, secret="whsec_attacker")
        with self.assertRaises(billing.WebhookError):
            billing.verify_signature(
                payload=body, signature_header=header, secret=SECRET
            )

    def test_a_tampered_body_is_refused(self):
        """The signature covers the body. Change one byte and it must fail --
        otherwise an attacker replays a real event with edited contents."""
        header = _sign(b'{"amount":100}')
        with self.assertRaises(billing.WebhookError):
            billing.verify_signature(
                payload=b'{"amount":999999}', signature_header=header, secret=SECRET
            )

    def test_an_old_signature_is_refused(self):
        """The tolerance window IS the replay window for a captured request."""
        body = b'{"hello":"world"}'
        header = _sign(body, timestamp=int(time.time()) - 3600)
        with self.assertRaises(billing.WebhookError):
            billing.verify_signature(
                payload=body, signature_header=header, secret=SECRET
            )

    def test_a_future_signature_is_refused(self):
        body = b'{"hello":"world"}'
        header = _sign(body, timestamp=int(time.time()) + 3600)
        with self.assertRaises(billing.WebhookError):
            billing.verify_signature(
                payload=body, signature_header=header, secret=SECRET
            )

    def test_a_missing_header_is_refused(self):
        for header in ("", "garbage", "t=123", "v1=abc", "t=notanumber,v1=abc"):
            with self.subTest(header=header):
                with self.assertRaises(billing.WebhookError):
                    billing.verify_signature(
                        payload=b"{}", signature_header=header, secret=SECRET
                    )

    def test_an_unset_secret_refuses_everything(self):
        """A misconfiguration must not become an open endpoint that anyone can
        use to cancel subscriptions."""
        body = b"{}"
        with self.assertRaises(billing.WebhookError):
            billing.verify_signature(
                payload=body, signature_header=_sign(body), secret=""
            )

    def test_rotation_with_two_signatures_works(self):
        """Stripe sends several v1 entries while a webhook secret is rotating.
        Any one matching is enough, or a rotation is an outage."""
        body = b'{"hello":"world"}'
        good = _sign(body).split("v1=")[1]
        ts = _sign(body).split(",")[0].split("=")[1]
        header = f"t={ts},v1=deadbeef,v1={good}"
        billing.verify_signature(
            payload=body, signature_header=header, secret=SECRET
        )


class AnEventIsAppliedExactlyOnce(unittest.TestCase):
    def test_the_same_event_twice_applies_once(self):
        db = _db()
        sub = _subscription(db, state=ent.ACTIVE)
        evt = _event("customer.subscription.deleted", evt_id="evt_dup")

        first = billing.handle_event(db, evt)
        second = billing.handle_event(db, evt)

        self.assertTrue(first.applied)
        self.assertFalse(second.applied)
        self.assertEqual(second.reason, "already processed")

    def test_a_retry_cannot_re_lapse_a_recovered_subscription(self):
        """The concrete damage replay would do. Stripe retries for three days;
        by then the customer may have fixed their card."""
        db = _db()
        sub = _subscription(db, state=ent.ACTIVE)
        cancel = _event("customer.subscription.deleted", evt_id="evt_cancel",
                        created=int(time.time()) - 100)
        billing.handle_event(db, cancel)
        self.assertEqual(sub.state, ent.LAPSED)

        # customer resubscribes
        sub.state = ent.ACTIVE
        db.flush()

        billing.handle_event(db, cancel)          # Stripe retries the old one
        self.assertEqual(sub.state, ent.ACTIVE, "a replay re-lapsed them")


class OutOfOrderEventsDoNotWin(unittest.TestCase):
    def test_a_late_failure_does_not_overwrite_a_recovery(self):
        """Stripe guarantees delivery, not order. Without this a paying
        customer lands in grace because an old event arrived late."""
        db = _db()
        sub = _subscription(db, state=ent.ACTIVE)
        now = int(time.time())

        recovered = _event("invoice.paid", evt_id="evt_paid", created=now)
        billing.handle_event(db, recovered)
        self.assertEqual(sub.state, ent.ACTIVE)

        stale = _event("invoice.payment_failed", evt_id="evt_failed",
                       created=now - 600)
        outcome = billing.handle_event(db, stale)

        self.assertFalse(outcome.applied)
        self.assertEqual(outcome.reason, "stale event")
        self.assertEqual(sub.state, ent.ACTIVE)


class ProtectionSurvivesBillingTrouble(unittest.TestCase):
    def test_a_failed_payment_is_grace_not_lapsed(self):
        """A card that expired on holiday must not remove the security
        software from somebody's phone."""
        db = _db()
        sub = _subscription(db, state=ent.ACTIVE)
        billing.handle_event(db, _event("invoice.payment_failed", evt_id="e1"))

        self.assertEqual(sub.state, ent.GRACE)
        resolved = ent.resolve(
            state=sub.state, tier_name=sub.tier, grace_ends_at=sub.grace_ends_at
        )
        self.assertTrue(resolved.protected)
        self.assertIsNotNone(sub.grace_ends_at, "grace needs a deadline")

    def test_past_due_maps_to_grace(self):
        self.assertEqual(billing.state_for_status("past_due"), ent.GRACE)
        self.assertEqual(billing.state_for_status("unpaid"), ent.GRACE)

    def test_only_an_ended_subscription_lapses(self):
        self.assertEqual(billing.state_for_status("canceled"), ent.LAPSED)
        self.assertEqual(billing.state_for_status("incomplete_expired"), ent.LAPSED)

    def test_an_unknown_stripe_status_keeps_protecting(self):
        """The day Stripe adds a status, nobody should lose protection."""
        self.assertEqual(billing.state_for_status("some_future_status"), ent.GRACE)
        self.assertEqual(billing.state_for_status(""), ent.GRACE)

    def test_paying_clears_the_grace_deadline(self):
        db = _db()
        sub = _subscription(db, state=ent.GRACE)
        sub.grace_ends_at = datetime.now(timezone.utc) + timedelta(days=3)
        db.flush()
        billing.handle_event(db, _event("invoice.paid", evt_id="e_paid"))
        self.assertEqual(sub.state, ent.ACTIVE)
        self.assertIsNone(sub.grace_ends_at)


class ADowngradeDoesNotPickWhichDevicesStop(unittest.TestCase):
    def test_an_oversized_downgrade_goes_to_grace(self):
        """Family (30) -> Personal (3) with 6 devices enrolled. Deactivating
        3 of them ourselves would choose which of the person's things stop
        being protected. That is their decision."""
        db = _db()
        sub = _subscription(db, state=ent.ACTIVE, tier="family")
        for i in range(6):
            dv.enroll_device(db, subscription=sub, name=f"d{i}",
                             surface_kind="mobile-app")

        evt = _event("customer.subscription.updated", evt_id="evt_down", obj={
            "object": "subscription", "id": "sub_123", "customer": "cus_123",
            "status": "active", "metadata": {"tier": "personal"},
        })
        outcome = billing.handle_event(db, evt)

        self.assertEqual(sub.state, ent.GRACE)
        self.assertIn("device choices", outcome.reason)
        self.assertEqual(dv.active_device_count(db, sub.id), 6,
                         "devices were deactivated behind the person's back")

    def test_a_downgrade_that_fits_applies_immediately(self):
        db = _db()
        sub = _subscription(db, state=ent.ACTIVE, tier="family")
        dv.enroll_device(db, subscription=sub, name="phone",
                         surface_kind="mobile-app")
        evt = _event("customer.subscription.updated", evt_id="evt_ok", obj={
            "object": "subscription", "id": "sub_123", "customer": "cus_123",
            "status": "active", "metadata": {"tier": "personal"},
        })
        billing.handle_event(db, evt)
        self.assertEqual(sub.tier, "personal")
        self.assertEqual(sub.state, ent.ACTIVE)


class UnusableEventsAreAcknowledged(unittest.TestCase):
    def test_an_unhandled_type_is_not_an_error(self):
        """Stripe sends a great many events. 2xx keeps the ones we do not use
        out of the three-day retry queue."""
        db = _db()
        _subscription(db)
        out = billing.handle_event(db, _event("charge.succeeded", evt_id="e_x"))
        self.assertFalse(out.applied)
        self.assertEqual(out.reason, "event type not handled")

    def test_an_event_for_an_unknown_subscription_is_acknowledged(self):
        """Retrying cannot conjure a row we do not have, and an endpoint that
        fails forever gets disabled by Stripe -- taking the events we DO need
        with it."""
        db = _db()
        out = billing.handle_event(db, _event("invoice.paid", evt_id="e_orphan"))
        self.assertFalse(out.applied)
        self.assertEqual(out.reason, "no matching subscription")

    def test_an_event_with_no_id_is_rejected(self):
        db = _db()
        with self.assertRaises(billing.WebhookError):
            billing.handle_event(db, {"type": "invoice.paid", "created": 1})

    def test_a_non_json_body_is_rejected(self):
        with self.assertRaises(billing.WebhookError):
            billing.parse_event(b"not json at all")


class TheTrialReminderIsWired(unittest.TestCase):
    def test_trial_will_end_is_handled(self):
        """Stripe fires this three days out, which is exactly
        tiers.json -> trial.reminder_days_before_charge. It is both the
        conversion moment and the required advance notice."""
        db = _db()
        sub = _subscription(db, state=ent.TRIALING)
        out = billing.handle_event(
            db, _event("customer.subscription.trial_will_end", evt_id="e_tw")
        )
        self.assertTrue(out.applied)
        self.assertEqual(sub.state, ent.TRIALING, "the reminder changed state")

    def test_the_reminder_window_matches_the_pricing_decision(self):
        self.assertEqual(ent.trial_reminder_days(), 3)


if __name__ == "__main__":
    unittest.main()
