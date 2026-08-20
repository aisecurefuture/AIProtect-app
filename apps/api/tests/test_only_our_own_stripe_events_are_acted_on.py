"""One Stripe account, several products. Only ours may move our subscriptions.

WHY THIS IS NOT SOLVABLE IN STRIPE'S CONFIGURATION
==================================================
A Stripe webhook endpoint is filtered by event TYPE, not by product. There is
no setting that says "send me only AIProtect events". On an account that also
sells something else, this endpoint receives every `invoice.paid`,
`invoice.payment_failed` and `customer.subscription.updated` on the account.
Telling them apart is the application's job, and this is where it is pinned.

THE SHARP ONE: A SHARED CUSTOMER
================================
`_find_subscription` falls back to matching on `customer`. One person can hold
ONE Stripe Customer across several of the account's products -- that is the
normal thing for Stripe to do when the same email buys twice. Without a
positive ownership check, that other product's `invoice.payment_failed`
matches this product's subscription by customer id and pushes it to `grace`,
carrying a paying customer toward `lapsed` because something they bought
elsewhere failed to renew.

That inverts the rule the whole billing module is built around: protection
never stops as a side effect. It would stop as a side effect of an unrelated
product's dunning.

THREE INDEPENDENT SIGNALS, ANY ONE SUFFICIENT
=============================================
  1. our PRODUCT_TAG in the object metadata -- checkout sessions and
     subscriptions, which we stamp at creation
  2. a price id we sell -- invoices, which carry prices on line items and do
     NOT inherit the subscription's metadata
  3. a Stripe subscription id already in our own table

Customer identity is deliberately NOT one of them.
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

API = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(API))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

import billing  # noqa: E402
import entitlements as ent  # noqa: E402
from models import Account, Base, ProcessedWebhookEvent, Subscription  # noqa: E402

OURS_FAMILY_ANNUAL = "price_ours_family_annual"
OURS_PERSONAL_MONTHLY = "price_ours_personal_monthly"
THEIRS = "price_some_other_product"

PRICES = {
    "STRIPE_PRICE_PERSONAL_MONTHLY": OURS_PERSONAL_MONTHLY,
    "STRIPE_PRICE_PERSONAL_ANNUAL": "price_ours_personal_annual",
    "STRIPE_PRICE_PRO_MONTHLY": "price_ours_pro_monthly",
    "STRIPE_PRICE_PRO_ANNUAL": "price_ours_pro_annual",
    "STRIPE_PRICE_FAMILY_MONTHLY": "price_ours_family_monthly",
    "STRIPE_PRICE_FAMILY_ANNUAL": OURS_FAMILY_ANNUAL,
}


def _db():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _subscription(db, *, customer="cus_shared", sub_id="sub_ours", email="a@example.com"):
    acct = Account(email=email)
    db.add(acct)
    db.flush()
    sub = Subscription(
        owner_account_id=acct.id, tier="family", state=ent.ACTIVE,
        stripe_customer_id=customer, stripe_subscription_id=sub_id,
    )
    db.add(sub)
    db.flush()
    return sub


def _event(event_type, obj, *, evt_id="evt_1"):
    return {"id": evt_id, "type": event_type, "created": int(time.time()),
            "data": {"object": obj}}


class AnotherProductsEventIsIgnored(unittest.TestCase):
    def test_a_shared_customers_other_product_does_not_touch_our_subscription(self):
        """THE CORE PROPERTY. Same Stripe Customer, different product. Their
        failed invoice must not move our subscription toward lapsed."""
        db = _db()
        sub = _subscription(db, customer="cus_shared", sub_id="sub_ours")

        foreign = _event("invoice.payment_failed", {
            "object": "invoice",
            "customer": "cus_shared",                 # SAME customer
            "subscription": "sub_their_other_product",
            "lines": {"data": [{"price": {"id": THEIRS}}]},
        })

        with mock.patch.dict(os.environ, PRICES, clear=False):
            out = billing.handle_event(db, foreign)

        self.assertFalse(out.applied)
        self.assertEqual(out.reason, "not this product's event")
        self.assertEqual(sub.state, ent.ACTIVE, "another product moved our state")
        self.assertIsNone(sub.grace_ends_at)

    def test_a_foreign_event_is_not_recorded_in_our_replay_table(self):
        """Otherwise another product's traffic grows this table without bound,
        and the replay log stops being a signal about our own billing."""
        db = _db()
        _subscription(db)
        foreign = _event("invoice.paid", {
            "object": "invoice", "customer": "cus_someone_else",
            "subscription": "sub_theirs",
            "lines": {"data": [{"price": {"id": THEIRS}}]},
        }, evt_id="evt_foreign")

        with mock.patch.dict(os.environ, PRICES, clear=False):
            billing.handle_event(db, foreign)

        rows = db.query(ProcessedWebhookEvent).all()
        self.assertEqual([r.id for r in rows], [], "foreign event was recorded")

    def test_a_foreign_event_is_acknowledged_not_errored(self):
        """An endpoint that fails forever gets disabled by Stripe, taking the
        events we DO need with it. A foreign event is not a failure."""
        db = _db()
        foreign = _event("customer.subscription.updated", {
            "object": "subscription", "id": "sub_theirs",
            "customer": "cus_theirs", "status": "canceled",
        })
        with mock.patch.dict(os.environ, PRICES, clear=False):
            out = billing.handle_event(db, foreign)   # must not raise
        self.assertFalse(out.applied)


class OurOwnEventsStillGetThrough(unittest.TestCase):
    def test_our_metadata_tag_identifies_an_event(self):
        db = _db()
        sub = _subscription(db, sub_id="sub_ours")
        evt = _event("customer.subscription.updated", {
            "object": "subscription", "id": "sub_ours", "customer": "cus_shared",
            "status": "active", "metadata": {"product": billing.PRODUCT_TAG},
        })
        with mock.patch.dict(os.environ, PRICES, clear=False):
            out = billing.handle_event(db, evt)
        self.assertTrue(out.applied, f"our own event was rejected: {out.reason}")

    def test_an_invoice_is_identified_by_a_price_we_sell(self):
        """Invoices do NOT inherit the subscription's metadata, so the price
        is the only signal available on them."""
        db = _db()
        _subscription(db, sub_id="sub_ours")
        evt = _event("invoice.paid", {
            "object": "invoice", "customer": "cus_shared", "subscription": "sub_ours",
            "lines": {"data": [{"price": {"id": OURS_FAMILY_ANNUAL}}]},
        })
        with mock.patch.dict(os.environ, PRICES, clear=False):
            self.assertTrue(billing.event_is_ours(evt))

    def test_a_known_subscription_id_identifies_an_event(self):
        """Belt and braces for anything carrying neither tag nor price."""
        evt = _event("customer.subscription.deleted", {
            "object": "subscription", "id": "sub_ours", "customer": "cus_shared",
        })
        with mock.patch.dict(os.environ, PRICES, clear=False):
            self.assertFalse(billing.event_is_ours(evt))
            self.assertTrue(
                billing.event_is_ours(evt, known_subscription_ids={"sub_ours"})
            )

    def test_the_newer_line_item_shape_is_understood(self):
        """Stripe moved the price under lines[].pricing.price_details. Missing
        it would silently reclassify every one of our invoices as foreign."""
        evt = _event("invoice.paid", {
            "object": "invoice", "customer": "cus_x", "subscription": "sub_y",
            "lines": {"data": [
                {"pricing": {"price_details": {"price": OURS_PERSONAL_MONTHLY}}}
            ]},
        })
        with mock.patch.dict(os.environ, PRICES, clear=False):
            self.assertTrue(billing.event_is_ours(evt))

    def test_checkout_stamps_the_product_tag(self):
        """If checkout stops stamping it, every later subscription event for
        that customer loses its strongest signal."""
        captured = {}

        class _S:
            id = "cs_1"
            url = "https://checkout.example/cs_1"

        class _Sessions:
            @staticmethod
            def create(**kw):
                captured.update(kw)
                return _S()

        fake = mock.Mock()
        fake.checkout.Session = _Sessions
        env = dict(PRICES, STRIPE_SECRET_KEY="sk_test")
        with mock.patch.dict(os.environ, env, clear=False), \
             mock.patch.object(billing, "_stripe", return_value=fake):
            billing.create_checkout_session(
                account_email="a@example.com", tier="family",
                cadence="annual", subscription_id="sub_1",
            )

        self.assertEqual(captured["metadata"]["product"], billing.PRODUCT_TAG)
        self.assertEqual(
            captured["subscription_data"]["metadata"]["product"], billing.PRODUCT_TAG,
            "the SUBSCRIPTION must carry the tag -- it is what later "
            "customer.subscription.* events are read from",
        )


class OursButOrphaned(unittest.TestCase):
    def test_our_event_with_no_matching_row_is_acked_distinctly(self):
        """Different from a foreign event, and worth a different reason: this
        one IS ours and we have no row for it, which is a real anomaly rather
        than routine cross-product noise."""
        db = _db()                                  # no subscriptions at all
        evt = _event("invoice.paid", {
            "object": "invoice", "customer": "cus_unknown",
            "subscription": "sub_unknown",
            "lines": {"data": [{"price": {"id": OURS_FAMILY_ANNUAL}}]},
        })
        with mock.patch.dict(os.environ, PRICES, clear=False):
            out = billing.handle_event(db, evt)
        self.assertFalse(out.applied)
        self.assertEqual(out.reason, "no matching subscription")


class WithNoPricesConfigured(unittest.TestCase):
    def test_price_matching_degrades_without_claiming_everything(self):
        """If the price env vars are unset, `our_price_ids()` is empty. That
        must not make the price test match every event -- an empty set of our
        prices means we cannot identify by price, not that all prices are
        ours."""
        blank = dict.fromkeys(PRICES, "")
        evt = _event("invoice.paid", {
            "object": "invoice", "customer": "cus_x", "subscription": "sub_x",
            "lines": {"data": [{"price": {"id": THEIRS}}]},
        })
        with mock.patch.dict(os.environ, blank, clear=False):
            self.assertFalse(billing.event_is_ours(evt))


if __name__ == "__main__":
    unittest.main()
