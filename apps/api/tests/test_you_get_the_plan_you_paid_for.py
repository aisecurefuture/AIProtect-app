"""The money and the entitlement come from ONE customer choice.

THE DEFECT THIS PREVENTS
========================
`POST /billing/checkout` used to take a tier AND a Stripe price id as two
independent client-supplied values:

    {"tier": "family", "price_id": "price_personal_monthly"}

Both validated. "family" IS a real tier; that price id IS a real price. The
tier is stamped into the checkout session's metadata, and the webhook reads it
back to set `subscription.tier` -- so this request grants 30 devices and 7
people for $4.99/mo, and every check along the way passes.

Nothing bound the two together. The fix is that the client names only the plan
it chose, and the server derives the price from it. There is no longer a
request shape that can express the mismatch.

The second property here is that an unconfigured price FAILS CLOSED. Falling
back to any other tier's price would charge someone for a plan they did not
pick, which is worse than a checkout that refuses.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

API = Path(__file__).resolve().parent.parent           # apps/api
sys.path.insert(0, str(API))

import billing  # noqa: E402
import entitlements  # noqa: E402

PRICES = {
    "STRIPE_PRICE_PERSONAL_MONTHLY": "price_personal_m",
    "STRIPE_PRICE_PERSONAL_ANNUAL": "price_personal_a",
    "STRIPE_PRICE_PRO_MONTHLY": "price_pro_m",
    "STRIPE_PRICE_PRO_ANNUAL": "price_pro_a",
    "STRIPE_PRICE_FAMILY_MONTHLY": "price_family_m",
    "STRIPE_PRICE_FAMILY_ANNUAL": "price_family_a",
}


class ThePriceIsDerivedFromTheTier(unittest.TestCase):
    def test_each_tier_and_cadence_resolves_to_its_own_price(self):
        with mock.patch.dict(os.environ, PRICES, clear=False):
            self.assertEqual(
                billing.price_id_for(tier="personal", cadence="monthly"),
                "price_personal_m",
            )
            self.assertEqual(
                billing.price_id_for(tier="family", cadence="annual"),
                "price_family_a",
            )

    def test_no_two_tiers_resolve_to_the_same_price(self):
        """THE CORE PROPERTY, stated positively: the price is a function of the
        tier, and it is injective. If two tiers shared a price id, the cheap
        one would buy the dear one's entitlement again."""
        with mock.patch.dict(os.environ, PRICES, clear=False):
            resolved = [
                billing.price_id_for(tier=t, cadence=c)
                for t in entitlements.tier_names()
                for c in billing.CADENCES
            ]
        self.assertEqual(
            len(resolved), len(set(resolved)),
            "two plans share a Stripe price id -- one of them grants the "
            "other's entitlement for the wrong money",
        )

    def test_the_checkout_session_is_built_with_the_tiers_own_price(self):
        """The end-to-end shape: ask for family, and family's price is what
        reaches Stripe -- there is no argument by which to ask otherwise."""
        captured = {}

        class _FakeSession:
            id = "cs_test"
            url = "https://checkout.example/cs_test"

        class _FakeSessions:
            @staticmethod
            def create(**kwargs):
                captured.update(kwargs)
                return _FakeSession()

        fake_stripe = mock.Mock()
        fake_stripe.checkout.Session = _FakeSessions

        env = dict(PRICES, STRIPE_SECRET_KEY="sk_test")
        with mock.patch.dict(os.environ, env, clear=False), \
             mock.patch.object(billing, "_stripe", return_value=fake_stripe):
            billing.create_checkout_session(
                account_email="someone@example.com",
                tier="family",
                cadence="annual",
                subscription_id="sub_1",
            )

        self.assertEqual(
            captured["line_items"], [{"price": "price_family_a", "quantity": 1}]
        )
        # And the metadata the webhook will read back agrees with the money.
        self.assertEqual(captured["metadata"]["tier"], "family")
        self.assertEqual(captured["subscription_data"]["metadata"]["tier"], "family")

    def test_create_checkout_session_takes_no_price_argument(self):
        """A regression guard on the SHAPE. If a price_id parameter ever comes
        back, a caller can pass one, and the whole defect returns with it."""
        import inspect

        params = inspect.signature(billing.create_checkout_session).parameters
        self.assertNotIn("price_id", params)
        self.assertIn("cadence", params)


class AnUnconfiguredPriceRefuses(unittest.TestCase):
    def test_a_missing_price_raises_rather_than_falling_back(self):
        env = {k: "" for k in PRICES}
        with mock.patch.dict(os.environ, env, clear=False):
            with self.assertRaises(billing.BillingNotConfigured):
                billing.price_id_for(tier="pro", cadence="annual")

    def test_an_unknown_cadence_is_refused(self):
        with mock.patch.dict(os.environ, PRICES, clear=False):
            with self.assertRaises(billing.BillingNotConfigured):
                billing.price_id_for(tier="pro", cadence="weekly")

    def test_an_unknown_tier_is_refused(self):
        with mock.patch.dict(os.environ, PRICES, clear=False):
            with self.assertRaises(billing.BillingNotConfigured):
                billing.price_id_for(tier="enterprise", cadence="annual")

    def test_configured_prices_reports_what_is_actually_buyable(self):
        """So the picker can say 'not available' instead of rendering a Buy
        button that 503s at the moment somebody decided to pay us."""
        partial = dict.fromkeys(PRICES, "")
        partial["STRIPE_PRICE_PERSONAL_ANNUAL"] = "price_personal_a"
        with mock.patch.dict(os.environ, partial, clear=False):
            out = billing.configured_prices()

        self.assertTrue(out["personal"]["annual"])
        self.assertFalse(out["personal"]["monthly"])
        self.assertFalse(out["family"]["annual"])


if __name__ == "__main__":
    unittest.main()
