"""The tier table must not quietly become incoherent.

Prices live in `shared/tiers.json` because they appear in at least four places
that have to agree: entitlement checks in the API, the pricing page, the store
product definitions, and the docs. Four copies of a number is four chances to
drift, and the dangerous one is silent -- a customer billed for Family whose
device cap still reads Pro.

One file removes the copies. This removes the other failure: a single file that
is internally wrong. Every property here is one somebody could plausibly break
while editing a price, and none of them would show up in a test of anything
else.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TIERS_PATH = REPO / "shared" / "tiers.json"


class TheTierTableIsCoherent(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = json.loads(TIERS_PATH.read_text(encoding="utf-8"))
        cls.tiers = cls.data["tiers"]
        cls.order = cls.data["upgrade_path"]

    def test_every_tier_in_the_upgrade_path_exists(self):
        for name in self.order:
            self.assertIn(name, self.tiers)
        self.assertEqual(sorted(self.order), sorted(self.tiers))

    def test_paying_more_never_gets_you_less(self):
        """Caps and prices must climb together.

        A tier that costs more and allows fewer devices is not a pricing
        mistake anyone notices in review -- it is a refund request.
        """
        for cheaper, dearer in zip(self.order, self.order[1:]):
            a, b = self.tiers[cheaper], self.tiers[dearer]
            with self.subTest(step=f"{cheaper}->{dearer}"):
                self.assertLess(a["price_monthly"], b["price_monthly"])
                self.assertLess(a["price_annual"], b["price_annual"])
                self.assertLessEqual(a["devices"], b["devices"])
                self.assertLessEqual(a["people"], b["people"])

    def test_annual_is_actually_a_discount(self):
        """An 'annual' price at or above 12x monthly is not a plan, it is a
        bug that punishes the customer who committed for a year."""
        for name, tier in self.tiers.items():
            with self.subTest(tier=name):
                self.assertLess(tier["price_annual"], tier["price_monthly"] * 12)

    def test_the_annual_discount_is_worth_advertising(self):
        """Below ~20% nobody switches, and the cash-flow benefit of annual
        prepay is the whole reason to offer it."""
        for name, tier in self.tiers.items():
            discount = 1 - tier["price_annual"] / (tier["price_monthly"] * 12)
            with self.subTest(tier=name, discount=round(discount, 3)):
                self.assertGreaterEqual(discount, 0.20)

    def test_the_entry_tier_covers_more_than_one_device(self):
        """One device, many surfaces means a 1-device tier is phone OR laptop,
        not both. With no free tier this is the acquisition point; it must not
        feel broken at the moment of first payment. See docs/MULTI-DEVICE.md.
        """
        entry = self.tiers[self.order[0]]
        self.assertGreaterEqual(
            entry["devices"], 3,
            "the entry tier cannot cover a normal person's phone, laptop and "
            "tablet, and it is the first thing anyone pays for",
        )

    def test_there_is_no_per_device_addon(self):
        """Rejected 2026-08-16, with reasons recorded in shared/tiers.json.

        Pinned as a test rather than a comment because it is exactly the kind
        of decision that gets quietly reversed by someone looking for revenue,
        without re-reading why marginal-above-average pricing was wrong.
        """
        self.assertIsNone(
            self.data["per_device_addon"],
            "a per-device add-on is back. Its marginal rate exceeded the "
            "average rate, it has no cost basis (<1c/device/month), and it "
            "charges friction to the most engaged user you have. Upgrade the "
            "tier instead.",
        )

    def test_the_marginal_device_gets_cheaper_not_dearer(self):
        """The property the rejected add-on violated, stated directly."""
        rates = [t["price_annual"] / t["devices"] for t in
                 (self.tiers[n] for n in self.order)]
        for cheaper, dearer in zip(rates, rates[1:]):
            self.assertLess(
                dearer, cheaper,
                f"cost per device rises across the upgrade path ({rates}); "
                f"buying more should cost less each, not more",
            )


class TheTrialIsHonest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.trial = json.loads(TIERS_PATH.read_text(encoding="utf-8"))["trial"]

    def test_the_trial_is_long_enough_to_show_a_block(self):
        """This product proves itself when it blocks something. A trial that
        can end before that has happened converts on faith, not evidence."""
        self.assertGreaterEqual(self.trial["days"], 14)

    def test_the_customer_is_reminded_before_being_charged(self):
        """Not optional politeness. Auto-renewal after a trial is regulated,
        and for a company selling security a surprise charge costs exactly the
        trust the product is asking people to extend."""
        reminder = self.trial["reminder_days_before_charge"]
        self.assertGreaterEqual(reminder, 1)
        self.assertLess(
            reminder, self.trial["days"],
            "the reminder would fire before the trial starts",
        )


class ChannelPricingIsUnambiguous(unittest.TestCase):
    def test_one_price_everywhere_until_deliberately_changed(self):
        fees = json.loads(TIERS_PATH.read_text(encoding="utf-8"))["store_fees"]
        self.assertTrue(
            fees["channel_price_parity"],
            "channel price parity was turned off; a second price needs a "
            "second explanation, per-jurisdiction anti-steering rules, and "
            "support for both. Make sure the fee saved is worth it.",
        )


if __name__ == "__main__":
    unittest.main()
