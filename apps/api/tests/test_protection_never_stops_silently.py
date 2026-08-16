"""Protection must never stop as a side effect of a billing event.

THE DEFECT THIS PREVENTS
========================
Every one of these is a plausible implementation, and every one silently leaves
somebody unprotected while the app still looks fine:

  * a card expires        -> subscription flips inactive -> scanning stops
  * a trial ends          -> `active` goes false on a timer -> scanning stops
  * Family downgrades     -> the 7 newest devices keep working, the rest are
                             deactivated to fit the tier -> those phones stop
  * a device hits the cap -> the least-recently-seen one is evicted to make
                             room -> a real device stops

The person is relying on this product. A security tool that quietly stops
protecting is worse than one that never protected, because the reliance is what
was sold. So there is exactly ONE state in which protection stops -- `lapsed` --
and it is only ever reached through `grace`, which the person was told about.

This is the same defect class the detection service refuses (a check that did
not run rendering as a check that ran and found nothing), expressed as a
billing state machine.
"""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

API = Path(__file__).resolve().parent.parent           # apps/api
REPO = API.parent.parent
sys.path.insert(0, str(API))

import entitlements as ent  # noqa: E402

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)


def _resolve(state, tier="personal", trial_ends=None, grace_ends=None, now=NOW):
    return ent.resolve(
        state=state, tier_name=tier,
        trial_ends_at=trial_ends, grace_ends_at=grace_ends, now=now,
    )


class ProtectionContinuesThroughEveryBillingEvent(unittest.TestCase):
    def test_a_live_trial_protects(self):
        e = _resolve(ent.TRIALING, trial_ends=NOW + timedelta(days=5))
        self.assertTrue(e.protected)
        self.assertEqual(e.state, ent.TRIALING)

    def test_an_expired_trial_does_not_drop_protection_on_a_timer(self):
        """THE CORE PROPERTY. The trial running out is a billing event, not a
        protection event. It routes through grace, where the person is asked."""
        e = _resolve(ent.TRIALING, trial_ends=NOW - timedelta(hours=1))
        self.assertTrue(e.protected)
        self.assertEqual(e.state, ent.GRACE)
        self.assertTrue(e.reason, "grace must explain itself")
        self.assertIsNotNone(e.deadline, "the person needs a countdown")

    def test_a_failed_payment_keeps_devices_protected(self):
        e = _resolve(ent.GRACE, grace_ends=NOW + timedelta(days=7))
        self.assertTrue(e.protected)
        self.assertIn("still protected", e.reason)

    def test_protection_stops_only_after_grace_expires(self):
        e = _resolve(ent.GRACE, grace_ends=NOW - timedelta(seconds=1))
        self.assertFalse(e.protected)
        self.assertEqual(e.state, ent.LAPSED)

    def test_lapsed_is_the_only_unprotected_state(self):
        for state in (ent.TRIALING, ent.ACTIVE, ent.GRACE):
            with self.subTest(state=state):
                self.assertTrue(
                    _resolve(state, grace_ends=NOW + timedelta(days=1)).protected
                )
        self.assertFalse(_resolve(ent.LAPSED).protected)

    def test_an_unknown_state_keeps_protecting(self):
        """A typo in a migration must not take protection away from a paying
        customer. Failing closed is the wrong direction here: the cost of
        wrongly protecting someone for a day is a rounding error, and the cost
        of wrongly unprotecting them is the product's whole premise."""
        e = _resolve("smoething_typoed")
        self.assertTrue(e.protected)
        self.assertEqual(e.state, ent.GRACE)

    def test_every_unprotected_state_says_why(self):
        """A client that can only say 'you are not protected' cannot tell the
        person how to fix it."""
        e = _resolve(ent.LAPSED)
        self.assertFalse(e.protected)
        self.assertTrue(e.reason.strip())


class TheDeviceCapRefusesRatherThanEvicts(unittest.TestCase):
    def test_under_the_cap_is_allowed(self):
        e = _resolve(ent.ACTIVE, tier="personal")       # 3 devices
        d = ent.can_enroll_device(entitlement=e, devices_in_use=2)
        self.assertTrue(d.allowed)

    def test_at_the_cap_is_refused(self):
        e = _resolve(ent.ACTIVE, tier="personal")
        d = ent.can_enroll_device(entitlement=e, devices_in_use=3)
        self.assertFalse(d.allowed)

    def test_the_refusal_names_the_upgrade(self):
        """There is no per-device add-on, so an upgrade is the ONLY route to
        more devices. A refusal that does not name it is a dead end."""
        e = _resolve(ent.ACTIVE, tier="personal")
        d = ent.can_enroll_device(entitlement=e, devices_in_use=3)
        self.assertEqual(d.upgrade_to, "pro")
        self.assertIn("Pro", d.reason)
        self.assertIn("10 devices", d.reason)

    def test_the_top_tier_refusal_still_offers_a_way_forward(self):
        e = _resolve(ent.ACTIVE, tier="family")          # 30 devices
        d = ent.can_enroll_device(entitlement=e, devices_in_use=30)
        self.assertFalse(d.allowed)
        self.assertIsNone(d.upgrade_to)
        self.assertIn("Remove a device", d.reason)

    def test_there_is_no_eviction_concept_at_all(self):
        """Pinned structurally, not by behaviour: the decision object has no
        field in which an evicted device could be reported, so an eviction
        cannot be added without this test being deliberately changed."""
        d = ent.can_enroll_device(
            entitlement=_resolve(ent.ACTIVE, tier="personal"), devices_in_use=3
        )
        self.assertNotIn("evict", str(d.to_dict()).lower())
        self.assertFalse(hasattr(d, "evicted"))

    def test_an_unprotected_account_cannot_enrol(self):
        e = _resolve(ent.LAPSED)
        d = ent.can_enroll_device(entitlement=e, devices_in_use=0)
        self.assertFalse(d.allowed)
        self.assertTrue(d.reason.strip())


class ADowngradeAsksRatherThanChooses(unittest.TestCase):
    def test_an_oversized_downgrade_needs_grace(self):
        """Family (30) -> Pro (10) with 12 enrolled must not deactivate 2 of
        them. Which two is the person's decision."""
        self.assertTrue(
            ent.downgrade_requires_grace(to_tier="pro", devices_in_use=12)
        )

    def test_a_downgrade_that_fits_does_not(self):
        self.assertFalse(
            ent.downgrade_requires_grace(to_tier="pro", devices_in_use=4)
        )


class TheTiersComeFromOnePlace(unittest.TestCase):
    def test_limits_are_read_from_shared_tiers_json(self):
        """Not restated in code. A second copy is the one that drifts, and the
        drift that matters is a customer billed for Family whose device cap
        still reads Pro."""
        import json
        raw = json.loads((REPO / "shared" / "tiers.json").read_text())
        for name, spec in raw["tiers"].items():
            with self.subTest(tier=name):
                self.assertEqual(ent.device_limit(name), spec["devices"])
                self.assertEqual(ent.people_limit(name), spec["people"])

    def test_the_trial_length_comes_from_the_same_file(self):
        import json
        raw = json.loads((REPO / "shared" / "tiers.json").read_text())
        self.assertEqual(ent.trial_days(), raw["trial"]["days"])


if __name__ == "__main__":
    unittest.main()
