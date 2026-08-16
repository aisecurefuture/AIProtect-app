"""One caller must not be able to spend everyone else's CPU.

THE GAP THIS CLOSES
===================
This service had no rate limiting of any kind, and five of its seven scan
endpoints were not covered by the saturation semaphore either -- including
``/scan/output-safety`` at ~2.72 s of CPU per call, and ``/scan/redact`` at up
to 24 NER windows x 2 models. Inference is CPU-only, un-batched and (until now)
un-cached, so a single client looping on either could peg every core.

The documented consequence of CPU saturation in this service is not a slow
response. It is ``/health`` queueing behind torch, timing out, docker calling
the container dead, and a restart that reloads ~5 GiB of weights while traffic
keeps arriving -- three times in 180 minutes on 2026-08-14.

That is survivable when every caller is an authenticated enterprise agent. It
is not survivable with a consumer free tier, where the attacker is an ordinary
user with an ordinary account and the endpoint is reachable by design.

WHY BOTH THIS AND THE SHED
==========================
The shed protects the PROCESS and is global -- under load it sheds whoever
arrives next, including well-behaved clients. This limits a CLIENT, so one
caller cannot take everyone's slots in the first place and the shed stays an
emergency backstop rather than the normal operating mode.
"""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rate_limit import SubscriptionLimiter, TokenBucketLimiter  # noqa: E402


class DisabledByDefault(unittest.TestCase):
    def test_zero_rpm_means_unlimited(self):
        """The B2B pilot's behaviour must not change because of a B2C
        requirement. 0 is the default and it means no limiting at all."""
        lim = TokenBucketLimiter(rpm=0)
        self.assertFalse(lim.enabled)
        for _ in range(1000):
            allowed, retry = lim.check("anyone")
            self.assertTrue(allowed)
            self.assertEqual(retry, 0.0)


class OneClientIsBounded(unittest.TestCase):
    def test_burst_is_allowed_then_the_client_is_refused(self):
        lim = TokenBucketLimiter(rpm=60, burst=5)
        allowed = [lim.check("client-a")[0] for _ in range(20)]
        self.assertEqual(allowed[:5], [True] * 5)
        self.assertIn(False, allowed[5:])

    def test_a_refusal_says_when_to_come_back(self):
        lim = TokenBucketLimiter(rpm=60, burst=1)
        lim.check("client-a")
        allowed, retry_after = lim.check("client-a")
        self.assertFalse(allowed)
        self.assertGreater(retry_after, 0.0)

    def test_tokens_refill_over_time(self):
        lim = TokenBucketLimiter(rpm=6000, burst=1)  # 100/s
        self.assertTrue(lim.check("client-a")[0])
        self.assertFalse(lim.check("client-a")[0])
        time.sleep(0.05)
        self.assertTrue(lim.check("client-a")[0])

    def test_one_greedy_client_does_not_starve_another(self):
        """THE POINT. Exhausting your own bucket must not touch anyone else's."""
        lim = TokenBucketLimiter(rpm=60, burst=3)
        for _ in range(50):
            lim.check("greedy")
        self.assertFalse(lim.check("greedy")[0])
        self.assertTrue(lim.check("polite")[0])


class TheLimiterIsSafeToOperate(unittest.TestCase):
    def test_identity_is_hashed_not_stored_raw(self):
        """/metrics reports tracked client counts, and a rate-limit table that
        discloses raw credentials is a worse bug than the one it fixes."""
        ident = TokenBucketLimiter.identity("super-secret-api-key", None)
        self.assertNotIn("super-secret-api-key", ident)
        self.assertEqual(ident, TokenBucketLimiter.identity("super-secret-api-key", None))

    def test_client_id_takes_precedence_over_api_key(self):
        """The consumer API forwards a per-account or per-device value; every
        consumer request would otherwise share one API key and one bucket."""
        by_key = TokenBucketLimiter.identity("shared-key", None)
        by_client = TokenBucketLimiter.identity("shared-key", "device-42")
        self.assertNotEqual(by_key, by_client)

    def test_the_client_map_is_bounded(self):
        """Keyed on caller-supplied identity, so an attacker can mint entries.
        Same hazard shape as the promptware tracker that reached 7.3 GiB."""
        lim = TokenBucketLimiter(rpm=60, burst=1, max_clients=25)
        for i in range(500):
            lim.check(f"client-{i}")
        self.assertLessEqual(lim.stats()["tracked_clients"], 25)

    def test_stats_count_both_outcomes(self):
        lim = TokenBucketLimiter(rpm=60, burst=2)
        for _ in range(6):
            lim.check("c")
        stats = lim.stats()
        self.assertEqual(stats["allowed"], 2)
        self.assertEqual(stats["rejected"], 4)


class ASubscriptionIsAlsoBounded(unittest.TestCase):
    """A per-device limit alone caps nothing that matters to the bill.

    Subscriptions cover many devices -- that is the product. It is also a
    multiplier on the most expensive operation this service has: ten devices at
    60 rpm is 600 rpm from one paying account, and a Family plan makes that the
    normal case rather than the abusive one.
    """

    def test_devices_cannot_sum_past_the_account_ceiling(self):
        """THE POINT. Each device stays inside its own limit, and together
        they still cannot exceed what the subscription is allowed."""
        lim = SubscriptionLimiter(
            device_rpm=600, device_burst=10, account_rpm=600, account_burst=12
        )
        allowed = 0
        for i in range(10):                       # ten enrolled devices
            for _ in range(5):                    # five requests each = 50
                ok, _retry, _scope = lim.check(device=f"dev-{i}", account="acct-1")
                allowed += ok
        self.assertLessEqual(allowed, 12, "account burst was exceeded")

    def test_a_rejection_says_which_ceiling_it_hit(self):
        """'Wait a moment' and 'another of your devices is eating the plan'
        are different messages, and the app cannot choose without this."""
        lim = SubscriptionLimiter(
            device_rpm=60, device_burst=1, account_rpm=6000, account_burst=100
        )
        lim.check(device="dev-a", account="acct-1")
        ok, _retry, scope = lim.check(device="dev-a", account="acct-1")
        self.assertFalse(ok)
        self.assertEqual(scope, "device")

        lim2 = SubscriptionLimiter(
            device_rpm=6000, device_burst=100, account_rpm=60, account_burst=1
        )
        lim2.check(device="dev-a", account="acct-1")
        ok, _retry, scope = lim2.check(device="dev-b", account="acct-1")
        self.assertFalse(ok)
        self.assertEqual(scope, "account")

    def test_one_device_cannot_starve_its_siblings(self):
        """Fairness within a household: a compromised or runaway laptop must
        not silently remove protection from everyone else's phone."""
        lim = SubscriptionLimiter(
            device_rpm=60, device_burst=3, account_rpm=6000, account_burst=500
        )
        for _ in range(50):
            lim.check(device="runaway-laptop", account="acct-1")
        self.assertFalse(lim.check(device="runaway-laptop", account="acct-1")[0])
        self.assertTrue(lim.check(device="someones-phone", account="acct-1")[0])

    def test_two_accounts_do_not_share_a_ceiling(self):
        lim = SubscriptionLimiter(
            device_rpm=6000, device_burst=100, account_rpm=60, account_burst=2
        )
        for _ in range(10):
            lim.check(device="dev-a", account="acct-1")
        self.assertFalse(lim.check(device="dev-a", account="acct-1")[0])
        self.assertTrue(lim.check(device="dev-z", account="acct-2")[0])

    def test_an_account_rejection_does_not_charge_the_device(self):
        """The account is peeked before the device bucket is spent. Otherwise a
        device pays a token for a request the account was always going to
        refuse, and a throttled household would also look like it had
        misbehaving devices."""
        lim = SubscriptionLimiter(
            device_rpm=60, device_burst=5, account_rpm=60, account_burst=1
        )
        lim.check(device="dev-a", account="acct-1")      # spends the account token
        for _ in range(3):
            ok, _r, scope = lim.check(device="dev-a", account="acct-1")
            self.assertFalse(ok)
            self.assertEqual(scope, "account")
        # The device never got charged for those, so once the account refills
        # the device still has its own budget intact.
        self.assertGreater(lim.stats()["device"]["allowed"], 0)
        self.assertEqual(lim.stats()["device"]["rejected"], 0)

    def test_no_account_header_still_limits_the_device(self):
        """Callers that do not send an account (a device not yet enrolled)
        must not thereby escape limiting altogether."""
        lim = SubscriptionLimiter(
            device_rpm=60, device_burst=2, account_rpm=60, account_burst=2
        )
        self.assertTrue(lim.check(device="dev-a")[0])
        self.assertTrue(lim.check(device="dev-a")[0])
        self.assertFalse(lim.check(device="dev-a")[0])

    def test_both_ceilings_default_to_unlimited(self):
        lim = SubscriptionLimiter(device_rpm=0, account_rpm=0)
        self.assertFalse(lim.enabled)
        for _ in range(500):
            self.assertTrue(lim.check(device="d", account="a")[0])


if __name__ == "__main__":
    unittest.main()
