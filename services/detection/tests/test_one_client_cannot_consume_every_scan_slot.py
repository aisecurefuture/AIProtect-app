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

from rate_limit import TokenBucketLimiter  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
