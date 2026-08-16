"""Per-client token-bucket rate limiting for the scan endpoints.

THE GAP THIS CLOSES
===================
This service had no rate limiting of any kind, and five of its seven scan
endpoints were not covered by the saturation semaphore either. `/scan/output-
safety` is ~2.72 s of CPU per call against a CPU-only, un-batched, un-cached
transformer stack, so a single client looping on it could peg every core --
and the documented consequence of CPU saturation here is not a slow response,
it is `/health` timing out, docker calling the container dead, and a restart
that reloads ~5 GiB of weights while traffic keeps arriving.

That is survivable when every caller is an authenticated enterprise agent. It
is not survivable with a consumer free tier, where the attacker is a normal
user with a normal account and the endpoint is reachable by design.

RELATIONSHIP TO THE SATURATION SHED
===================================
They solve different problems and the service needs both:

  * The shed (_sheds_when_saturated) protects the PROCESS. It is global, and it
    is fair in the worst way -- under load it sheds whoever arrives next,
    including well-behaved clients.
  * This limits a CLIENT. It keeps one caller from consuming everyone's slots
    in the first place, so the shed stays a genuine emergency backstop rather
    than the normal operating mode.

DEFAULT OFF
===========
`..._RATE_LIMIT_RPM=0` means unlimited, and 0 is the default: the B2B pilot's
behaviour must not change because of a B2C requirement. The consumer profile
sets a real number in its own compose file.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import OrderedDict
from typing import Dict, Optional, Tuple

#: Requests per minute per client. 0 disables limiting entirely.
RATE_LIMIT_RPM = int(os.getenv("CYBERARMOR_DETECTION_RATE_LIMIT_RPM", "0"))
#: Burst allowance. Defaults to ~10 s worth of the sustained rate, min 1.
RATE_LIMIT_BURST = int(
    os.getenv("CYBERARMOR_DETECTION_RATE_LIMIT_BURST", str(max(1, RATE_LIMIT_RPM // 6)))
)
#: Bound on tracked clients. The promptware session tracker in this same
#: service was once unbounded and reached 7.3 GiB against an 8 GiB cap in 27
#: hours; a per-client map keyed on caller-supplied identity is the same shape
#: of hazard, so it is an LRU from the start rather than after the incident.
RATE_LIMIT_MAX_CLIENTS = int(
    os.getenv("CYBERARMOR_DETECTION_RATE_LIMIT_MAX_CLIENTS", "10000")
)


class TokenBucketLimiter:
    """Classic token bucket, one bucket per client identity, bounded by LRU."""

    def __init__(
        self,
        *,
        rpm: int = RATE_LIMIT_RPM,
        burst: int = RATE_LIMIT_BURST,
        max_clients: int = RATE_LIMIT_MAX_CLIENTS,
    ) -> None:
        self._rpm = max(0, rpm)
        self._capacity = float(max(1, burst)) if self._rpm else 0.0
        self._refill_per_second = self._rpm / 60.0 if self._rpm else 0.0
        self._max_clients = max(1, max_clients)
        self._buckets: "OrderedDict[str, Tuple[float, float]]" = OrderedDict()
        self._lock = threading.Lock()
        self._allowed = 0
        self._rejected = 0

    @property
    def enabled(self) -> bool:
        return self._rpm > 0

    @staticmethod
    def identity(api_key: Optional[str], client_id: Optional[str]) -> str:
        """Derive a stable, non-reversible client identity.

        Prefers an explicit client id (the consumer API forwards a per-account
        or per-device value) and falls back to the API key. Both are hashed:
        this map is read by /metrics, and a rate-limit table that discloses raw
        credentials is a worse bug than the one it was added to fix.
        """
        raw = (client_id or api_key or "anonymous").encode("utf-8", errors="replace")
        return hashlib.blake2b(raw, digest_size=12).hexdigest()

    def check(self, identity: str) -> Tuple[bool, float]:
        """Consume one token. Returns (allowed, retry_after_seconds)."""
        if not self.enabled:
            return True, 0.0
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(identity, (self._capacity, now))
            tokens = min(self._capacity, tokens + (now - last) * self._refill_per_second)
            if tokens >= 1.0:
                self._buckets[identity] = (tokens - 1.0, now)
                self._buckets.move_to_end(identity)
                self._allowed += 1
                allowed, retry_after = True, 0.0
            else:
                self._buckets[identity] = (tokens, now)
                self._buckets.move_to_end(identity)
                self._rejected += 1
                deficit = 1.0 - tokens
                retry_after = (
                    deficit / self._refill_per_second if self._refill_per_second else 60.0
                )
                allowed = False
            while len(self._buckets) > self._max_clients:
                self._buckets.popitem(last=False)
            return allowed, round(retry_after, 3)

    def stats(self) -> Dict[str, object]:
        with self._lock:
            return {
                "enabled": self.enabled,
                "rpm": self._rpm,
                "burst": int(self._capacity),
                "tracked_clients": len(self._buckets),
                "max_clients": self._max_clients,
                "allowed": self._allowed,
                "rejected": self._rejected,
            }


#: Process-wide instance used by main.py.
SCAN_LIMITER = TokenBucketLimiter()
