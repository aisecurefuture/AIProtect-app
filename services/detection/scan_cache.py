"""Content-addressed result cache for scans.

A scan is a pure function of (text, configuration). Nothing in this service
memoised that, so identical text scanned twice paid full transformer inference
twice -- measured at ~3.58 s and ~14 core-seconds per /scan on production. For
a consumer product, where the same prompts and the same handful of URLs recur
constantly across users, that is the single largest avoidable cost in the
system.

THREE RULES, EACH LOAD-BEARING
==============================

1. NEVER CACHE AN INCOMPLETE SCAN.
   A response carrying `detector_unavailable` describes a moment when a model
   was broken, not a property of the text. Caching it would pin a degraded
   verdict in front of a recovered model for the whole TTL -- turning a
   transient fault into a persistent lie about coverage. The caller enforces
   this by only calling `put()` for complete scans; `put()` refuses anyway.

2. THE KEY INCLUDES THE CONFIGURATION FINGERPRINT.
   Change a threshold or a profile and yesterday's verdict is not an answer to
   today's question. See detection_profile.config_fingerprint().

3. NO PLAINTEXT IS STORED, EVER.
   Keys are salted digests, and the salt is per-process and random, so the
   stored keyspace is not an offline-checkable fingerprint of user content.
   The cache holds verdicts, never the text that produced them. This matters
   more for B2C than B2B: the text being scanned is a private individual's
   chat message, not a corporate egress log.

Not shared across processes on purpose. An in-process dict has no serialisation
cost, no network hop, and no cross-tenant blast radius -- and this service runs
one uvicorn process. A Redis-backed variant would need rule 3 rethought, since
the keyspace would then outlive the process and be visible to an operator.
"""

from __future__ import annotations

import copy
import hashlib
import os
import secrets
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, Optional

_TRUE = {"1", "true", "yes", "on"}

#: Default OFF. Enabling a cache changes what a caller observes (a verdict up
#: to TTL seconds old), and the B2B deployment serves a paying regulated pilot
#: -- that is their decision to make deliberately, not one to inherit from a
#: B2C change. The consumer profile turns it on in its own compose file.
CACHE_ENABLED = os.getenv("CYBERARMOR_DETECTION_CACHE_ENABLED", "false").strip().lower() in _TRUE
CACHE_TTL_SECONDS = float(os.getenv("CYBERARMOR_DETECTION_CACHE_TTL_S", "300"))
CACHE_MAX_ENTRIES = int(os.getenv("CYBERARMOR_DETECTION_CACHE_MAX_ENTRIES", "10000"))


class ScanCache:
    """Bounded, TTL'd, thread-safe LRU keyed by salted content digest."""

    def __init__(
        self,
        *,
        enabled: bool = CACHE_ENABLED,
        ttl_seconds: float = CACHE_TTL_SECONDS,
        max_entries: int = CACHE_MAX_ENTRIES,
    ) -> None:
        self._enabled = enabled
        self._ttl = max(0.0, ttl_seconds)
        self._max = max(1, max_entries)
        self._store: "OrderedDict[str, tuple[float, Dict[str, Any]]]" = OrderedDict()
        self._lock = threading.Lock()
        # Per-process, never persisted, never logged.
        self._salt = secrets.token_bytes(16)
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._expired = 0
        self._refused = 0

    # -- keying ------------------------------------------------------------

    def key(self, namespace: str, text: str, fingerprint: str) -> str:
        h = hashlib.blake2b(self._salt, digest_size=20)
        h.update(namespace.encode("utf-8"))
        h.update(b"\x00")
        h.update(fingerprint.encode("utf-8"))
        h.update(b"\x00")
        h.update(text.encode("utf-8", errors="replace"))
        return h.hexdigest()

    # -- access ------------------------------------------------------------

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        if not self._enabled:
            return None
        now = time.time()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            stored_at, value = entry
            if self._ttl and (now - stored_at) > self._ttl:
                del self._store[key]
                self._expired += 1
                self._misses += 1
                return None
            self._store.move_to_end(key)
            self._hits += 1
            # DEEP copy, and the depth is the point. A shallow dict() copy
            # shares the nested `detections` list, so one request appending to
            # its own findings would rewrite the entry every later request
            # reads. Caught by test_a_hit_cannot_be_mutated_by_its_caller,
            # which is the whole reason that test exists. Against ~3.58 s of
            # transformer inference, copying a small dict costs nothing.
            return copy.deepcopy(value)

    def put(self, key: str, value: Dict[str, Any]) -> None:
        """Store a verdict. Refuses anything that admits to being incomplete."""
        if not self._enabled:
            return
        if not self._is_cacheable(value):
            with self._lock:
                self._refused += 1
            return
        with self._lock:
            # Deep on the way in as well: the caller keeps using the dict it
            # handed us (it is the response being returned), so storing a
            # shallow copy would let the live response mutate the cache entry.
            self._store[key] = (time.time(), copy.deepcopy(value))
            self._store.move_to_end(key)
            while len(self._store) > self._max:
                self._store.popitem(last=False)
                self._evictions += 1

    @staticmethod
    def _is_cacheable(value: Dict[str, Any]) -> bool:
        """Rule 1, enforced here as well as at the call site.

        `scan_complete is False` and a non-empty `detectors_unavailable` both
        mean a model did not run. Endpoints that carry neither field (e.g. the
        single-detector routes) are cacheable only when they say nothing about
        a gap -- absence of the key means the route never reports one.
        """
        if value.get("scan_complete") is False:
            return False
        if value.get("detectors_unavailable"):
            return False
        for finding in value.get("detections") or ():
            if isinstance(finding, dict) and finding.get("type") == "detector_unavailable":
                return False
        return True

    # -- observability -----------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._hits + self._misses
            return {
                "enabled": self._enabled,
                "entries": len(self._store),
                "max_entries": self._max,
                "ttl_seconds": self._ttl,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(self._hits / total, 4) if total else 0.0,
                "evictions": self._evictions,
                "expired": self._expired,
                # Non-zero here is a signal, not noise: it counts scans that
                # ran degraded and were correctly kept out of the cache.
                "refused_incomplete": self._refused,
            }

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


#: Process-wide instance used by main.py.
SCAN_CACHE = ScanCache()
