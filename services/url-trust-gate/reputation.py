"""Reputation cache + verdict types.

In-process TTL cache for the scaffold. The interface is shaped so it can
be swapped for Redis or the audit store without touching callers.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from main import IOC, TrustGateScores


@dataclass
class ReputationVerdict:
    scores: "TrustGateScores"
    iocs: List["IOC"] = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)
    stored_at: float = field(default_factory=time.monotonic)


class ReputationCache:
    """Thread-safe TTL cache keyed by canonical URL fingerprint."""

    def __init__(self, ttl_s: int = 900, max_entries: int = 100_000):
        self._ttl_s = ttl_s
        self._max = max_entries
        self._lock = threading.Lock()
        self._store: dict[str, ReputationVerdict] = {}

    def lookup(self, fingerprint: str) -> Optional[ReputationVerdict]:
        with self._lock:
            v = self._store.get(fingerprint)
            if v is None:
                return None
            if time.monotonic() - v.stored_at > self._ttl_s:
                self._store.pop(fingerprint, None)
                return None
            return v

    def store(self, fingerprint: str, verdict: ReputationVerdict) -> None:
        with self._lock:
            if len(self._store) >= self._max:
                # Cheap eviction: drop the oldest 5% by stored_at. Good
                # enough for a scaffold; production should use an LRU.
                victims = sorted(
                    self._store.items(), key=lambda kv: kv[1].stored_at
                )[: max(1, self._max // 20)]
                for k, _ in victims:
                    self._store.pop(k, None)
            verdict.stored_at = time.monotonic()
            self._store[fingerprint] = verdict

    # TODO: external reputation feed adapters.
    # - Google Safe Browsing v4 (Update API for low-latency local cache).
    # - Microsoft SmartScreen / Defender ATP indicator API.
    # - VirusTotal v3 url/{id} (rate-limited; cache aggressively).
    # - Tenant-supplied threat feeds (STIX/TAXII).
    # Each should write through into this cache so the gate's hot path
    # stays in-process.
