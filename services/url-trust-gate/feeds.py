"""External reputation feed adapters.

The trust gate's primary detection signal is its own ML pipeline (via
the detection service). External feeds are a second opinion: cheap,
high-precision, low-recall. They're particularly valuable for the
phishing/malware dimensions where Google and Microsoft already have
massive ground-truth corpora.

Implemented:
  - Google Safe Browsing v4 (Lookup API, network-call variant). For
    high-volume deployments switch to the Update API + local hash
    cache; the interface here is shaped to allow that drop-in.
  - Microsoft Defender SmartScreen / Threat Intelligence indicator API.
    Requires SMARTSCREEN_TENANT_ID + SMARTSCREEN_CLIENT_ID +
    SMARTSCREEN_CLIENT_SECRET (Entra app with ThreatIntelligence.Read).
  - VirusTotal v3 URL scan endpoint (rate-limited; results cached for
    VIRUSTOTAL_CACHE_TTL_S seconds to stay within the free-tier quota of
    500 lookups/day). Requires VIRUSTOTAL_API_KEY.

Planned:
  - Tenant-supplied STIX/TAXII feeds.

All adapters implement ``ReputationFeed.lookup`` and ``ReputationFeed.name``;
``ReputationAggregator`` fans out concurrently and merges results into
the gate's score vector.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol, Tuple, runtime_checkable

import httpx

logger = logging.getLogger("url_trust_gate.feeds")


@dataclass
class FeedVerdict:
    feed: str
    matched: bool = False
    threat_types: List[str] = field(default_factory=list)
    confidence: float = 0.0
    raw: Optional[dict] = None
    #: Did this feed actually get to check?
    #:
    #: ``matched=False`` alone answered two different questions with one value:
    #: "checked against the threat lists and found nothing" and "there was no
    #: feed, or no data, so nothing was checked." A caller cannot tell a clean
    #: URL from an unchecked one, which is the defect class this repo tracks.
    #: Defaults False so an unconfigured feed never claims authority.
    authoritative: bool = False


@runtime_checkable
class ReputationFeed(Protocol):
    name: str

    async def lookup(self, url: str) -> FeedVerdict: ...


# ---------------------------------------------------------------------------
# Google Safe Browsing v4
# ---------------------------------------------------------------------------


class SafeBrowsingFeed:
    """Google Safe Browsing v4 **Update API** — local hash-prefix matching.

    Configure with ``SAFE_BROWSING_API_KEY``.

    WHY THIS IS NOT THE LOOKUP API ANY MORE. It was
    ``v4/threatMatches:find``: one HTTPS round trip to Google per URL. That is
    correct for a low-volume tool and wrong here. This gate is consulted on
    every top-level navigation and from the proxy's Step 0, so at the 800-seat
    pilot scale it is ~10^5 lookups/day against a default quota near 10^4 --
    and each one puts a customer's browsing on Google's wire, one URL at a time.

    The Update API inverts that: Google publishes SHA-256 prefixes, this client
    downloads them (``safebrowsing_v4``) and matches in memory. No per-lookup
    quota, no per-lookup latency, and no per-URL disclosure -- only a 4-byte
    prefix is ever sent, and only for the ~1-in-4-billion collisions that need
    confirming.

    Sync is the caller's job: await :meth:`sync` on startup and on a timer.
    Until it succeeds, verdicts come back ``authoritative=False`` -- NOT clean.
    """

    name = "google-safe-browsing"

    def __init__(
        self,
        api_key: Optional[str] = None,
        client_id: str = "cyberarmor-url-trust-gate",
        client_version: str = "0.1.0",
        timeout_s: float = 30.0,
    ):
        from safebrowsing_v4 import SafeBrowsingUpdateClient

        self._client = SafeBrowsingUpdateClient(
            api_key=api_key,
            client_id=client_id,
            client_version=client_version,
            timeout_s=timeout_s,
        )

    @property
    def configured(self) -> bool:
        return self._client.configured

    @property
    def synced(self) -> bool:
        return self._client.db.synced

    @property
    def prefix_count(self) -> int:
        return self._client.db.prefix_count

    async def sync(self) -> bool:
        """Fetch and apply one round of threat-list updates."""
        return await self._client.sync()

    async def lookup(self, url: str) -> FeedVerdict:
        if not self._client.configured:
            return FeedVerdict(feed=self.name, authoritative=False)

        matches, authoritative = self._client.db.lookup(url)
        if not authoritative:
            # Never downloaded a list. "Not matched" here would be a clean bill
            # of health from a check that never ran.
            return FeedVerdict(feed=self.name, authoritative=False)

        if not matches:
            return FeedVerdict(feed=self.name, authoritative=True)

        # A prefix hit is NOT a verdict -- 4 bytes collide. Confirm the full
        # hash before calling anything malicious.
        threat_types = await self._client.confirm(matches)
        if not threat_types:
            return FeedVerdict(feed=self.name, authoritative=True)

        return FeedVerdict(
            feed=self.name,
            matched=True,
            threat_types=threat_types,
            # Safe Browsing matches are very high precision.
            confidence=0.95,
            authoritative=True,
            raw={"prefix_matches": len(matches), "threat_types": threat_types},
        )


# ---------------------------------------------------------------------------
# Microsoft Defender SmartScreen / Threat Intelligence indicator API
# ---------------------------------------------------------------------------


class SmartScreenFeed:
    """Microsoft Defender Threat Intelligence URL indicator lookup.

    Uses the Microsoft Graph Security API:
        GET https://graph.microsoft.com/v1.0/security/tiIndicators?$filter=...

    Authentication is via the client-credentials OAuth2 flow (Entra ID).
    The app registration needs the ``ThreatIndicators.Read.All``
    application permission (Graph API).

    Required env vars:
      SMARTSCREEN_TENANT_ID   — Entra tenant (directory) ID
      SMARTSCREEN_CLIENT_ID   — App registration client ID
      SMARTSCREEN_CLIENT_SECRET — App client secret

    The bearer token is cached for its lifetime (typically 3600 s) so we
    don't hammer the token endpoint.
    """

    name = "microsoft-smartscreen"

    _TOKEN_ENDPOINT = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    _GRAPH_INDICATOR_ENDPOINT = (
        "https://graph.microsoft.com/v1.0/security/tiIndicators"
    )
    # Threat categories that map to phishing.
    _PHISHING_TYPES = frozenset({"phishing", "phishingUrl", "maliciousUrl"})
    # Threat categories that map to malware.
    _MALWARE_TYPES = frozenset({"malware", "botnet", "c2", "exploit", "ransomware"})

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        timeout_s: float = 2.0,
    ):
        self._tenant_id = tenant_id or os.getenv("SMARTSCREEN_TENANT_ID", "")
        self._client_id = client_id or os.getenv("SMARTSCREEN_CLIENT_ID", "")
        self._client_secret = client_secret or os.getenv("SMARTSCREEN_CLIENT_SECRET", "")
        self._timeout_s = timeout_s
        # Token cache: (access_token, expires_at_monotonic)
        self._token_cache: Optional[Tuple[str, float]] = None

    @property
    def configured(self) -> bool:
        return bool(self._tenant_id and self._client_id and self._client_secret)

    async def _get_token(self) -> Optional[str]:
        now = time.monotonic()
        if self._token_cache:
            token, expires_at = self._token_cache
            if now < expires_at - 60:  # 60s buffer
                return token

        try:
            async with httpx.AsyncClient(timeout=self._timeout_s, trust_env=False) as c:
                resp = await c.post(
                    self._TOKEN_ENDPOINT.format(tenant=self._tenant_id),
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                        "scope": "https://graph.microsoft.com/.default",
                    },
                )
                if resp.status_code != 200:
                    logger.debug(
                        "smartscreen_token_error status=%s body=%s",
                        resp.status_code,
                        resp.text[:200],
                    )
                    return None
                data = resp.json()
                token = data.get("access_token", "")
                expires_in = int(data.get("expires_in", 3600))
                self._token_cache = (token, now + expires_in)
                return token
        except Exception as exc:
            logger.debug("smartscreen_token_unreachable err=%s", exc)
            return None

    async def lookup(self, url: str) -> FeedVerdict:
        if not self.configured:
            return FeedVerdict(feed=self.name)

        token = await self._get_token()
        if not token:
            return FeedVerdict(feed=self.name)

        try:
            async with httpx.AsyncClient(timeout=self._timeout_s, trust_env=False) as c:
                # Filter by networkDestinationUrl or url field.
                filter_expr = (
                    f"(networkDestinationUrl eq '{url}' or url eq '{url}')"
                    " and isActive eq true"
                )
                resp = await c.get(
                    self._GRAPH_INDICATOR_ENDPOINT,
                    params={"$filter": filter_expr, "$top": "5"},
                    headers={"Authorization": f"Bearer {token}"},
                )
                if resp.status_code == 404:
                    # No match — clean URL.
                    return FeedVerdict(feed=self.name)
                if resp.status_code != 200:
                    logger.debug(
                        "smartscreen_lookup non-200 status=%s body=%s",
                        resp.status_code,
                        resp.text[:200],
                    )
                    return FeedVerdict(feed=self.name)

                data = resp.json() or {}
                indicators = data.get("value", []) or []
                if not indicators:
                    return FeedVerdict(feed=self.name)

                threat_types: List[str] = []
                max_confidence = 0.0
                for ind in indicators:
                    tlp = str(ind.get("tlpLevel", "")).lower()
                    category = str(ind.get("threatType", "")).lower()
                    if category:
                        threat_types.append(category)
                    # Microsoft confidence is 0–100.
                    conf_raw = float(ind.get("confidence", 50) or 50)
                    max_confidence = max(max_confidence, conf_raw / 100.0)

                return FeedVerdict(
                    feed=self.name,
                    matched=True,
                    threat_types=sorted(set(threat_types)),
                    confidence=max_confidence,
                    raw=data,
                )
        except Exception as exc:
            logger.debug("smartscreen_lookup_unreachable err=%s", exc)
            return FeedVerdict(feed=self.name)


# ---------------------------------------------------------------------------
# VirusTotal v3 URL reputation
# ---------------------------------------------------------------------------


_VT_CACHE_TTL_S = int(os.getenv("VIRUSTOTAL_CACHE_TTL_S", "3600"))


class VirusTotalFeed:
    """VirusTotal v3 URL reputation lookup.

    Uses ``GET /urls/{id}`` where ``{id}`` is the URL-safe base64 encoding
    of the URL as specified in the VT v3 docs.

    Rate limits on the public (free) API: 4 req/min, 500/day.  This
    adapter caches positive AND negative verdicts for
    ``VIRUSTOTAL_CACHE_TTL_S`` (default 3600 s) to stay well inside
    quota even under sustained load.

    Confidence mapping: VT returns per-engine votes. We take
    ``malicious / (malicious + harmless + undetected)`` as confidence,
    floored at 0 and capped at 1.

    Required env var:
      VIRUSTOTAL_API_KEY — your VT API key (public or private tier).
    """

    name = "virustotal"
    _API_BASE = "https://www.virustotal.com/api/v3"
    # Threat categories that VT labels as phishing.
    _PHISHING_CATS = frozenset({"phishing", "social-engineering"})

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout_s: float = 2.0,
        cache_ttl_s: int = _VT_CACHE_TTL_S,
    ):
        self._api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        self._timeout_s = timeout_s
        self._cache_ttl_s = cache_ttl_s
        # Simple in-process TTL cache: url -> (FeedVerdict, expires_at_monotonic)
        self._cache: Dict[str, Tuple[FeedVerdict, float]] = {}

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    @staticmethod
    def _url_id(url: str) -> str:
        """Compute the VT v3 URL identifier (URL-safe base64, no padding)."""
        return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()

    def _cache_get(self, url: str) -> Optional[FeedVerdict]:
        entry = self._cache.get(url)
        if entry is None:
            return None
        verdict, expires_at = entry
        if time.monotonic() > expires_at:
            del self._cache[url]
            return None
        return verdict

    def _cache_set(self, url: str, verdict: FeedVerdict) -> None:
        self._cache[url] = (verdict, time.monotonic() + self._cache_ttl_s)

    async def lookup(self, url: str) -> FeedVerdict:
        if not self._api_key:
            return FeedVerdict(feed=self.name)

        cached = self._cache_get(url)
        if cached is not None:
            return cached

        url_id = self._url_id(url)
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s, trust_env=False) as c:
                resp = await c.get(
                    f"{self._API_BASE}/urls/{url_id}",
                    headers={"x-apikey": self._api_key},
                )
                if resp.status_code == 404:
                    # URL not in VT database — treat as clean.
                    verdict = FeedVerdict(feed=self.name)
                    self._cache_set(url, verdict)
                    return verdict
                if resp.status_code != 200:
                    logger.debug(
                        "virustotal_lookup non-200 status=%s body=%s",
                        resp.status_code,
                        resp.text[:200],
                    )
                    return FeedVerdict(feed=self.name)

                data = resp.json() or {}
                stats = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                ) or {}
                malicious = int(stats.get("malicious", 0) or 0)
                suspicious = int(stats.get("suspicious", 0) or 0)
                harmless = int(stats.get("harmless", 0) or 0)
                undetected = int(stats.get("undetected", 0) or 0)
                total = malicious + suspicious + harmless + undetected
                if total == 0 or malicious == 0:
                    verdict = FeedVerdict(feed=self.name)
                    self._cache_set(url, verdict)
                    return verdict

                confidence = min(1.0, (malicious + suspicious * 0.5) / total)

                # Pull threat categories from per-engine results.
                categories_raw = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("categories", {})
                ) or {}
                all_cats = {v.lower() for v in categories_raw.values() if v}
                threat_types = sorted(all_cats or {"malware"})

                verdict = FeedVerdict(
                    feed=self.name,
                    matched=True,
                    threat_types=threat_types,
                    confidence=confidence,
                    raw={"last_analysis_stats": stats, "categories": categories_raw},
                )
                self._cache_set(url, verdict)
                return verdict

        except Exception as exc:
            logger.debug("virustotal_lookup_unreachable err=%s", exc)
            return FeedVerdict(feed=self.name)


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


@dataclass
class AggregatedReputation:
    matched: bool = False
    phishing: float = 0.0
    malware: float = 0.0
    threat_types: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    elapsed_ms: int = 0


class ReputationAggregator:
    """Fan out across configured feeds and merge into score deltas.

    Latency-bounded: if a feed exceeds its timeout it's silently dropped.
    """

    def __init__(self, feeds: Optional[List[ReputationFeed]] = None):
        self._feeds = feeds or []

    def add(self, feed: ReputationFeed) -> None:
        self._feeds.append(feed)

    @classmethod
    def from_env(cls) -> "ReputationAggregator":
        feeds: List[ReputationFeed] = []
        sb = SafeBrowsingFeed()
        if sb.configured:
            feeds.append(sb)
        ss = SmartScreenFeed()
        if ss.configured:
            feeds.append(ss)
        vt = VirusTotalFeed()
        if vt.configured:
            feeds.append(vt)
        if feeds:
            logger.info(
                "reputation_feeds_active feeds=%s",
                [f.name for f in feeds],
            )
        else:
            logger.info(
                "reputation_feeds_active feeds=[] "
                "(set SAFE_BROWSING_API_KEY / SMARTSCREEN_* / VIRUSTOTAL_API_KEY to enable)"
            )
        return cls(feeds)

    async def sync_all(self) -> None:
        """One round of list updates for every feed that maintains a local DB.

        Only Safe Browsing does today. A feed without a ``sync`` is queried
        per-URL and needs nothing here.
        """
        for feed in self._feeds:
            sync = getattr(feed, "sync", None)
            if sync is None:
                continue
            try:
                await sync()
            except Exception as exc:
                logger.warning(
                    "feed_sync_failed feed=%s err=%s -- its local list is now "
                    "STALE; lookups still match whatever was last downloaded",
                    getattr(feed, "name", "?"), exc,
                )

    def start_background_sync(self, interval_s: float = 1800.0):
        """Keep local threat lists current for the life of the process.

        Returns the task, or None when no feed needs syncing.

        The first sync runs IMMEDIATELY rather than after one interval: until
        it lands, Safe Browsing reports ``authoritative=False`` on every URL,
        and a gate that cannot check anything for the first half hour after a
        deploy is a gap nobody would see. ``sync()`` itself honours Google's
        ``minimumWaitDuration``, so a tight interval here cannot get the key
        rate-limited -- it just returns early.
        """
        if not any(hasattr(f, "sync") for f in self._feeds):
            return None

        async def _loop() -> None:
            while True:
                await self.sync_all()
                await asyncio.sleep(interval_s)

        return asyncio.create_task(_loop())

    async def lookup(self, url: str) -> AggregatedReputation:
        if not self._feeds:
            return AggregatedReputation()

        start = time.monotonic()
        results = await asyncio.gather(
            *(f.lookup(url) for f in self._feeds), return_exceptions=True
        )

        agg = AggregatedReputation()
        for r in results:
            if isinstance(r, Exception):
                continue
            if not isinstance(r, FeedVerdict):
                continue
            if not r.matched:
                continue
            agg.matched = True
            agg.sources.append(r.feed)
            for tt in r.threat_types:
                if tt and tt not in agg.threat_types:
                    agg.threat_types.append(tt)
            # Map threat-type -> score channel.
            # Covers Google Safe Browsing types (UPPER_CASE), Microsoft
            # SmartScreen types (camelCase / lower), and VirusTotal
            # category strings.
            _PHISHING_THREAT_TYPES = frozenset({
                # Safe Browsing
                "SOCIAL_ENGINEERING",
                # SmartScreen
                "phishing", "phishingUrl", "maliciousUrl",
                # VirusTotal categories
                "phishing", "social-engineering",
            })
            _MALWARE_THREAT_TYPES = frozenset({
                # Safe Browsing
                "MALWARE",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
                # SmartScreen
                "malware", "botnet", "c2", "exploit", "ransomware",
                # VirusTotal categories
                "malware", "trojan", "ransomware", "adware",
            })
            for tt in r.threat_types:
                if tt in _PHISHING_THREAT_TYPES:
                    agg.phishing = max(agg.phishing, r.confidence)
                if tt in _MALWARE_THREAT_TYPES:
                    agg.malware = max(agg.malware, r.confidence)
            # Fallback: if matched but no recognised type, treat as malware.
            if not any(
                tt in _PHISHING_THREAT_TYPES or tt in _MALWARE_THREAT_TYPES
                for tt in r.threat_types
            ):
                agg.malware = max(agg.malware, r.confidence)

        agg.elapsed_ms = int((time.monotonic() - start) * 1000)
        return agg
