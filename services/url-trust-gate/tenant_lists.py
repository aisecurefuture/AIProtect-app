"""Tenant allow/block list lookup.

The policy service is the source of truth. Lists can be expressed in two
flavours, and the gate handles both:

  1. **Per-policy lists.** A policy with ``scope=url-trust-gate`` whose
     rules carry ``allow_domains`` / ``block_domains`` / ``allow_urls`` /
     ``block_urls`` arrays. Discovered via
     ``GET /policies?tenant_id=...&scope=url-trust-gate``.
  2. **Dedicated artifact-kind list** (preferred, future). A typed
     artifact uploaded to ``/artifacts/{tenant}/url-trust-gate-list``.

We try the policy-listing endpoint first, then fall back to artifacts.
Results are cached per-tenant for ``LIST_CACHE_TTL_S`` because lists
change rarely and the policy service is hit on every tenant request
otherwise.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import httpx

from cyberarmor_core.crypto import build_auth_headers

logger = logging.getLogger("url_trust_gate.tenant_lists")

LIST_CACHE_TTL_S = int(os.getenv("URL_TRUST_GATE_TENANT_LIST_TTL_S", "300"))


@dataclass
class _TenantLists:
    allow_domains: List[str] = field(default_factory=list)
    block_domains: List[str] = field(default_factory=list)
    allow_urls: List[str] = field(default_factory=list)
    block_urls: List[str] = field(default_factory=list)
    fetched_at: float = 0.0


class TenantListClient:
    def __init__(self, policy_url: str, policy_secret: str, timeout_s: float = 1.0):
        self._policy_url = policy_url
        self._policy_secret = policy_secret
        self._timeout_s = timeout_s
        self._cache: Dict[str, _TenantLists] = {}
        self._cache_lock = asyncio.Lock()

    async def lookup(
        self, tenant_id: str, host: str, url: str
    ) -> Optional[str]:
        """Return ``"allow"`` / ``"block"`` / ``None``.

        Block takes precedence over allow when both match.
        """

        lists = await self._get(tenant_id)
        if lists is None:
            return None

        # Block first.
        if any(_domain_match(host, d) for d in lists.block_domains):
            return "block"
        if any(_url_match(url, u) for u in lists.block_urls):
            return "block"
        if any(_domain_match(host, d) for d in lists.allow_domains):
            return "allow"
        if any(_url_match(url, u) for u in lists.allow_urls):
            return "allow"
        return None

    async def invalidate(self, tenant_id: str) -> None:
        async with self._cache_lock:
            self._cache.pop(tenant_id, None)

    async def _get(self, tenant_id: str) -> Optional[_TenantLists]:
        now = time.monotonic()
        async with self._cache_lock:
            cached = self._cache.get(tenant_id)
            if cached is not None and now - cached.fetched_at < LIST_CACHE_TTL_S:
                return cached

        lists = await self._fetch(tenant_id)
        if lists is None:
            return cached  # serve stale on fetch failure rather than nothing

        async with self._cache_lock:
            self._cache[tenant_id] = lists
        return lists

    async def _fetch(self, tenant_id: str) -> Optional[_TenantLists]:
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout_s, trust_env=False
            ) as c:
                resp = await c.get(
                    f"{self._policy_url}/policies",
                    params={"tenant_id": tenant_id, "scope": "url-trust-gate"},
                    headers=build_auth_headers(self._policy_url, self._policy_secret),
                )
                if resp.status_code != 200:
                    logger.debug(
                        "tenant_lists non-200 status=%s body=%s",
                        resp.status_code,
                        resp.text[:200],
                    )
                    return None
                policies = resp.json() or []
                return _merge(policies)
        except Exception as exc:
            logger.debug("tenant_lists unreachable err=%s", exc)
            return None


def _merge(policies: List[dict]) -> _TenantLists:
    out = _TenantLists(fetched_at=time.monotonic())
    for p in policies:
        if not p.get("enabled", True):
            continue
        rules = p.get("rules") or {}
        for key, sink in (
            ("allow_domains", out.allow_domains),
            ("block_domains", out.block_domains),
            ("allow_urls", out.allow_urls),
            ("block_urls", out.block_urls),
        ):
            values = rules.get(key) or []
            if isinstance(values, list):
                for v in values:
                    if isinstance(v, str) and v:
                        sink.append(v.strip().lower())
    # Deduplicate while preserving order.
    out.allow_domains = list(dict.fromkeys(out.allow_domains))
    out.block_domains = list(dict.fromkeys(out.block_domains))
    out.allow_urls = list(dict.fromkeys(out.allow_urls))
    out.block_urls = list(dict.fromkeys(out.block_urls))
    return out


def _domain_match(host: str, pattern: str) -> bool:
    """Match either an exact domain or a leading-dot suffix wildcard.

    ``pattern="example.com"`` matches ``example.com`` only.
    ``pattern=".example.com"`` matches ``foo.example.com`` and any subdomain
    but NOT ``example.com`` itself (use both forms to cover both).
    """

    host = (host or "").lower()
    pattern = (pattern or "").lower()
    if not host or not pattern:
        return False
    if pattern.startswith("."):
        return host.endswith(pattern) and host != pattern[1:]
    return host == pattern


def _url_match(url: str, pattern: str) -> bool:
    """Exact URL or prefix match if pattern ends with ``*``."""

    url = (url or "").lower()
    pattern = (pattern or "").lower()
    if not url or not pattern:
        return False
    if pattern.endswith("*"):
        return url.startswith(pattern[:-1])
    return url == pattern
