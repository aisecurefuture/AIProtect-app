"""Low-footprint safe crawler.

Design goals (from architecture doc):
  - Never carries user cookies / credentials / Authorization headers.
  - Blocks SSRF: refuses RFC1918, link-local, loopback, and metadata IPs.
  - Hard caps: timeout, response size, redirect count.
  - GET only by default. POST/PUT must be opt-in and only allowed in
    detonation mode.
  - Dedicated outbound identity (User-Agent + source ASN if configured).
  - Streams response bytes so we can stop reading at the size limit
    without buffering the entire body.

This module is a SCAFFOLD. The full implementation needs an isolated
egress namespace (separate container, no internal route, restrictive
egress firewall). The Python-level checks here are belt-and-braces; the
real safety boundary is the network namespace.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import socket
from dataclasses import dataclass, field
from typing import List, Optional, Set

import httpx

logger = logging.getLogger("url_trust_gate.crawler")

DEFAULT_USER_AGENT = (
    "CyberArmor-URLTrustGate/0.1 (+https://cyberarmor.ai/bots/url-trust-gate)"
)

# Hostnames that bypass SSRF private-address rejection. Intended for the
# 15-minute PoC and integration tests that need to drive the crawler
# against a same-network test server. Empty by default — production
# deployments must NOT set this.
_SSRF_ALLOWLIST_HOSTS: Set[str] = {
    h.strip().lower()
    for h in os.getenv("URL_TRUST_GATE_CRAWLER_SSRF_ALLOWLIST", "").split(",")
    if h.strip()
}


@dataclass
class CrawlResult:
    final_url: str
    status: int
    redirect_chain: List[str] = field(default_factory=list)
    content_type: str = ""
    content_bytes: bytes = b""
    truncated: bool = False
    content_hash: Optional[str] = None
    error: Optional[str] = None


class SafeCrawler:
    def __init__(
        self,
        timeout_s: float = 4.0,
        max_bytes: int = 1_048_576,
        max_redirects: int = 5,
        user_agent: str = DEFAULT_USER_AGENT,
    ):
        self._timeout_s = timeout_s
        self._max_bytes = max_bytes
        self._max_redirects = max_redirects
        self._user_agent = user_agent

    async def fetch(
        self, url: str, *, tenant_id: str, request_id: str
    ) -> CrawlResult:
        """Fetch a URL with all safety rails on.

        Returns a CrawlResult even on error — the gate distinguishes
        "couldn't fetch" from "fetched and looks bad" and treats both
        signals separately.
        """

        if not _ssrf_safe_destination(url):
            return CrawlResult(
                final_url=url,
                status=0,
                error="ssrf_blocked",
            )

        # TODO: pin DNS resolution to the egress sandbox's resolver. The
        # default resolver may resolve internal names if /etc/hosts or
        # search domains leak in. The crawler container should run in a
        # dedicated network namespace with no access to internal DNS.

        headers = {
            "User-Agent": self._user_agent,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5",
            "Accept-Language": "en",
            "X-CyberArmor-Crawler": "url-trust-gate",
            "X-CyberArmor-Request-Id": request_id,
        }

        redirect_chain: List[str] = []
        final_url = url
        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=self._timeout_s,
                # IMPORTANT: do NOT set cookies, do NOT load env trust.
                trust_env=False,
                http2=False,
            ) as client:
                current = url
                for _ in range(self._max_redirects + 1):
                    # Re-validate every hop — attackers redirect to
                    # internal IPs after the first request.
                    if not _ssrf_safe_destination(current):
                        return CrawlResult(
                            final_url=current,
                            status=0,
                            redirect_chain=redirect_chain,
                            error="ssrf_blocked_on_redirect",
                        )
                    async with client.stream(
                        "GET", current, headers=headers
                    ) as resp:
                        if resp.is_redirect:
                            loc = resp.headers.get("location", "")
                            if not loc:
                                final_url = current
                                break
                            redirect_chain.append(current)
                            current = httpx.URL(current).join(loc).human_repr()
                            continue
                        # Terminal response — read up to max_bytes.
                        body = bytearray()
                        truncated = False
                        async for chunk in resp.aiter_bytes():
                            remaining = self._max_bytes - len(body)
                            if remaining <= 0:
                                truncated = True
                                break
                            body.extend(chunk[:remaining])
                            if len(body) >= self._max_bytes:
                                truncated = True
                                break
                        content = bytes(body)
                        return CrawlResult(
                            final_url=current,
                            status=resp.status_code,
                            redirect_chain=redirect_chain,
                            content_type=resp.headers.get("content-type", ""),
                            content_bytes=content,
                            truncated=truncated,
                            content_hash=hashlib.sha256(content).hexdigest(),
                        )
                # Too many redirects.
                return CrawlResult(
                    final_url=current,
                    status=0,
                    redirect_chain=redirect_chain,
                    error="too_many_redirects",
                )
        except httpx.TimeoutException:
            return CrawlResult(final_url=final_url, status=0, error="timeout")
        except httpx.HTTPError as exc:
            return CrawlResult(
                final_url=final_url, status=0, error=f"http_error:{type(exc).__name__}"
            )
        except Exception as exc:
            logger.warning("crawler_unexpected_error url=%s err=%s", url, exc)
            return CrawlResult(
                final_url=final_url, status=0, error=f"unexpected:{type(exc).__name__}"
            )


def _ssrf_safe_destination(url: str) -> bool:
    """Reject URLs that resolve to internal/loopback/metadata addresses."""

    try:
        parsed = httpx.URL(url)
    except Exception:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    host = parsed.host
    if not host:
        return False

    if host.lower() in _SSRF_ALLOWLIST_HOSTS:
        return True

    # Resolve all A/AAAA records and reject if ANY are internal. Attackers
    # can return both a public and a private record (DNS rebinding).
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False

    seen = set()
    for info in infos:
        addr = info[4][0]
        if addr in seen:
            continue
        seen.add(addr)
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False
        # AWS / GCP / Azure metadata endpoints.
        if str(ip) in {"169.254.169.254", "169.254.170.2", "fd00:ec2::254"}:
            return False
    return True
