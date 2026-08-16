"""Detonation sandbox client.

The gate does NOT run a browser in-process. Detonation lives in a
separate worker service (see ``services/detonation-worker/``) that
runs on an isolated network with no route to internal services. This
module is the HTTP client.

Why this split:

  - The worker uses ``mcr.microsoft.com/playwright/python``, which
    tracks Chromium + OS libs as a published image. Trying to install
    ``playwright install --with-deps chromium`` on the gate's PQC
    Debian base hits Ubuntu/Debian package-name mismatches.
  - Mixing fetches of attacker-controlled web pages with calls into
    backend services (detection, policy, audit) in one namespace is
    the wrong shape. A worker-only network keeps detonation egress-only.
  - The interface is unchanged: callers still get a ``DetonationResult``
    dataclass; the gate's extractors / evidence layer don't move.

If the worker URL is unset or unreachable the call returns
``DetonationResult(error=...)`` and the gate cleanly downgrades to
standard-depth behaviour for that request.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

import httpx

logger = logging.getLogger("url_trust_gate.detonation")

DETONATION_WORKER_URL = os.getenv("DETONATION_WORKER_URL", "")
DETONATION_WORKER_API_SECRET = os.getenv(
    "DETONATION_WORKER_API_SECRET", "change-me-detonation-worker"
)
DETONATION_WORKER_TIMEOUT_S = float(
    os.getenv("DETONATION_WORKER_TIMEOUT_S", "15.0")
)


@dataclass
class DetonationResult:
    rendered_html: str = ""
    visible_text: str = ""
    hidden_text: str = ""
    css_hidden_text: str = ""
    unicode_hidden_text: str = ""
    forms: List[dict] = field(default_factory=list)
    downloads: List[dict] = field(default_factory=list)
    scripts_inline: List[str] = field(default_factory=list)
    screenshot_hash: Optional[str] = None
    error: Optional[str] = None
    request_count: int = 0
    bytes_transferred: int = 0

    @property
    def succeeded(self) -> bool:
        """True only when the sandbox actually rendered the page.

        render() NEVER RETURNS None. Every failure path -- worker not
        configured (:94), non-200 or 401 (:113/:117), timeout (:132),
        unreachable (:140) -- returns a DetonationResult carrying `error`.

        So `detonation_result is not None` is an identity check that is true
        whenever detonation was ATTEMPTED, and callers used it to populate a
        field named `detonated`. A worker that was absent, 401'd on a
        mistyped secret, or timed out therefore produced a policy input, an
        API response and an AUDIT RECORD all asserting the URL had been
        detonated in a sandbox when nothing had rendered it.

        An evidence trail that overstates what was inspected is worse than
        one that admits it could not look.
        """
        return not self.error


class DetonationSandbox:
    """HTTP client for the detonation-worker service."""

    def __init__(
        self,
        worker_url: str = DETONATION_WORKER_URL,
        api_secret: str = DETONATION_WORKER_API_SECRET,
        timeout_s: float = DETONATION_WORKER_TIMEOUT_S,
    ):
        self._worker_url = (worker_url or "").rstrip("/")
        self._api_secret = api_secret
        self._timeout_s = timeout_s
        self._http: Optional[httpx.AsyncClient] = None

    @property
    def configured(self) -> bool:
        return bool(self._worker_url)

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            # IMPORTANT: trust_env=False so user-configured proxies don't
            # accidentally route gate-to-worker traffic through the open
            # internet. The gate must reach the worker via the internal
            # detonation network and nowhere else.
            self._http = httpx.AsyncClient(
                timeout=self._timeout_s, trust_env=False, http2=False
            )
        return self._http

    async def render(
        self, url: str, *, tenant_id: str, request_id: str
    ) -> DetonationResult:
        if not self._worker_url:
            return DetonationResult(error="detonation_worker_not_configured")

        try:
            client = await self._client()
            resp = await client.post(
                f"{self._worker_url}/render",
                json={
                    "url": url,
                    "tenant_id": tenant_id,
                    "request_id": request_id,
                },
                headers={"x-api-key": self._api_secret},
            )
            if resp.status_code != 200:
                logger.warning(
                    "detonation_worker_non_200 status=%s body=%s",
                    resp.status_code,
                    resp.text[:200],
                )
                return DetonationResult(
                    error=f"worker_status_{resp.status_code}"
                )
            payload = resp.json() or {}
            return DetonationResult(
                rendered_html=payload.get("rendered_html", "") or "",
                visible_text=payload.get("visible_text", "") or "",
                hidden_text=payload.get("hidden_text", "") or "",
                css_hidden_text=payload.get("css_hidden_text", "") or "",
                unicode_hidden_text=payload.get("unicode_hidden_text", "") or "",
                forms=payload.get("forms") or [],
                downloads=payload.get("downloads") or [],
                scripts_inline=payload.get("scripts_inline") or [],
                screenshot_hash=payload.get("screenshot_hash"),
                error=payload.get("error"),
                request_count=int(payload.get("request_count", 0) or 0),
                bytes_transferred=int(payload.get("bytes_transferred", 0) or 0),
            )
        except httpx.TimeoutException:
            return DetonationResult(error="worker_timeout")
        except Exception as exc:
            logger.warning(
                "detonation_worker_error tenant=%s request=%s err=%s",
                tenant_id,
                request_id,
                exc,
            )
            return DetonationResult(
                error=f"worker_unreachable:{type(exc).__name__}"
            )

    async def aclose(self) -> None:
        if self._http is not None and not self._http.is_closed:
            await self._http.aclose()
