"""CyberArmor URL / Context Trust Gate Service.

Pre-ingestion control point that sits between humans, browsers, endpoint
agents, RASP-instrumented apps, and AI agents on one side, and the open
web on the other. Before any of those consumers fetches or follows a URL,
or ingests external content into AI context, the gate:

  1. Canonicalises the URL (host, path, querystring, redirect chain).
  2. Looks up reputation (tenant allow/block lists, cached verdicts, optional
     external feeds: Google Safe Browsing v4, Microsoft SmartScreen, VirusTotal v3).
  3. Optionally fetches the destination with an isolated low-footprint
     crawler (no user creds/cookies, SSRF-blocked egress, size/time-limited).
  4. Optionally renders the page in a detonation sandbox to catch hidden
     DOM/CSS-hidden/Unicode-hidden promptware.
  5. Streams extracted content to the Detection Service for phishing,
     prompt-injection, promptware, DLP/exfil, and IOC scoring.
  6. Calls the Policy Service to map score+context to an action
     (allow / warn / redact / sandbox / block / isolate).
  7. Optionally dispatches incidents to the Response Service.
  8. Persists evidence (URL hash, redirect chain, extracted IOCs, content
     hash, decision lineage) to the Audit Service.

All paths run end-to-end. The 15-minute PoC installer (scripts/poc/install.sh)
demonstrates benign, CSS-hidden promptware, zero-width injection, and
credential-harvest scenarios producing live verdicts in under 120 ms.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from cyberarmor_core.crypto import (
    build_auth_headers,
    get_public_key_info,
    verify_shared_secret,
)

from canonicalize import canonicalize_url, classify_querystring_sensitivity
from reputation import ReputationCache, ReputationVerdict
from crawler import SafeCrawler, CrawlResult
from detonation import DetonationSandbox, DetonationResult
from extractors import extract_signals, ExtractedSignals
from evidence import EvidenceRecord, EvidenceWriter
from cyberarmor_core.audit_writer import AuditWriter
from feeds import ReputationAggregator
from metrics import MetricsRegistry
import consumer_verdict

#: Single-user product: there is no tenant. The constant still reaches the
#: evidence record and the audit hash chain, where one value collapses that
#: chain to a single chain -- correct for one account, not a workaround.
DEFAULT_ACCOUNT_ID = "aiprotect"

#: Attribution fallback when a caller sends no device. Matches the convention
#: settled in the seam spikes: agent_id is the enrolled device, or a surface
#: literal when no device originated the event.
UNATTRIBUTED_DEVICE = "aiprotect-api"


def resolve_device_id(req: "TrustGateRequest") -> str:
    """Which enrolled device this evaluation belongs to.

    A subscription covers many devices, so every verdict has to be
    attributable to one of them or the Activity feed cannot say where
    something happened. `device_id` is the consumer-facing spelling;
    `agent_id` is the inherited one and is still honoured.
    """
    return req.device_id or req.agent_id or UNATTRIBUTED_DEVICE

logger = logging.getLogger("url_trust_gate")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

URL_TRUST_GATE_API_SECRET = os.getenv("URL_TRUST_GATE_API_SECRET", "change-me-url-trust-gate")
DETECTION_SERVICE_URL = os.getenv("DETECTION_SERVICE_URL", "http://detection:8002")
DETECTION_API_SECRET = os.getenv("DETECTION_API_SECRET", "change-me-detection")
POLICY_SERVICE_URL = os.getenv("POLICY_SERVICE_URL", "http://policy:8001")
POLICY_API_SECRET = os.getenv("POLICY_API_SECRET", "change-me-policy")
RESPONSE_SERVICE_URL = os.getenv("RESPONSE_SERVICE_URL", "http://response:8003")
RESPONSE_API_SECRET = os.getenv("RESPONSE_API_SECRET", "change-me-response")
AUDIT_SERVICE_URL = os.getenv("AUDIT_SERVICE_URL", "http://audit:8011")
AUDIT_API_SECRET = os.getenv("AUDIT_API_SECRET", "change-me-audit")

ENFORCE_SECURE_SECRETS = os.getenv(
    "CYBERARMOR_ENFORCE_SECURE_SECRETS", "false"
).strip().lower() in {"1", "true", "yes", "on"}
ALLOW_INSECURE_DEFAULTS = os.getenv(
    "CYBERARMOR_ALLOW_INSECURE_DEFAULTS", "false"
).strip().lower() in {"1", "true", "yes", "on"}

# Crawler / detonation defaults. These are conservative by design: every
# enterprise-safe trap called out in the design (latency, SSRF, side
# effects, dynamic content, false positives) is bounded by one of these.
CRAWLER_TIMEOUT_S = float(os.getenv("URL_TRUST_GATE_CRAWLER_TIMEOUT_S", "4.0"))
CRAWLER_MAX_BYTES = int(os.getenv("URL_TRUST_GATE_CRAWLER_MAX_BYTES", "1048576"))  # 1 MiB
CRAWLER_MAX_REDIRECTS = int(os.getenv("URL_TRUST_GATE_CRAWLER_MAX_REDIRECTS", "5"))
DETONATION_DEFAULT_OFF = os.getenv("URL_TRUST_GATE_DETONATION_DEFAULT", "off").lower() != "on"
FAST_PATH_CACHE_TTL_S = int(os.getenv("URL_TRUST_GATE_CACHE_TTL_S", "900"))


def _enforce_secure_secrets() -> None:
    if not ENFORCE_SECURE_SECRETS or ALLOW_INSECURE_DEFAULTS:
        return
    lowered = (URL_TRUST_GATE_API_SECRET or "").strip().lower()
    if not lowered or lowered.startswith("change-me") or "changeme" in lowered:
        raise RuntimeError(
            "Refusing startup with insecure defaults in strict secret mode. "
            "Set strong value for: URL_TRUST_GATE_API_SECRET. "
            "For local dev only, set CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true."
        )


_enforce_secure_secrets()


def verify_api_key(api_key: Annotated[str | None, Header(alias="x-api-key")] = None):
    verify_shared_secret(api_key, URL_TRUST_GATE_API_SECRET, service_name="url-trust-gate")


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class TrustGateRequest(BaseModel):
    """Incoming request to evaluate a URL before a consumer fetches it."""

    # AIProtect has accounts and devices, not tenants. The field is kept and
    # defaulted rather than deleted: it still flows into the evidence record
    # and the audit service's hash chain, where a single constant collapses
    # that chain to one chain -- which is the correct shape for a single-user
    # product, not a workaround. Callers never send it.
    tenant_id: str = DEFAULT_ACCOUNT_ID
    url: str
    # Where the request originated. Drives policy and evidence tagging.
    # Examples: "browser-extension", "endpoint-agent", "proxy", "rasp",
    # "ai-router", "office-extension", "email-link-rewrite".
    source: str
    # Optional consumer identity context (user, app, agent). Used by the
    # policy engine; never logged in raw form unless tenant policy allows.
    user_id: Optional[str] = None
    app_id: Optional[str] = None
    # Legacy spelling of device_id. Kept so forked callers keep working.
    agent_id: Optional[str] = None
    # THE DEVICE THAT ASKED. A subscription covers many devices, so "which of
    # my devices hit this link" is a question the Activity feed has to be able
    # to answer -- "Blocked on your iPhone" is only possible if the identity
    # rides along with the evaluation. Resolved via `resolve_device_id()`,
    # which prefers this over the legacy `agent_id`.
    device_id: Optional[str] = None
    # Hint to the gate about how much work to do. "fast" = cache + reputation
    # only; "standard" = + safe crawl; "deep" = + detonation sandbox.
    depth: str = Field(default="standard", pattern="^(fast|standard|deep)$")
    # If true, the consumer is asking the gate to render in a sandbox even
    # when policy would normally short-circuit on cache hit. Used for
    # one-off "is this still safe?" checks.
    force_recrawl: bool = False
    # Optional caller-provided context. Free-form; used only by policy.
    context: Optional[Dict[str, Any]] = None


class IOC(BaseModel):
    kind: str  # url|domain|ip|email|hash|wallet|phone|...
    value: str
    confidence: float = 0.0
    source: str = "url-trust-gate"


class TrustGateScores(BaseModel):
    phishing: float = 0.0
    malware: float = 0.0
    prompt_injection: float = 0.0
    promptware: float = 0.0
    data_exfil: float = 0.0
    credential_harvest: float = 0.0
    brand_impersonation: float = 0.0
    overall_risk: float = 0.0


class TrustGateDecision(BaseModel):
    # action mirrors policy service vocabulary plus gate-specific extras.
    action: str  # allow|warn|redact|sandbox|block|isolate
    reason: str
    matched_policy: Optional[str] = None
    redact_segments: List[str] = Field(default_factory=list)
    # If the gate suggests browser isolation, this is where to redirect.
    isolation_url: Optional[str] = None


class TrustGateResponse(BaseModel):
    request_id: str
    tenant_id: str
    #: Which device this verdict was produced for. Echoed so a client holding
    #: several enrolled devices can attribute the result without correlating.
    device_id: Optional[str] = None
    #: WHICH SURFACE ON THAT DEVICE asked -- browser extension, desktop agent,
    #: mobile app. One device runs several; they share a subscription slot but
    #: are separately installed and separately revocable, so attribution needs
    #: both halves. "Blocked in Chrome on your MacBook" is device + surface;
    #: neither alone is a sentence anybody can act on.
    surface: Optional[str] = None
    #: Plain-language rendering for a person: verdict / reason /
    #: checks_performed. See consumer_verdict.py -- `safe` is a bounded claim
    #: ("nothing we checked came back bad"), never an assertion about the page.
    consumer: Dict[str, Any] = Field(default_factory=dict)
    canonical_url: str
    redirect_chain: List[str] = Field(default_factory=list)
    cache_hit: bool = False
    crawled: bool = False
    detonated: bool = False
    scores: TrustGateScores
    iocs: List[IOC] = Field(default_factory=list)
    decision: TrustGateDecision
    evidence_id: Optional[str] = None


class FeedbackPayload(BaseModel):
    """SOC analyst FP/FN correction on a prior gate decision.

    Either ``request_id`` or ``url_fingerprint`` must be provided so the
    record can be linked back to the original evidence entry in the audit
    service. ``corrected_action`` is optional — omit it when the analyst
    is only flagging the verdict without specifying what the right action
    should have been.
    """
    tenant_id: str
    # At least one of these must be supplied to identify the original decision.
    request_id: Optional[str] = None
    url_fingerprint: Optional[str] = None
    # "false_positive" = gate blocked/warned something that was safe.
    # "false_negative" = gate allowed something that was hostile.
    verdict: str = Field(..., pattern="^(false_positive|false_negative)$")
    corrected_action: Optional[str] = Field(
        default=None,
        pattern="^(allow|warn|redact|sandbox|block|isolate)$",
    )
    analyst_id: Optional[str] = None
    notes: Optional[str] = None
    elapsed_ms: int = 0


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(title="CyberArmor URL / Context Trust Gate", version="0.1.0")
SERVICE_STARTED_AT = datetime.now(timezone.utc)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Module-level singletons. Each is a thin wrapper today; the heavy lifting
# is intentionally pushed behind these interfaces so they can be swapped
# out (e.g. detonation -> dedicated containerised sandbox cluster) without
# touching the request handler.
_reputation_cache = ReputationCache(ttl_s=FAST_PATH_CACHE_TTL_S)
_crawler = SafeCrawler(
    timeout_s=CRAWLER_TIMEOUT_S,
    max_bytes=CRAWLER_MAX_BYTES,
    max_redirects=CRAWLER_MAX_REDIRECTS,
)
_detonation = DetonationSandbox()
_evidence = EvidenceWriter(audit_url=AUDIT_SERVICE_URL, audit_secret=AUDIT_API_SECRET)

#: THE AUDIT WRITE IS NO LONGER IN THE REQUEST PATH. Changed 2026-08-14.
#:
#: /evaluate used to `await _evidence.write(...)` inline. The comment above that
#: call said "gate decision is never blocked by it" -- true of the DECISION and
#: false of the REQUEST. With 3 retries at 0.25/0.5/1.0s backoff and a 2s
#: timeout each, a DOWN audit service added up to ~8 SECONDS to every
#: /evaluate -- and the MITM proxy calls /evaluate on every inspected request.
#:
#: MEASURED: restarting the audit service on 2026-08-14 pushed this container's
#: own healthcheck past its timeout, and the host watchdog emailed
#: "Unhealthy (unmanaged): docker-compose-url-trust-gate-1". An audit outage
#: degraded the enforcement path.
#:
#: The shared writer buffers in memory, batches to /events/batch, and spools to
#: a durable volume when audit is unreachable -- so a failed write becomes an
#: event that still gets delivered, instead of the dead-letter LOG LINE the old
#: path produced, which nobody was reading and which lost every record.
_audit = AuditWriter(service_url=AUDIT_SERVICE_URL, api_secret=AUDIT_API_SECRET)
_feeds = ReputationAggregator.from_env()
_metrics = MetricsRegistry()

#: Held so the task is not garbage-collected mid-flight; asyncio keeps only a
#: weak reference to a bare create_task().
_feed_sync_task = None

#: Same reason. Without a strong reference the audit flush loop can be collected
#: mid-flight and every buffered event is lost silently.
_audit_flush_task = None


def _audit_enqueue_evidence(record: EvidenceRecord) -> Optional[str]:
    """Hand one evidence record to the buffered writer. Returns its id.

    Deliberately SYNCHRONOUS and non-blocking: it appends to an in-memory deque
    and returns. The previous implementation awaited an HTTP POST with three
    retries here, inside /evaluate, which the MITM proxy calls on every
    inspected request -- so a down audit service added seconds to real user
    traffic and took this container's healthcheck down with it.

    Returns None only if the mapping itself fails, which is what
    observe_evidence_write_error() at the call site records. Delivery failures
    are no longer reported here at all, because they are no longer final: the
    writer spools and retries. Reporting a spooled event as an error would
    train an operator to ignore the metric that means real loss.
    """
    try:
        import uuid as _uuid
        from dataclasses import asdict as _asdict
        from evidence import _as_audit_event

        evidence_id = _uuid.uuid4().hex
        payload = {"evidence_id": evidence_id, **_asdict(record)}
        _audit.enqueue(_as_audit_event(evidence_id, record, payload))
        return evidence_id
    except Exception as exc:   # never propagate into the gate's decision
        logger.warning("audit_enqueue_failed err=%s", exc)
        return None

#: How often to pull Safe Browsing list updates. Google's own
#: `minimumWaitDuration` is honoured inside the client, so a shorter value here
#: cannot rate-limit the key -- the fetch just returns early.
FEED_SYNC_INTERVAL_S = float(os.getenv("FEED_SYNC_INTERVAL_S", "1800"))


@app.on_event("startup")
async def _start_feed_sync() -> None:
    """Begin keeping local threat lists current.

    Safe Browsing moved from the Lookup API (one HTTPS call to Google per URL,
    quota-limited, and disclosing every customer URL) to the Update API, which
    matches SHA-256 prefixes locally. That only works if something downloads
    the lists -- without this hook the database stays empty and every verdict
    comes back `authoritative=False`, which is honest but useless.
    """
    global _feed_sync_task, _audit_flush_task
    _feed_sync_task = _feeds.start_background_sync(FEED_SYNC_INTERVAL_S)

    # The audit flush loop. Without it, evidence accumulates in memory and dies
    # with the process -- the writer buffers by design, so something has to
    # drain it.
    try:
        _audit_flush_task = asyncio.get_running_loop().create_task(
            _audit.run_forever(httpx.AsyncClient(timeout=5.0, trust_env=False)))
        logger.info(
            "audit_writer_started url=%s spool_ready=%s",
            AUDIT_SERVICE_URL, _audit.stats()["spool_ready"])
    except RuntimeError as exc:
        logger.error("audit_writer_not_started err=%s", exc)
    if _feed_sync_task is None:
        logger.info(
            "feed_sync_disabled reason=no_feed_maintains_a_local_list -- "
            "URL verdicts will rest on local signals only"
        )

# URL fingerprints with a background warm-crawl already in flight, so a
# burst of depth=fast requests for the same first-seen URL doesn't spawn a
# crawl per request. See _schedule_background_crawl.
_background_crawl_inflight: set[str] = set()


# ---------------------------------------------------------------------------
# Health / readiness / metrics — match conventions from detection & policy
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "url-trust-gate",
        "started_at": SERVICE_STARTED_AT.isoformat(),
        "uptime_s": int((datetime.now(timezone.utc) - SERVICE_STARTED_AT).total_seconds()),
    }


@app.get("/ready")
async def ready() -> Dict[str, Any]:
    """Readiness probe — returns 200 only when required dependencies are reachable.

    Probes detection, policy, and audit services (all required). Also probes the
    detonation worker if DETONATION_WORKER_URL is configured. Each probe uses a
    short timeout so this endpoint completes in well under one second.
    """
    _PROBE_TIMEOUT = 2.0  # seconds per dependency

    deps: Dict[str, str] = {}
    failed: list[str] = []

    probe_targets = [
        ("detection", DETECTION_SERVICE_URL, DETECTION_API_SECRET),
        ("policy", POLICY_SERVICE_URL, POLICY_API_SECRET),
        ("audit", AUDIT_SERVICE_URL, AUDIT_API_SECRET),
    ]

    # Detonation worker is optional — only probe if configured.
    _det_url = os.getenv("DETONATION_WORKER_URL", "")
    _det_secret = os.getenv("DETONATION_WORKER_API_SECRET", "")
    if _det_url:
        probe_targets.append(("detonation-worker", _det_url, _det_secret))

    async def _probe(name: str, base_url: str, secret: str) -> tuple[str, str]:
        try:
            async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT) as client:
                resp = await client.get(
                    f"{base_url}/health",
                    headers={"x-api-key": secret} if secret else {},
                )
                if resp.status_code == 200:
                    return name, "ok"
                return name, f"http_{resp.status_code}"
        except httpx.TimeoutException:
            return name, "timeout"
        except Exception as exc:
            return name, f"error:{type(exc).__name__}"

    results = await asyncio.gather(*[_probe(n, u, s) for n, u, s in probe_targets])

    for name, status in results:
        deps[name] = status
        if status != "ok":
            failed.append(name)

    if failed:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "failed": failed, "deps": deps},
        )

    return {"status": "ready", "deps": deps}


@app.get("/metrics")
def metrics() -> PlainTextResponse:
    # Prometheus expects the canonical content-type on the scrape endpoint.
    # The version string ("0.0.4") tells Prometheus which text format we emit
    # so it can parse the exposition correctly.
    return PlainTextResponse(
        _metrics.render(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.get("/pki/public-key")
def pki_public_key() -> Dict[str, Any]:
    return get_public_key_info()


# ---------------------------------------------------------------------------
# Core endpoint
# ---------------------------------------------------------------------------


def _detonation_succeeded(result: "Optional[DetonationResult]") -> bool:
    """Did the sandbox actually render this URL?

    NOT `result is not None`. render() returns a result object on every
    failure path, so identity means "detonation was attempted", not
    "detonation happened". This distinction is the difference between an
    audit record that is true and one that is not.
    """
    return bool(result is not None and result.succeeded)


@app.post("/evaluate", response_model=TrustGateResponse, dependencies=[Depends(verify_api_key)])
async def evaluate(req: TrustGateRequest) -> TrustGateResponse:
    """Evaluate a URL/context request and return an enforcement decision.

    This is the single entry point used by browser extensions, endpoint
    agents, the proxy/RASP path, and the AI router. Latency budget for
    `depth=fast` is ~10ms (cache + canonicalisation only); `standard`
    targets <500ms with safe crawl; `deep` is best-effort and may run for
    several seconds inside the detonation sandbox.
    """

    start = time.monotonic()
    request_id = _new_request_id(req)

    # ---------------- 1. Canonicalise + querystring classification ----------
    canonical = canonicalize_url(req.url)
    qs_sensitivity = classify_querystring_sensitivity(canonical.query_params)
    # NOTE: redacted_url is what we LOG and store in evidence. Raw URL with
    # sensitive querystring values never leaves this function.
    redacted_url = canonical.redacted_url(qs_sensitivity)

    # ---------------- 2. Reputation / cache fast path -----------------------
    cached: Optional[ReputationVerdict] = None
    if not req.force_recrawl:
        cached = _reputation_cache.lookup(canonical.fingerprint)

    if cached is not None and req.depth == "fast":
        decision = await _decide_with_policy(
            req=req,
            scores=cached.scores,
            iocs=cached.iocs,
            canonical_url=redacted_url,
            crawled=False,
            detonated=False,
        )
        return _build_response(
            request_id=request_id,
            req=req,
            canonical_url=redacted_url,
            redirect_chain=cached.redirect_chain,
            cache_hit=True,
            crawled=False,
            detonated=False,
            scores=cached.scores,
            iocs=cached.iocs,
            decision=decision,
            evidence_id=None,  # fast path skips evidence write by design
            start=start,
        )

    if cached is None and req.depth == "fast":
        # First-seen URL under the fast (cache/reputation-only) contract.
        # Answer immediately from external reputation feeds below, same as
        # always, but also warm the cache with a real crawl in the
        # background so the NEXT depth=fast lookup -- from ANY caller, not
        # just this one -- gets actual content-based signals instead of
        # reputation-only ones forever. Every live caller (proxy, RASP)
        # only ever requests depth=fast and never triggers a crawl
        # themselves; only the browser extension does an equivalent
        # backfill today, client-side, per tab. Centralizing it here
        # benefits every caller uniformly without touching those call
        # sites again.
        _schedule_background_crawl(req, canonical)

    # ---------------- 3. (removed) tenant allow / block lists ---------------
    # The B2B gate short-circuited here on a per-tenant allow/block list
    # fetched from the policy service. Removed with the fork: there is no
    # policy service in this product and no tenant to scope a list to, so the
    # lookup could only ever have returned None.
    #
    # NOT a decision to go without per-account lists. "Always allow this site"
    # and "never open this site" are good consumer features and they belong
    # here -- but they belong on the ACCOUNT, evaluated against the enrolled
    # device set, and the API that owns accounts does not exist yet. Building
    # them against a tenant-shaped lookup first would be building the wrong
    # thing. Tracked in FORK-PROVENANCE.md.

    # ---------------- 4. Safe crawl -----------------------------------------
    crawl_result: Optional[CrawlResult] = None
    if req.depth in {"standard", "deep"}:
        crawl_result = await _crawler.fetch(
            canonical.url,
            tenant_id=req.tenant_id,
            request_id=request_id,
        )

    # ---------------- 5. Detonation (deep only) -----------------------------
    detonation_result: Optional[DetonationResult] = None
    if req.depth == "deep" and not DETONATION_DEFAULT_OFF:
        detonation_result = await _detonation.render(
            canonical.url,
            tenant_id=req.tenant_id,
            request_id=request_id,
        )
        # A failure has to leave a trace an operator can find. Without this the
        # only record of a dead worker was a `detonated: true` field claiming
        # the opposite -- and url_trust_gate_detonation_timeouts_total sat at 0
        # forever because observe_detonation_timeout() had no caller anywhere in
        # the service, while those same timeouts were counted as successes by
        # url_trust_gate_detonations_total.
        if detonation_result is not None and detonation_result.error:
            if detonation_result.error == "worker_timeout":
                _metrics.observe_detonation_timeout()
            logger.warning(
                "detonation_failed request_id=%s url=%s error=%s -- this URL was "
                "NOT rendered in a sandbox; the decision below is based on the "
                "crawl and feeds only",
                request_id, redacted_url, detonation_result.error,
            )

    # ---------------- 6. Signal extraction + ML scoring ---------------------
    signals: ExtractedSignals = extract_signals(
        canonical=canonical,
        crawl=crawl_result,
        detonation=detonation_result,
    )
    scores, iocs = await _score_with_detection(req, signals, session_id=request_id)

    # External reputation feeds (Safe Browsing etc.) run in parallel with
    # detection in spirit, but for simplicity we sequence them after. They
    # only sharpen the verdict — they're never the sole reason to block.
    feed_verdict = await _feeds.lookup(canonical.url)
    if feed_verdict.matched:
        for src in feed_verdict.sources:
            _metrics.observe_feed_hit(src)
        scores.phishing = max(scores.phishing, feed_verdict.phishing)
        scores.malware = max(scores.malware, feed_verdict.malware)
        scores.overall_risk = max(
            scores.overall_risk, scores.phishing, scores.malware
        )
        for tt in feed_verdict.threat_types:
            iocs.append(
                IOC(
                    kind="threat-type",
                    value=tt,
                    confidence=feed_verdict.phishing or feed_verdict.malware,
                    source=",".join(feed_verdict.sources) or "external-feed",
                )
            )

    # ---------------- 7. Policy decision ------------------------------------
    decision = await _decide_with_policy(
        req=req,
        scores=scores,
        iocs=iocs,
        canonical_url=redacted_url,
        crawled=crawl_result is not None,
        detonated=_detonation_succeeded(detonation_result),
    )

    # ---------------- 8. Evidence + cache write -----------------------------
    # ENQUEUED, not awaited. See the _audit note at the top of this module: the
    # previous inline await put the audit service's outages into this request
    # path, and the proxy calls /evaluate on every inspected request.
    evidence_id = _audit_enqueue_evidence(
        EvidenceRecord(
            request_id=request_id,
            tenant_id=req.tenant_id,
            source=req.source,
            user_id=req.user_id,
            app_id=req.app_id,
            agent_id=req.agent_id,
            canonical_url=redacted_url,
            url_fingerprint=canonical.fingerprint,
            redirect_chain=crawl_result.redirect_chain if crawl_result else [],
            content_hash=crawl_result.content_hash if crawl_result else None,
            screenshot_hash=detonation_result.screenshot_hash if detonation_result else None,
            scores=scores.model_dump(),
            iocs=[i.model_dump() for i in iocs],
            decision=decision.model_dump(),
            crawled=crawl_result is not None,
            detonated=_detonation_succeeded(detonation_result),
            recorded_at=datetime.now(timezone.utc).isoformat(),
        )
    )
    if evidence_id is None:
        _metrics.observe_evidence_write_error()

    _reputation_cache.store(
        canonical.fingerprint,
        ReputationVerdict(
            scores=scores,
            iocs=iocs,
            redirect_chain=crawl_result.redirect_chain if crawl_result else [],
        ),
    )

    # ---------------- 9. Optional incident dispatch -------------------------
    if decision.action in {"block", "isolate"} and scores.overall_risk >= 0.8:
        await _dispatch_incident(req, decision, redacted_url, scores, iocs, evidence_id)

    return _build_response(
        request_id=request_id,
        req=req,
        canonical_url=redacted_url,
        redirect_chain=crawl_result.redirect_chain if crawl_result else [],
        cache_hit=False,
        crawled=crawl_result is not None,
        detonated=_detonation_succeeded(detonation_result),
        scores=scores,
        iocs=iocs,
        decision=decision,
        evidence_id=evidence_id,
        start=start,
    )


@app.post("/feedback", dependencies=[Depends(verify_api_key)])
async def feedback(payload: FeedbackPayload) -> Dict[str, Any]:
    """SOC analyst FP/FN correction on a prior gate decision.

    Accepts a structured, schema-validated correction record and persists it
    to the audit service. The record is linked back to the original gate
    decision via ``request_id`` or ``url_fingerprint``.

    At least one of ``request_id`` or ``url_fingerprint`` must be supplied.
    Returns 422 on schema violations (FastAPI validates the Pydantic model
    before this function body runs).

    Writes are best-effort and non-blocking — a failed audit write returns
    ``accepted`` anyway so analysts are never blocked waiting for the
    backend. The write failure is counted in Prometheus.

    THAT LAST SENTENCE WAS FALSE UNTIL 2026-08-12 for the failure that was
    actually occurring. The response object was discarded, so only transport
    errors reached the counter; a 422 — which is what every one of these writes
    returned, because trace_id and agent_id were missing — sailed through as
    success. The status is now checked and counted.
    """
    if not payload.request_id and not payload.url_fingerprint:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=422,
            detail="At least one of request_id or url_fingerprint is required.",
        )

    record = payload.model_dump(exclude_none=True)
    logger.info(
        "feedback_received tenant=%s verdict=%s request_id=%s",
        payload.tenant_id,
        payload.verdict,
        payload.request_id or payload.url_fingerprint,
    )

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                f"{AUDIT_SERVICE_URL}/events",
                json={
                    # trace_id and agent_id are REQUIRED by AuditEvent and were
                    # both absent, so this write returned 422 every time it ran.
                    # The response was never inspected -- `await client.post(...)`
                    # with the result discarded -- so the except below caught
                    # transport errors only and a 422 passed as success. The
                    # docstring's claim that the failure is counted in Prometheus
                    # was true for a dropped socket and false for the failure
                    # that actually happened, every time.
                    "trace_id": payload.request_id or payload.url_fingerprint,
                    "tenant_id": payload.tenant_id,
                    "agent_id": "url-trust-gate",
                    "event_type": "url_trust_gate_feedback",
                    "outcome": str(payload.verdict),
                    # Declared field: pydantic drops unknown keys silently, so
                    # "service" and "data" were being discarded even on a body
                    # that validated. The analyst's correction IS the record.
                    "detail": {"service": "url-trust-gate", **record},
                },
                headers={"x-api-key": AUDIT_API_SECRET},
            )
        if resp.status_code >= 400:
            # The status is now READ. A rejected write is a lost analyst
            # correction, and this endpoint answers "accepted" either way.
            logger.warning(
                "feedback_audit_write_rejected status=%s body=%s request_id=%s",
                resp.status_code, resp.text[:200],
                payload.request_id or payload.url_fingerprint,
            )
            _metrics.inc_error("feedback_audit_write")
    except Exception as exc:
        logger.warning("feedback_audit_write_failed err=%s", exc)
        _metrics.inc_error("feedback_audit_write")

    return {"status": "accepted", "feedback_id": record.get("request_id") or record.get("url_fingerprint")}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _new_request_id(req: TrustGateRequest) -> str:
    h = hashlib.sha256()
    h.update(req.tenant_id.encode())
    h.update(b"\0")
    h.update(req.url.encode())
    h.update(b"\0")
    h.update(str(time.time_ns()).encode())
    return h.hexdigest()[:24]


def _build_response(
    *,
    request_id: str,
    req: TrustGateRequest,
    canonical_url: str,
    redirect_chain: List[str],
    cache_hit: bool,
    crawled: bool,
    detonated: bool,
    scores: TrustGateScores,
    iocs: List[IOC],
    decision: TrustGateDecision,
    evidence_id: Optional[str],
    start: float,
) -> TrustGateResponse:
    elapsed_ms = int((time.monotonic() - start) * 1000)
    _metrics.observe_request(
        depth=req.depth,
        decision=decision.action,
        cache_hit=cache_hit,
        crawled=crawled,
        detonated=detonated,
        elapsed_ms=elapsed_ms,
    )
    return TrustGateResponse(
        request_id=request_id,
        tenant_id=req.tenant_id,
        device_id=resolve_device_id(req),
        surface=req.source,
        consumer=consumer_verdict.summarise(
            action=decision.action,
            scores=scores,
            depth=req.depth,
            cache_hit=cache_hit,
            crawled=crawled,
            detonated=detonated,
        ),
        canonical_url=canonical_url,
        redirect_chain=redirect_chain,
        cache_hit=cache_hit,
        crawled=crawled,
        detonated=detonated,
        scores=scores,
        iocs=iocs,
        decision=decision,
        evidence_id=evidence_id,
        elapsed_ms=elapsed_ms,
    )





def _schedule_background_crawl(req: TrustGateRequest, canonical: "CanonicalUrl") -> None:
    """Fire-and-forget standard-depth crawl (escalating to deep/detonation
    for elevated-risk results) to warm the reputation cache for a
    first-seen URL. Never blocks the depth=fast caller and never lets an
    exception escape into the request handler -- this is purely cache
    warming, not something any caller is waiting on.
    """
    fingerprint = canonical.fingerprint
    if fingerprint in _background_crawl_inflight:
        return
    _background_crawl_inflight.add(fingerprint)

    async def _run() -> None:
        bg_request_id = f"bg-{fingerprint[:12]}"
        try:
            crawl_result = await _crawler.fetch(
                canonical.url, tenant_id=req.tenant_id, request_id=bg_request_id,
            )
            signals = extract_signals(canonical=canonical, crawl=crawl_result, detonation=None)
            scores, iocs = await _score_with_detection(req, signals, session_id=bg_request_id)

            # Escalate to real browser rendering for anything the cheap
            # crawl already flagged as risky, or that looks suspicious at
            # the URL level alone (homoglyph). This is the only place in
            # the codebase that ever requests depth=deep -- every live
            # caller (proxy, RASP, browser extension) only ever asks for
            # depth=fast/standard, so detonation.py's real-browser
            # rendering (the only thing that sees JS-injected or
            # CSS-hidden content) previously never ran at all. Still
            # gated by the same DETONATION_DEFAULT_OFF ops kill switch
            # the explicit depth=deep request path respects.
            if (
                (scores.overall_risk >= 0.5 or canonical.homoglyph_suspected)
                and not DETONATION_DEFAULT_OFF
            ):
                detonation_result = await _detonation.render(
                    canonical.url, tenant_id=req.tenant_id, request_id=bg_request_id,
                )
                signals = extract_signals(
                    canonical=canonical, crawl=crawl_result, detonation=detonation_result,
                )
                scores, iocs = await _score_with_detection(req, signals, session_id=bg_request_id)

            _reputation_cache.store(
                fingerprint,
                ReputationVerdict(
                    scores=scores,
                    iocs=iocs,
                    redirect_chain=crawl_result.redirect_chain if crawl_result else [],
                ),
            )
        except Exception as exc:
            logger.debug("background_crawl_failed url_fp=%s err=%s", fingerprint, exc)
        finally:
            _background_crawl_inflight.discard(fingerprint)

    asyncio.create_task(_run())


# What a `sensitive_data` finding contributes to data_exfil, keyed by the
# thing that was found -- NOT by how confident the detector was that it had
# identified the token correctly.
#
# The defect this replaces (measured 2026-08-15): the mapping was
# ``scores.data_exfil = max(scores.data_exfil, f["confidence"])`` for every
# finding whose type contained "sensitive". The detection service's NER model
# emits type="sensitive_data" for ordinary named entities -- PER, LOC, ORG,
# GPE (services/detection/ml_models.py:936, _NER_PII_GROUPS at :585) -- and
# its ``confidence`` is the tagger's ENTITY-TYPE confidence: "I am 99.9% sure
# this token is a person's name." Read as a threat probability, that made
# every page naming a person, a company, or a place score data_exfil ~1.00,
# which became overall_risk ~1.00 (max-of across dimensions) and then a warn.
# scripts/poc/test-pages/benign.html -- a tea article naming "Camellia
# sinensis", "Vermont", and "the Tea Society of Vermont" -- is the reported
# case. Under a tenant with a redact or block policy on that threshold, this
# flagged essentially all traffic.
#
# Two errors were compounding, and both are fixed here:
#   1. an entity-classification confidence is not a threat probability;
#   2. PII-shaped text on a page you are VISITING is not data leaving.
#      Exfiltration is about egress; a contact page listing an email address
#      is not an exfiltration event.
#
# What survives is the narrow, defensible case: a page publishing a
# structured secret. Weights are the gate's own judgement of severity, so a
# leaked private key outranks a card number, and nothing reaches 1.0 on
# content evidence alone.
_EXFIL_WEIGHTS: dict[str, float] = {
    # Live credentials — the strongest content-only exfiltration signal.
    "private_key": 0.90,
    "aws_key": 0.90,
    "gcp_api_key": 0.85,
    "github_token": 0.85,
    "openai_api_key": 0.85,
    "anthropic_api_key": 0.85,
    "slack_token": 0.80,
    "stripe_key": 0.85,
    "generic_api_key": 0.70,
    "password_field": 0.70,
    "jwt": 0.65,
    # Regulated identifiers.
    "credit_card": 0.75,
    "ssn": 0.75,
    "ein": 0.55,
    "bank_routing": 0.65,
    "iban": 0.60,
    "crypto_address": 0.50,
    "passport": 0.60,
    "drivers_license": 0.55,
    "mrn": 0.60,
    "health_plan_id": 0.60,
    "npi": 0.45,
    "dea": 0.55,
    "date_of_birth": 0.35,
    # Semantic DLP concepts (services/detection/main.py:_SEMANTIC_DLP_PROTOTYPES).
    # These describe the SHAPE of the text -- "this reads like a credential
    # dump" -- which is the right kind of signal for exfiltration.
    "credential_exfiltration": 0.75,
    "source_code_secret_leak": 0.70,
    "pii_exposure": 0.60,
    "financial_sensitive": 0.50,
}

# Entity classes that appear on ordinary web pages and carry no exfiltration
# signal on their own. Listed explicitly rather than left to fall through, so
# that "we considered this and decided it scores zero" is distinguishable from
# "we have never seen this label" (which is logged below).
_NON_EXFIL_ENTITIES: frozenset[str] = frozenset({
    "person_name",
    "location",
    "organization",
    "geopolitical_entity",
    "ner_sensitive",      # NER subtype label, not a finding class
    "ner_pii_model",      # ditto
    "entity_dlp",         # container subtype; the real class is in `entity`
    "semantic_dlp",       # ditto, real class is in `concept`
    "email_address",
    "email",
    "phone_number",
    "phone",
    "ip_address",
    "url",
})

_EXFIL_UNKNOWN_LABELS_SEEN: set[str] = set()


def _exfil_score(finding: dict) -> float:
    """How much this `sensitive_data` finding says about data EXFILTRATION.

    Reads the finding's class from whichever field carries it -- the detection
    service uses `entity_type` (NER), `subtype` (regex passes), `entity`
    (entity regex) and `concept` (semantic DLP) -- and never reads
    `confidence`, which for the NER path is a token-classification score
    rather than a risk.
    """
    labels = [
        str(finding.get(k) or "").strip().lower()
        for k in ("entity_type", "concept", "entity", "subtype")
    ]
    labels = [v for v in labels if v]

    best = 0.0
    recognised = False
    for label in labels:
        if label in _EXFIL_WEIGHTS:
            best = max(best, _EXFIL_WEIGHTS[label])
            recognised = True
        elif label in _NON_EXFIL_ENTITIES:
            recognised = True

    if not recognised and labels:
        # A detector class this table has never seen scores zero -- but
        # silently scoring zero is how a real signal disappears. Say so once
        # per label so a new detector shows up in the logs instead of being
        # quietly ignored.
        unseen = [v for v in labels if v not in _EXFIL_UNKNOWN_LABELS_SEEN]
        if unseen:
            _EXFIL_UNKNOWN_LABELS_SEEN.update(unseen)
            logger.warning(
                "exfil_label_unmapped labels=%s -- this sensitive_data class "
                "contributes 0.0 to data_exfil because it is not in "
                "_EXFIL_WEIGHTS; add it there if it is an exfiltration signal",
                unseen,
            )
    return best


async def _score_with_detection(
    req: TrustGateRequest, signals: ExtractedSignals, session_id: str
) -> tuple[TrustGateScores, List[IOC]]:
    """Stream extracted content to the Detection Service and aggregate scores.

    The detection service already exposes /scan, /scan/prompt-injection,
    /scan/promptware, /scan/sensitive-data and /scan/output-safety. The
    gate fans out the relevant subset based on which signals were
    successfully extracted, then aggregates into the trust-gate score
    vector.
    """

    scores = TrustGateScores()
    iocs: List[IOC] = []

    # Cheap heuristics that don't need the detection service. These run
    # even if the detection service is unreachable so the gate can still
    # produce a usable verdict.
    if signals.has_credential_form:
        scores.credential_harvest = max(scores.credential_harvest, 0.6)
    if signals.has_brand_impersonation_keywords:
        scores.brand_impersonation = max(scores.brand_impersonation, 0.5)
    if signals.hidden_text_blocks:
        # Hidden text alone is not malicious — it's a SIGNAL to look
        # harder, not a verdict. Score modestly and let the ML layer
        # confirm.
        scores.prompt_injection = max(scores.prompt_injection, 0.4)
        scores.promptware = max(scores.promptware, 0.3)

    # Fan out to detection service for ML scoring of any extracted text.
    if signals.text_for_ml:
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.post(
                    f"{DETECTION_SERVICE_URL}/scan",
                    json={
                        "content": signals.text_for_ml,
                        # PER-EVALUATION, not per-tenant. This was
                        # f"url-trust-gate:{req.tenant_id}" -- ONE session id
                        # for every URL the gate ever checked. The detection
                        # service's promptware ATTACK-CHAIN detector fires once
                        # a session has >=2 events, so it correlated a benign
                        # article and a phishing page as steps of one attack and
                        # returned promptware=1.0 on everything after the second
                        # scan. Measured 2026-08-14: all five demo pages,
                        # including a tea-blends article, scored promptware=1.00
                        # -> redact. A one-shot URL check is not a conversation;
                        # each evaluation is its own session, so the chain only
                        # ever sees this evaluation's single event and cannot
                        # spuriously chain across unrelated URLs. Real single-page
                        # injection is still caught by the prompt_injection ML
                        # classifier, independently of chain correlation.
                        "session_id": f"url-trust-gate:{session_id}",
                        "context": {
                            "source": "url-trust-gate",
                            "consumer_source": req.source,
                        },
                    },
                    headers=build_auth_headers(DETECTION_SERVICE_URL, DETECTION_API_SECRET),
                )
                if resp.status_code == 200:
                    body = resp.json()
                    # Detection service returns the list of findings under
                    # "detections" (with "findings" kept as a back-compat
                    # alias on some endpoints). Read both so we don't miss
                    # signals if the schema shifts.
                    findings = body.get("detections") or body.get("findings") or []
                    for f in findings:
                        kind = f.get("type", "")
                        conf = float(f.get("confidence", 0.0))
                        if "prompt_injection" in kind:
                            scores.prompt_injection = max(scores.prompt_injection, conf)
                        if "promptware" in kind:
                            scores.promptware = max(scores.promptware, conf)
                        if "exfil" in kind or "dlp" in kind or "sensitive" in kind:
                            scores.data_exfil = max(scores.data_exfil, _exfil_score(f))
                        if "phishing" in kind or "credential" in kind:
                            scores.credential_harvest = max(
                                scores.credential_harvest, conf
                            )

                    # A scan with a dead detector in it is not a clean scan.
                    # The detection service already lifts this to the top
                    # level; the gate was ignoring it, so a URL checked while
                    # the PII or injection model was unloaded produced a
                    # verdict indistinguishable from one that ran every check.
                    degraded = body.get("detectors_unavailable") or []
                    if degraded:
                        logger.warning(
                            "detection_degraded request_id=%s unavailable=%s -- this "
                            "verdict was produced with %d detector(s) that did not run",
                            session_id,
                            [d.get("detector") for d in degraded],
                            len(degraded),
                        )
                else:
                    logger.warning(
                        "detection_non_200 status=%s body=%s",
                        resp.status_code,
                        resp.text[:200],
                    )
        except Exception as exc:
            # Fail-open on detection unreachable: the policy engine still
            # gets the heuristic scores. Mark the verdict as degraded so
            # downstream evidence shows it.
            logger.warning("detection_unreachable err=%s", exc)

    # IOCs from the extractors layer.
    iocs.extend(signals.iocs)

    # Composite risk: max-of across all signal dimensions. A tenant-tunable
    # weighted aggregation can be layered on top once per-tenant calibration
    # data accumulates in the evidence store.
    scores.overall_risk = max(
        scores.phishing,
        scores.malware,
        scores.prompt_injection,
        scores.promptware,
        scores.data_exfil,
        scores.credential_harvest,
        scores.brand_impersonation,
    )

    return scores, iocs


async def _decide_with_policy(
    *,
    req: TrustGateRequest,
    scores: TrustGateScores,
    iocs: List[IOC],
    canonical_url: str,
    crawled: bool,
    detonated: bool,
) -> TrustGateDecision:
    """Ask the policy service what to do given scores + context.

    Falls back to a built-in conservative ruleset if the policy service is
    unreachable, so the gate degrades gracefully rather than failing open.
    """

    payload = {
        "tenant_id": req.tenant_id,
        "scope": "url-trust-gate",
        "context": {
            "source": req.source,
            "user_id": req.user_id,
            "app_id": req.app_id,
            "agent_id": req.agent_id,
            "canonical_url": canonical_url,
            "scores": scores.model_dump(),
            "ioc_count": len(iocs),
            "crawled": crawled,
            "detonated": detonated,
            **(req.context or {}),
        },
    }

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.post(
                f"{POLICY_SERVICE_URL}/evaluate",
                json=payload,
                headers=build_auth_headers(POLICY_SERVICE_URL, POLICY_API_SECRET),
            )
            if resp.status_code == 200:
                data = resp.json()
                action = _normalise_action(data.get("decision", "monitor"))
                reason = data.get("reason", "policy decision")
                # If the policy service has no rule for url-trust-gate
                # (legacy /evaluate returns ALLOW + reason="no_policy_match"
                # in that case), don't blindly downgrade — defer to the
                # gate's own score-based fallback so a deployment without
                # any url-trust-gate policies still enforces the heuristic
                # + ML defaults rather than failing open.
                if action == "allow" and reason in {
                    "no_policy_match", "policy_allow", "no policy match"
                }:
                    fb = _fallback_decision(scores)
                    if fb.action != "allow":
                        return fb
                return TrustGateDecision(
                    action=action,
                    reason=reason,
                    matched_policy=data.get("matched_policy"),
                    redact_segments=data.get("redact_segments", []) or [],
                    isolation_url=data.get("isolation_url"),
                )
            logger.warning(
                "policy_non_200 status=%s body=%s",
                resp.status_code,
                resp.text[:200],
            )
    except Exception as exc:
        logger.warning("policy_unreachable err=%s", exc)

    return _fallback_decision(scores)


#: The policy service's DECISION vocabulary -- the `decision = "..."` values in
#: services/policy/main.py -- mapped onto this gate's action vocabulary.
#:
#: This map exists because the caller at :865 reads `data["decision"]`, which
#: is the decision vocabulary, while this function was written for the older
#: ACTION vocabulary {monitor, allow, warn, block}. Six of the seven decision
#: values matched neither branch and fell through to `return "warn"`. Only
#: ALLOW survived, and only because the two vocabularies happen to spell it
#: the same way.
#:
#: The consequence was a fail-open on a control that runs on every top-level
#: navigation (url_trust_gate.js) and on the proxy's Step 0
#: (transparent_proxy.py): a tenant policy saying DENY for a URL was delivered
#: to the browser as "warn", which is a session-storage note. QUARANTINE and
#: REQUIRE_APPROVAL the same. Found 2026-07-31 while tracing why the
#: match-everything ISO 27001 block template had not darkened every browser --
#: it had, and this silently downgraded it, so a real bug was masked by a
#: second bug rather than by anything working.
_POLICY_DECISION_TO_ACTION = {
    "DENY": "block",
    # The gate cannot run an approval interaction mid-navigation, so the safe
    # reading of "a human must approve this" is: not without one.
    "REQUIRE_APPROVAL": "block",
    # The gate runs on a top-level navigation with no way to hold the request
    # open while a person answers, so it cannot honour "ask the user" either.
    # Declared EXPLICITLY rather than left to the unknown-value default: that
    # default is "warn", which for this gate is a session-storage note, and
    # letting a stop-and-ask decision fall through to a note is precisely the
    # silent downgrade this table was rewritten on 2026-07-31 to end.
    "REQUIRE_USER_DECISION": "block",
    "QUARANTINE": "isolate",
    "ALLOW": "allow",
    "ALLOW_WITH_LIMITS": "allow",
    "ALLOW_WITH_AUDIT_ONLY": "allow",
    "ALLOW_WITH_REDACTION": "redact",
}


def _normalise_action(action: str) -> str:
    """Map policy-service vocabulary to gate vocabulary.

    Accepts BOTH shapes the policy service can send: the decision vocabulary
    (ALLOW / DENY / ALLOW_WITH_REDACTION / ...) from POST /evaluate, and the
    older action vocabulary {monitor, allow, warn, block} plus the gate's own
    {redact, sandbox, isolate}.

    An unrecognised value still becomes "warn", but it is now LOGGED. That
    default is only defensible for a value we genuinely do not know; it was
    never defensible for DENY, which is what this function was doing.
    """

    raw = (action or "").strip()

    mapped = _POLICY_DECISION_TO_ACTION.get(raw.upper())
    if mapped is not None:
        return mapped

    lowered = raw.lower()
    if lowered in {"allow", "warn", "block", "monitor"}:
        return "allow" if lowered == "monitor" else lowered
    if lowered in {"redact", "sandbox", "isolate"}:
        return lowered

    # Not a value either vocabulary defines. Say so: a verdict this gate had
    # to guess at must not be indistinguishable from one the tenant authored.
    logger.warning(
        "trust_gate_unknown_policy_verdict verdict=%r fallback=warn -- "
        "the policy service sent a value neither vocabulary defines; this "
        "navigation was NOT decided by tenant policy",
        raw,
    )
    return "warn"


def _fallback_decision(scores: TrustGateScores) -> TrustGateDecision:
    if scores.credential_harvest >= 0.7 or scores.phishing >= 0.7:
        return TrustGateDecision(action="block", reason="fallback: phishing/credential harvest")
    # MALWARE HAD NO BRANCH. scores.malware was set, populated by the
    # reputation feeds, and consulted by nothing -- so a confirmed Google Safe
    # Browsing malware hit at 0.95 confidence fell through to the generic
    # `overall_risk >= 0.5` line below and came out as a WARNING. Phishing
    # blocked only because it happened to have its own line.
    #
    # Measured 2026-08-01 against Google's own live test URLs:
    #   testsafebrowsing.appspot.com/s/phishing.html -> block
    #   testsafebrowsing.appspot.com/s/malware.html  -> warn
    #
    # Same threshold as phishing, deliberately: both are high-precision
    # verdicts from the same feed, and there is no argument for treating a
    # confirmed malware host more permissively than a confirmed phishing one.
    if scores.malware >= 0.7:
        return TrustGateDecision(action="block", reason="fallback: malware")
    if scores.promptware >= 0.7 or scores.prompt_injection >= 0.7:
        return TrustGateDecision(action="redact", reason="fallback: hidden instruction risk")
    if scores.overall_risk >= 0.5:
        return TrustGateDecision(action="warn", reason="fallback: moderate risk")
    return TrustGateDecision(action="allow", reason="fallback: below thresholds")


async def _dispatch_incident(
    req: TrustGateRequest,
    decision: TrustGateDecision,
    canonical_url: str,
    scores: TrustGateScores,
    iocs: List[IOC],
    evidence_id: Optional[str],
) -> None:
    """Best-effort POST to the response service for high-severity verdicts."""

    incident = {
        "tenant_id": req.tenant_id,
        "source": "url-trust-gate",
        "severity": "high" if scores.overall_risk >= 0.9 else "medium",
        "description": (
            f"URL Trust Gate {decision.action} for {canonical_url}: "
            f"{decision.reason}"
        ),
        "actions": [{"kind": decision.action, "target": canonical_url}],
        "evidence_id": evidence_id,
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(
                f"{RESPONSE_SERVICE_URL}/respond",
                json=incident,
                headers=build_auth_headers(RESPONSE_SERVICE_URL, RESPONSE_API_SECRET),
            )
    except Exception as exc:
        logger.warning("response_dispatch_failed err=%s", exc)
