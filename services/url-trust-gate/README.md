# URL / Context Trust Gate

Pre-ingestion control point for URLs and external content destined for humans, browsers, endpoint agents, RASP-instrumented apps, and AI agents.

> Status: **scaffold**. The fast paths (canonicalisation, reputation cache, policy/detection plumbing, evidence writer interface) are wired end-to-end. The crawler has SSRF guards but needs an isolated egress namespace in production. The detonation sandbox, external reputation feeds, and tenant allow/block lookups are stubbed with TODOs.

## What it does

Before a consumer follows a URL or ingests external content, the gate:

1. Canonicalises the URL and classifies querystring sensitivity (so we never log secrets).
2. Looks up reputation (in-process TTL cache; pluggable external feeds — Safe Browsing / SmartScreen / VirusTotal).
3. Optionally runs a low-footprint safe crawler (no user creds, SSRF-blocked egress, size/time-limited, redirect chain re-validated each hop).
4. Optionally runs a detonation sandbox (deep mode) to catch JS-rendered DOM, CSS-hidden text, and Unicode-tag/zero-width promptware.
5. Streams extracted text to the Detection Service for phishing / prompt-injection / promptware / DLP scoring.
6. Calls the Policy Service for the final action (allow / warn / redact / sandbox / block / isolate).
7. Persists an evidence record (URL fingerprint, redirect chain, IOCs, decision lineage) for proof and ML training.
8. Optionally dispatches incidents to the Response Service for high-severity verdicts.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/evaluate` | Main entry point. Returns a `TrustGateResponse` with the action. |
| `POST` | `/feedback` | SOC analyst FP/FN feedback. Feeds the training-data flywheel. |
| `GET` | `/health` | Liveness. |
| `GET` | `/ready` | Readiness (TODO: probe detection / policy / audit). |
| `GET` | `/metrics` | Prometheus exposition (TODO). |
| `GET` | `/pki/public-key` | Standard service identity. |

Auth: `x-api-key: $URL_TRUST_GATE_API_SECRET`.

## Latency budgets

- `depth=fast` — cache + canonicalisation only. Target ~10ms. Browser extension click interception lives here; if the cache misses, fall back to `standard` async and let the user proceed with a warning.
- `depth=standard` — adds safe crawl. Target <500ms. Default for endpoint agents and RASP outbound HTTP.
- `depth=deep` — adds detonation sandbox render. Best-effort, can run several seconds. Used for unknown / suspicious URLs and for forensic recheck via `/feedback`.

## Why this scaffold leans heavy on TODOs

The traps from the architecture design are real:

- **SSRF / egress safety.** `crawler.py` does Python-level address checks but the real boundary is the network namespace. Production deployment MUST land the crawler in a container with no route to internal services or cloud metadata.
- **Side effects.** GET-only by default. POST + cookies + Authorization are explicitly disallowed. Detonation mode can opt into form interaction but must run in throwaway profiles.
- **Privacy.** Querystring values are classified by key name and redacted before leaving the request handler. Raw URLs with sensitive values never reach evidence or logs.
- **Latency.** Reputation cache is in-process for the scaffold; production should use Redis or write through to the audit store. Cache invalidation is keyed on URL fingerprint (host + path + sorted non-sensitive QS keys), so identical URLs with rotating tokens collapse to one entry.
- **Dynamic content.** The safe crawler will miss SPAs and CSS-hidden text. Detonation closes that gap; until it lands, deep-mode requests degrade to standard-mode behaviour.
- **False positives.** Hidden text alone is a SIGNAL, not a verdict. The gate scores it modestly and lets the ML detection layer confirm.

## Wiring into the rest of CyberArmor

| Consumer | Where to call from |
| --- | --- |
| Browser extension (Chromium / Firefox / Safari) | `webNavigation.onBeforeNavigate` → `POST /evaluate?depth=fast` (see `extensions/chromium-shared/url_trust_gate.js`). |
| Endpoint agent | Outbound DNS/HTTP hook → `POST /evaluate?depth=standard`. |
| Proxy / RASP | Pre-request interceptor (see `rasp/python/cyberarmor_rasp/url_trust_gate.py`). |
| AI router | Before tool-call URL retrieval → `POST /evaluate?depth=deep`. |
| Email / Office extensions | Link rewrite / hover preview → `POST /evaluate?depth=standard`. |

## Files

- `main.py` — FastAPI app and request orchestration.
- `canonicalize.py` — URL normalisation + querystring sensitivity.
- `reputation.py` — TTL cache for verdicts. External feed adapters live here.
- `crawler.py` — Safe HTTP fetcher with SSRF guards and size/time/redirect caps.
- `detonation.py` — Headless-browser sandbox interface. Currently stub.
- `extractors.py` — Deterministic signal extraction from crawl + detonation artefacts.
- `evidence.py` — Audit-service writer. Schema is the contract; keep additive.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `URL_TRUST_GATE_API_SECRET` | `change-me-url-trust-gate` | Inbound API key. |
| `DETECTION_SERVICE_URL` | `http://detection:8002` | Detection service base URL. |
| `POLICY_SERVICE_URL` | `http://policy:8001` | Policy service base URL. |
| `RESPONSE_SERVICE_URL` | `http://response:8003` | Response service base URL. |
| `AUDIT_SERVICE_URL` | `http://audit:8011` | Audit graph service base URL. |
| `URL_TRUST_GATE_CRAWLER_TIMEOUT_S` | `4.0` | Per-request crawler timeout. |
| `URL_TRUST_GATE_CRAWLER_MAX_BYTES` | `1048576` | Hard cap on fetched body size. |
| `URL_TRUST_GATE_CRAWLER_MAX_REDIRECTS` | `5` | Each hop re-validated against SSRF rules. |
| `URL_TRUST_GATE_DETONATION_DEFAULT` | `off` | Set to `on` to run detonation by default for `depth=deep`. |

### Detonation worker

Detonation runs in a separate service, [`services/detonation-worker/`](../detonation-worker/), built on Microsoft's official Playwright Python image. The gate is a thin HTTP client (see [`detonation.py`](detonation.py)). The compose stack puts the worker on a dedicated `detonation` network with no route to internal services. Configure with:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DETONATION_WORKER_URL` | (empty) | Base URL of the worker (e.g. `http://detonation-worker:8015`). If unset, deep-mode requests downgrade cleanly to standard. |
| `DETONATION_WORKER_API_SECRET` | `change-me-detonation-worker` | Shared secret with the worker. |
| `DETONATION_WORKER_TIMEOUT_S` | `15.0` | Per-render timeout the gate enforces on its HTTP call. |
| `URL_TRUST_GATE_CACHE_TTL_S` | `900` | Reputation cache TTL. |
