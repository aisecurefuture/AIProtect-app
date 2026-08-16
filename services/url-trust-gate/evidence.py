"""Evidence writer.

Each gate decision produces an evidence record that goes to the audit
service. Evidence is the proof layer: what the gate saw, why it decided,
and the full signal vector. The schema here is the contract — keep
additions backward-compatible.

Reliability model
-----------------
Evidence writes are synchronous with the gate response — every decision
that reaches the caller has already attempted to persist its record.
Transient audit-service failures are retried up to ``max_retries`` times
with exponential back-off (default: 3 attempts, initial delay 0.25 s,
capped at 2 s). On final failure the full payload is emitted as a
structured WARNING log at level ``evidence_write_dead_letter`` so that
any log-aggregation pipeline (Splunk, CloudWatch, Elastic, etc.) can
ingest and reconcile it independently of the audit service.

The gate decision is never blocked or delayed by evidence write failures
— if all retries are exhausted the gate still returns its verdict and the
caller sees ``evidence_id=None``. Callers increment the
``evidence_write_errors_total`` Prometheus counter on ``None`` so the
gap is visible in dashboards.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from cyberarmor_core.crypto import build_auth_headers

logger = logging.getLogger("url_trust_gate.evidence")

# Retry defaults — operators can override via EvidenceWriter constructor.
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BACKOFF_BASE_S = 0.25   # 0.25 s, 0.5 s, 1.0 s (capped at 2 s)
_DEFAULT_BACKOFF_CAP_S = 2.0


@dataclass
class EvidenceRecord:
    request_id: str
    tenant_id: str
    source: str
    user_id: Optional[str]
    app_id: Optional[str]
    agent_id: Optional[str]
    canonical_url: str  # already redacted by the gate
    url_fingerprint: str
    redirect_chain: List[str]
    content_hash: Optional[str]
    screenshot_hash: Optional[str]
    scores: Dict[str, Any]
    iocs: List[Dict[str, Any]]
    decision: Dict[str, Any]
    crawled: bool
    detonated: bool
    recorded_at: str


#: The taxonomy already classified this event type long before anything
#: successfully emitted one -- libs/cyberarmor-core/cyberarmor_core/
#: event_taxonomy.py:206, category "security", subject "malicious_url".
_EVENT_TYPE = "url_trust_gate_verdict"

#: Sent when the record carries no agent. agent_id is REQUIRED by AuditEvent
#: (services/audit/main.py) and EvidenceRecord.agent_id is Optional, so a
#: fallback is mandatory or the write 422s on the records that matter most --
#: a URL fetched by something we could not attribute.
_UNATTRIBUTED_AGENT = "url-trust-gate"


def _as_audit_event(evidence_id: str, record: EvidenceRecord, payload: dict) -> dict:
    """Map an EvidenceRecord onto the audit service's AuditEvent schema.

    WHY THIS FUNCTION EXISTS. This writer previously POSTed
    ``{"kind": "url-trust-gate", "data": {...}}``. AuditEvent requires
    ``trace_id``, ``agent_id`` and ``event_type``, none of which have defaults,
    so EVERY WRITE SINCE THE CODE WAS WRITTEN returned 422. The handler treats
    4xx as unretryable, logs a warning and returns None, and the gate still
    answers 200 with ``evidence_id: null`` -- so the URL Trust Gate has always
    reported success while storing nothing. Production audit_events held zero
    rows on 2026-08-12 and this was one of the three reasons.

    WHY THE OBVIOUS FIX WOULD HAVE BEEN WORSE. Adding only the three required
    fields makes the POST succeed -- and pydantic's default ``extra='ignore'``
    then DISCARDS ``kind`` and ``data`` without a word, so the canonical URL,
    the scores, the IOCs, the decision and the redirect chain would all be
    dropped behind a 201. Measured, not assumed. The evidence therefore travels
    in ``detail``, a declared field, which means it is also covered by the
    record's signature.
    """
    decision = record.decision if isinstance(record.decision, dict) else {}
    verdict = str(decision.get("action") or decision.get("decision") or "unknown")

    return {
        # request_id is the gate's correlation id for one evaluation, which is
        # exactly what a trace id is for. Falling back to evidence_id keeps the
        # field populated rather than inventing an empty string, which would
        # pass validation and correlate nothing.
        "trace_id": record.request_id or evidence_id,
        "tenant_id": record.tenant_id,
        "agent_id": record.agent_id or _UNATTRIBUTED_AGENT,
        "human_initiator_id": record.user_id,
        "outcome": verdict,
        "policy_decision": {
            "decision": verdict,
            "reason_code": str(decision.get("reason") or decision.get("reason_code") or ""),
            "risk_score": float(decision.get("risk_score") or decision.get("score") or 0.0),
        },
        "action": {
            "type": "url_evaluation",
            "target_system": record.canonical_url,
            "tool_input_hash": record.url_fingerprint,
            "prompt_hash": record.content_hash,
        },
        # Everything the declared fields cannot carry. Whole, so nothing is lost
        # and nothing has to be guessed at later: evidence_id, app_id, source,
        # redirect_chain, scores, iocs, screenshot_hash, crawled, detonated,
        # recorded_at.
        "detail": payload,
        # LAST, deliberately. The taxonomy coverage guard
        # (libs/cyberarmor-core/tests/test_event_taxonomy_covers_what_is_emitted.py)
        # greps event_type lines with two lines of trailing context, so whatever
        # follows this key is read as an emitted event type. With event_type
        # above, "policy_decision" was reported as an unclassified event —
        # a regression this commit's author introduced and did not notice,
        # because that test was already red for unrelated reasons. A red test
        # hides the next one.
        "event_type": _EVENT_TYPE,
    }


class EvidenceWriter:
    def __init__(
        self,
        audit_url: str,
        audit_secret: str,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        backoff_base_s: float = _DEFAULT_BACKOFF_BASE_S,
        backoff_cap_s: float = _DEFAULT_BACKOFF_CAP_S,
    ):
        self._audit_url = audit_url
        self._audit_secret = audit_secret
        self._max_retries = max_retries
        self._backoff_base_s = backoff_base_s
        self._backoff_cap_s = backoff_cap_s

    async def write(self, record: EvidenceRecord) -> Optional[str]:
        """Persist an evidence record to the audit service.

        Retries up to ``max_retries`` times with exponential back-off on
        transient failures (network errors and 5xx responses). Returns the
        ``evidence_id`` string on success, or ``None`` if all attempts fail.
        On final failure, emits a dead-letter log entry containing the full
        serialised payload so it can be recovered from log aggregation.
        """
        evidence_id = uuid.uuid4().hex
        payload = {"evidence_id": evidence_id, **asdict(record)}
        body = _as_audit_event(evidence_id, record, payload)
        headers = build_auth_headers(self._audit_url, self._audit_secret)

        last_exc: Optional[Exception] = None

        for attempt in range(1, self._max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=2.0) as client:
                    resp = await client.post(
                        f"{self._audit_url}/events",
                        json=body,
                        headers=headers,
                    )

                if resp.status_code < 400:
                    # Success — log only on retry so the happy path is quiet.
                    if attempt > 1:
                        logger.info(
                            "evidence_write_recovered attempt=%s evidence_id=%s",
                            attempt, evidence_id,
                        )
                    return evidence_id

                if resp.status_code < 500:
                    # 4xx — client error, retrying won't help.
                    logger.warning(
                        "evidence_write_client_error status=%s body=%s evidence_id=%s",
                        resp.status_code, resp.text[:200], evidence_id,
                    )
                    break

                # 5xx — transient server error, retry.
                logger.warning(
                    "evidence_write_server_error status=%s attempt=%s/%s evidence_id=%s",
                    resp.status_code, attempt, self._max_retries, evidence_id,
                )
                last_exc = RuntimeError(f"audit service {resp.status_code}")

            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "evidence_write_attempt_failed err=%s attempt=%s/%s evidence_id=%s",
                    exc, attempt, self._max_retries, evidence_id,
                )

            if attempt < self._max_retries:
                delay = min(
                    self._backoff_base_s * (2 ** (attempt - 1)),
                    self._backoff_cap_s,
                )
                await asyncio.sleep(delay)

        # All attempts exhausted — emit a dead-letter record so log
        # aggregation (Splunk, CloudWatch, Elastic, etc.) can recover it.
        # Callers must increment the evidence_write_errors_total counter.
        logger.warning(
            "evidence_write_dead_letter evidence_id=%s last_err=%s payload=%s",
            evidence_id,
            last_exc,
            json.dumps(payload, default=str),
        )
        return None
