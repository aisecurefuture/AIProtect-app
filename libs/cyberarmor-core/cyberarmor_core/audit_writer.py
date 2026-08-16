"""Store-and-forward audit writer for the enforcement point.

WHY THIS EXISTS. On 2026-08-12 production ``audit_events`` held ZERO rows, ever,
for every tenant. The MITM proxy -- the component that sees essentially all AI
traffic and makes every enforcement decision -- contained no audit code at all:
no ``AUDIT_SERVICE_URL``, no ``/events``, no reference to port 8011. Its outbound
posts went to ``/telemetry/ingest``. A live demo ran end to end and the audit
trail recorded nothing, while the product was sold on that trail.

THREE CONSTRAINTS SHAPE THIS DESIGN, and each one rules out the obvious version.

1. IT MUST NOT BLOCK TRAFFIC. This runs inside mitmproxy's request path. A
   synchronous POST per request puts the audit service's latency, and its
   outages, directly into the customer's browsing. ``enqueue()`` therefore only
   appends to an in-memory deque and returns; a background task does the rest.

2. IT MUST NOT WRITE ONE EVENT PER REQUEST. ``uq_audit_chain_link`` serialises
   appends per tenant -- that is what stops the chain forking -- so per-tenant
   throughput has a real ceiling (docs/specs/pilot-capacity-model.md:349 puts it
   at 100-150 appends/s). This pilot is ONE tenant with 800 seats. Per-request
   writes would make that ceiling the enforcement point's ceiling. Events are
   batched to ``POST /events/batch``.

3. IT MUST NOT LOSE EVENTS WHEN AUDIT IS DOWN. An audit trail with a
   best-effort writer is a trail with holes exactly when something interesting
   was happening -- and an outage is highly correlated with the events you most
   want. So a failed flush SPOOLS to disk on a durable volume and is drained
   when the service returns.

WHAT IS DELIBERATELY NOT DONE. There is no silent drop anywhere. When the spool
hits its ceiling this refuses further events and counts them, loudly, rather
than discarding the oldest to make room: an audit trail that quietly forgets is
the defect this whole subsystem keeps being audited for. The counters are
exposed so "we lost N events" is always answerable with a number.

IDEMPOTENCE. Every event is assigned its ``event_id`` at ENQUEUE time, not by
the audit service. A retried batch therefore carries the same ids and the audit
service rejects the duplicates it already stored, so a partially-applied batch
converges instead of double-writing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger("cyberarmor.proxy.audit")

#: Where spooled events live when the audit service is unreachable. A named
#: docker volume, not a bind mount and not /tmp: it must survive a container
#: restart, which is the most common reason a flush fails in the first place.
AUDIT_SPOOL_DIR = os.getenv("CYBERARMOR_AUDIT_SPOOL_DIR", "/var/lib/cyberarmor/audit-spool")

#: Flush when either threshold trips. Size keeps a busy tenant's batches
#: reasonable; the interval bounds how long an event sits in memory -- which is
#: the window a crash would lose, since RAM is not durable.
AUDIT_BATCH_MAX_EVENTS = int(os.getenv("CYBERARMOR_AUDIT_BATCH_MAX_EVENTS", "200"))
AUDIT_FLUSH_INTERVAL_S = float(os.getenv("CYBERARMOR_AUDIT_FLUSH_INTERVAL_S", "2.0"))

#: In-memory ceiling. Beyond this, events go straight to the spool rather than
#: growing the heap without bound -- this process is a proxy, and OOM here is an
#: outage for all traffic, not just for auditing.
AUDIT_MEMORY_MAX_EVENTS = int(os.getenv("CYBERARMOR_AUDIT_MEMORY_MAX_EVENTS", "5000"))

#: Disk ceiling for the spool. Reaching it means refusing events and counting
#: them, never overwriting older ones.
AUDIT_SPOOL_MAX_BYTES = int(os.getenv("CYBERARMOR_AUDIT_SPOOL_MAX_BYTES", str(512 * 1024 * 1024)))

AUDIT_SERVICE_URL = os.getenv("AUDIT_SERVICE_URL", "http://audit:8011")
AUDIT_API_SECRET = os.getenv("AUDIT_API_SECRET", "")


@dataclass
class AuditWriterStats:
    """Every number an operator needs to answer 'did we lose anything?'."""
    enqueued: int = 0
    sent: int = 0
    spooled: int = 0
    drained: int = 0
    refused_spool_full: int = 0
    refused_no_spool: int = 0
    flush_failures: int = 0
    spool_bytes: int = 0
    corrupt_lines_skipped: int = 0

    def as_dict(self) -> Dict[str, Any]:
        d = {k: getattr(self, k) for k in self.__dataclass_fields__}
        # The single number that decides whether this trail is complete.
        d["lost"] = self.refused_spool_full + self.refused_no_spool
        d["healthy"] = d["lost"] == 0
        return d


class AuditWriter:
    def __init__(
        self,
        service_url: str = AUDIT_SERVICE_URL,
        api_secret: str = AUDIT_API_SECRET,
        spool_dir: str = AUDIT_SPOOL_DIR,
        batch_max: int = AUDIT_BATCH_MAX_EVENTS,
        memory_max: int = AUDIT_MEMORY_MAX_EVENTS,
        spool_max_bytes: int = AUDIT_SPOOL_MAX_BYTES,
    ):
        self._url = service_url.rstrip("/")
        self._secret = api_secret
        self._spool_dir = Path(spool_dir)
        self._batch_max = batch_max
        self._memory_max = memory_max
        self._spool_max_bytes = spool_max_bytes
        self._buffer: Deque[Dict[str, Any]] = deque()
        self._stats = AuditWriterStats()
        self._spool_ready = self._prepare_spool()
        self._task: Optional[asyncio.Task] = None
        self._stopping = False

    # -- spool ---------------------------------------------------------------

    def _prepare_spool(self) -> bool:
        """Create the spool directory, and PROVE it is writable.

        Not `exists()`. A directory can exist and be unwritable -- which is
        exactly what happens when a fresh named volume is mounted at a path the
        image never created, because Docker then creates it root-owned and this
        process runs as appuser. That failure mode produced a silently
        unsigned audit trail once already; here it would produce a silently
        lossy one, so it is detected at construction and reported.
        """
        try:
            self._spool_dir.mkdir(parents=True, exist_ok=True)
            probe = self._spool_dir / ".write-probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return True
        except Exception as exc:
            logger.error(
                "audit_spool_unusable dir=%s err=%s -- audit events CANNOT be "
                "preserved across an audit-service outage and will be counted "
                "as lost", self._spool_dir, exc,
            )
            return False

    def _spool_size(self) -> int:
        try:
            return sum(f.stat().st_size for f in self._spool_dir.glob("*.jsonl"))
        except Exception:
            return 0

    def _spool(self, events: List[Dict[str, Any]]) -> None:
        if not events:
            return
        if not self._spool_ready:
            self._stats.refused_no_spool += len(events)
            logger.error(
                "audit_events_lost count=%s reason=spool_unusable total_lost=%s",
                len(events), self._stats.as_dict()["lost"],
            )
            return

        # Serialise FIRST, so the ceiling is checked against what the spool
        # would become, not against what it already is. Checking only the
        # current size lets the first write through however small the ceiling,
        # and lets one large batch overshoot it by the size of that batch --
        # which on a busy proxy is exactly when the disk is under pressure.
        payload = "".join(json.dumps(ev, default=str) + "\n" for ev in events)
        incoming = len(payload.encode("utf-8"))
        size = self._spool_size()
        self._stats.spool_bytes = size
        if size + incoming > self._spool_max_bytes:
            # REFUSE, do not evict. Discarding the oldest spooled events to
            # make room would mean the trail quietly forgets its earliest
            # record of an incident -- and an operator would see a healthy
            # writer. Refusing is visible.
            self._stats.refused_spool_full += len(events)
            logger.error(
                "audit_events_lost count=%s reason=spool_full bytes=%s "
                "incoming=%s max=%s total_lost=%s -- FREE SPACE OR RESTORE THE "
                "AUDIT SERVICE",
                len(events), size, incoming, self._spool_max_bytes,
                self._stats.as_dict()["lost"],
            )
            return

        # Write to a temp file and rename: an interrupted write must not leave
        # a half-line that the drain then has to guess about.
        path = self._spool_dir / f"spool-{time.time_ns()}-{uuid.uuid4().hex[:8]}.jsonl"
        try:
            fd, tmp = tempfile.mkstemp(dir=str(self._spool_dir), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
            self._stats.spooled += len(events)
            logger.warning(
                "audit_events_spooled count=%s file=%s -- the audit service is "
                "unreachable; these are preserved and will be drained",
                len(events), path.name,
            )
        except Exception as exc:
            self._stats.refused_no_spool += len(events)
            logger.error(
                "audit_events_lost count=%s reason=spool_write_failed err=%s",
                len(events), exc,
            )

    def _read_spool_file(self, path: Path) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    # Counted, never ignored: a corrupt line is a lost event
                    # and the operator is entitled to know how many.
                    self._stats.corrupt_lines_skipped += 1
                    logger.error(
                        "audit_spool_corrupt_line file=%s total=%s",
                        path.name, self._stats.corrupt_lines_skipped,
                    )
        except Exception as exc:
            logger.error("audit_spool_read_failed file=%s err=%s", path.name, exc)
        return events

    # -- public --------------------------------------------------------------

    def enqueue(self, event: Dict[str, Any]) -> None:
        """Non-blocking. Never raises into the request path."""
        try:
            event.setdefault("event_id", "evt_" + uuid.uuid4().hex[:20])
            self._stats.enqueued += 1
            self._buffer.append(event)
            if len(self._buffer) >= self._memory_max:
                # Backpressure to DISK, not to the caller and not to /dev/null.
                overflow = [self._buffer.popleft() for _ in range(len(self._buffer) // 2)]
                self._spool(overflow)
        except Exception as exc:      # pragma: no cover - must never propagate
            logger.error("audit_enqueue_failed err=%s", exc)

    def stats(self) -> Dict[str, Any]:
        s = self._stats.as_dict()
        s["buffered"] = len(self._buffer)
        s["spool_files"] = len(list(self._spool_dir.glob("*.jsonl"))) if self._spool_ready else 0
        s["spool_ready"] = self._spool_ready
        return s

    async def flush_once(self, client) -> bool:
        """Send one batch. Returns True if anything was successfully sent."""
        if not self._buffer:
            return False
        batch = [self._buffer.popleft() for _ in range(min(self._batch_max, len(self._buffer)))]
        ok = await self._send(client, batch)
        if not ok:
            self._spool(batch)
        return ok

    async def drain_spool(self, client, max_files: int = 20) -> int:
        """Re-send spooled events. Only unlinks a file once audit accepted it."""
        if not self._spool_ready:
            return 0
        drained = 0
        for path in sorted(self._spool_dir.glob("*.jsonl"))[:max_files]:
            events = self._read_spool_file(path)
            if not events:
                path.unlink(missing_ok=True)
                continue
            if await self._send(client, events):
                path.unlink(missing_ok=True)
                drained += len(events)
                self._stats.drained += len(events)
                logger.info(
                    "audit_spool_drained count=%s file=%s", len(events), path.name)
            else:
                # Leave it. A file removed on a failed send is an event lost
                # forever, and the whole point of the spool is that this cannot
                # happen.
                break
        return drained

    async def _send(self, client, events: List[Dict[str, Any]]) -> bool:
        try:
            resp = await client.post(
                f"{self._url}/events/batch",
                json={"events": events},
                headers={"x-api-key": self._secret, "Content-Type": "application/json"},
            )
        except Exception as exc:
            self._stats.flush_failures += 1
            logger.warning("audit_flush_failed err=%s count=%s", exc, len(events))
            return False

        if resp.status_code >= 400:
            # The status is READ. url-trust-gate discarded this response for
            # the life of the codebase and every write 422'd unnoticed.
            self._stats.flush_failures += 1
            logger.warning(
                "audit_flush_rejected status=%s body=%s count=%s",
                resp.status_code, str(resp.text)[:200], len(events),
            )
            return False

        # A 2xx may still report per-event failures. Duplicates are already
        # stored, so they are not loss; anything else is reported.
        try:
            body = resp.json()
            failed = body.get("failed") or []
            if failed:
                logger.warning(
                    "audit_flush_partial stored=%s failed=%s",
                    body.get("stored"), failed[:5],
                )
        except Exception:
            pass
        self._stats.sent += len(events)
        return True

    async def run_forever(self, client) -> None:
        """Background loop. Drains the spool first: events already on disk are
        older than anything in memory, and an audit trail should come back in
        order where it can."""
        while not self._stopping:
            try:
                await self.drain_spool(client)
                await self.flush_once(client)
            except Exception as exc:   # pragma: no cover
                logger.error("audit_writer_loop_error err=%s", exc)
            await asyncio.sleep(AUDIT_FLUSH_INTERVAL_S)

    def stop(self) -> None:
        self._stopping = True

    async def shutdown(self, client) -> None:
        """Best effort on the way down: try to send, spool whatever is left.

        Whatever is still in memory when the process dies is genuinely lost, so
        the flush interval is the real bound on that window.
        """
        self.stop()
        try:
            await self.flush_once(client)
        except Exception:
            pass
        if self._buffer:
            self._spool([self._buffer.popleft() for _ in range(len(self._buffer))])
