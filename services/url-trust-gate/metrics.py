"""Prometheus metrics for the URL Trust Gate.

Self-contained exposition format so we don't pull in the
prometheus_client dependency (other services in this repo render
manually too). If we later standardise on prometheus_client this
module becomes a thin adapter.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Dict, Tuple


# Histogram buckets in milliseconds. Tuned to span fast-path (sub-10ms),
# standard (~hundreds of ms), and deep (multi-second) cases.
_LATENCY_BUCKETS_MS = (5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000)


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        # counters[(name, labels_tuple)] = float
        self._counters: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = (
            defaultdict(float)
        )
        # histograms[(name, labels)] = {"sum": float, "count": int, "buckets": [int]}
        self._histograms: Dict[
            Tuple[str, Tuple[Tuple[str, str], ...]], Dict[str, object]
        ] = {}

    # ------------------------------------------------------------------
    # Public API used by main.py
    # ------------------------------------------------------------------

    def observe_request(
        self,
        *,
        depth: str,
        decision: str,
        cache_hit: bool,
        crawled: bool,
        detonated: bool,
        elapsed_ms: int,
    ) -> None:
        labels = (("depth", depth), ("decision", decision))
        self._inc("url_trust_gate_requests_total", labels)
        if cache_hit:
            self._inc("url_trust_gate_cache_hits_total", (("depth", depth),))
        if crawled:
            self._inc("url_trust_gate_crawls_total", (("depth", depth),))
        if detonated:
            self._inc("url_trust_gate_detonations_total", (("depth", depth),))
        self._observe_histogram(
            "url_trust_gate_decision_latency_ms",
            (("depth", depth),),
            elapsed_ms,
        )

    def observe_feed_hit(self, feed: str) -> None:
        """Record a reputation-feed match (Safe Browsing, SmartScreen, VirusTotal)."""
        self._inc("url_trust_gate_feed_hits_total", (("feed", feed),))

    def observe_crawl_error(self, reason: str) -> None:
        """Record a safe-crawl failure (SSRF block, timeout, HTTP error, etc.)."""
        self._inc("url_trust_gate_crawl_errors_total", (("reason", reason),))

    def observe_detonation_timeout(self) -> None:
        """Record a detonation-sandbox timeout."""
        self._inc("url_trust_gate_detonation_timeouts_total", ())

    def observe_evidence_write_error(self) -> None:
        """Record a failed evidence write to the audit service."""
        self._inc("url_trust_gate_evidence_write_errors_total", ())

    def inc_error(self, error_type: str) -> None:
        """Generic error counter, labelled by type."""
        self._inc("url_trust_gate_errors_total", (("type", error_type),))

    def render(self) -> str:
        with self._lock:
            lines: list[str] = []
            seen_help: set[str] = set()
            for (name, labels), value in self._counters.items():
                if name not in seen_help:
                    lines.append(f"# HELP {name} {_HELP.get(name, name)}")
                    lines.append(f"# TYPE {name} counter")
                    seen_help.add(name)
                lines.append(f"{name}{_fmt_labels(labels)} {value}")

            for (name, labels), payload in self._histograms.items():
                if name not in seen_help:
                    lines.append(f"# HELP {name} {_HELP.get(name, name)}")
                    lines.append(f"# TYPE {name} histogram")
                    seen_help.add(name)
                buckets = payload["buckets"]  # type: ignore[index]
                cumulative = 0
                for bound, count in zip(_LATENCY_BUCKETS_MS, buckets):  # type: ignore[arg-type]
                    cumulative += count
                    bucket_labels = labels + (("le", str(bound)),)
                    lines.append(f"{name}_bucket{_fmt_labels(bucket_labels)} {cumulative}")
                cumulative += payload["overflow"]  # type: ignore[index]
                inf_labels = labels + (("le", "+Inf"),)
                lines.append(f"{name}_bucket{_fmt_labels(inf_labels)} {cumulative}")
                lines.append(f"{name}_sum{_fmt_labels(labels)} {payload['sum']}")
                lines.append(f"{name}_count{_fmt_labels(labels)} {payload['count']}")
            return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _inc(
        self, name: str, labels: Tuple[Tuple[str, str], ...], value: float = 1.0
    ) -> None:
        with self._lock:
            self._counters[(name, labels)] += value

    def _observe_histogram(
        self, name: str, labels: Tuple[Tuple[str, str], ...], value: float
    ) -> None:
        with self._lock:
            payload = self._histograms.get((name, labels))
            if payload is None:
                payload = {
                    "sum": 0.0,
                    "count": 0,
                    "buckets": [0] * len(_LATENCY_BUCKETS_MS),
                    "overflow": 0,
                }
                self._histograms[(name, labels)] = payload
            payload["sum"] = float(payload["sum"]) + value  # type: ignore[index]
            payload["count"] = int(payload["count"]) + 1  # type: ignore[index]
            placed = False
            for i, bound in enumerate(_LATENCY_BUCKETS_MS):
                if value <= bound:
                    payload["buckets"][i] += 1  # type: ignore[index]
                    placed = True
                    break
            if not placed:
                payload["overflow"] = int(payload["overflow"]) + 1  # type: ignore[index]


_HELP = {
    "url_trust_gate_requests_total": "Total /evaluate requests, labelled by depth and decision.",
    "url_trust_gate_cache_hits_total": "Reputation-cache hits, labelled by depth.",
    "url_trust_gate_crawls_total": "Safe-crawl attempts, labelled by depth.",
    "url_trust_gate_detonations_total": "Detonation-sandbox renders, labelled by depth.",
    "url_trust_gate_decision_latency_ms": "End-to-end /evaluate latency in milliseconds, labelled by depth. Use histogram_quantile(0.5|0.95|0.99, ...) for p50/p95/p99.",
    "url_trust_gate_feed_hits_total": "Reputation-feed matches, labelled by feed (safe_browsing, smartscreen, virustotal).",
    "url_trust_gate_crawl_errors_total": "Safe-crawl failures, labelled by reason (ssrf_blocked, timeout, http_error, size_exceeded).",
    "url_trust_gate_detonation_timeouts_total": "Detonation-sandbox timeouts (nav or total budget exceeded).",
    "url_trust_gate_evidence_write_errors_total": "Failed evidence writes to the audit service.",
    "url_trust_gate_errors_total": "Generic error counter, labelled by type.",
}


def _fmt_labels(labels: Tuple[Tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    parts = [f'{k}="{_escape(v)}"' for k, v in labels]
    return "{" + ",".join(parts) + "}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
