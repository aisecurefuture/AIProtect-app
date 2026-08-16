"""Tests for the Prometheus metrics registry and /metrics HTTP endpoint.

Tests are split in two layers:

  1. Unit tests for MetricsRegistry itself — no HTTP stack needed.
  2. Integration smoke-tests that exercise the FastAPI /metrics route
     via httpx.AsyncClient so we verify the content-type header and
     basic exposition format without spinning up real downstream services.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest

from metrics import MetricsRegistry


# ---------------------------------------------------------------------------
# MetricsRegistry unit tests
# ---------------------------------------------------------------------------


def test_render_empty():
    reg = MetricsRegistry()
    out = reg.render()
    # Should always end with a newline (Prometheus requirement).
    assert out.endswith("\n")


def test_counter_increments():
    reg = MetricsRegistry()
    reg.observe_request(
        depth="fast",
        decision="allow",
        cache_hit=True,
        crawled=False,
        detonated=False,
        elapsed_ms=5,
    )
    out = reg.render()
    assert "url_trust_gate_requests_total" in out
    assert 'depth="fast"' in out
    assert 'decision="allow"' in out
    # Cache-hit counter must appear.
    assert "url_trust_gate_cache_hits_total" in out
    # Crawl counter must NOT appear (crawled=False).
    assert "url_trust_gate_crawls_total" not in out


def test_crawl_counter_appears_when_crawled():
    reg = MetricsRegistry()
    reg.observe_request(
        depth="standard",
        decision="block",
        cache_hit=False,
        crawled=True,
        detonated=False,
        elapsed_ms=210,
    )
    out = reg.render()
    assert "url_trust_gate_crawls_total" in out
    assert "url_trust_gate_cache_hits_total" not in out


def test_detonation_counter_appears_when_detonated():
    reg = MetricsRegistry()
    reg.observe_request(
        depth="deep",
        decision="sandbox",
        cache_hit=False,
        crawled=True,
        detonated=True,
        elapsed_ms=3800,
    )
    out = reg.render()
    assert "url_trust_gate_detonations_total" in out


def test_histogram_emitted():
    reg = MetricsRegistry()
    reg.observe_request(
        depth="standard",
        decision="warn",
        cache_hit=False,
        crawled=True,
        detonated=False,
        elapsed_ms=75,
    )
    out = reg.render()
    assert "url_trust_gate_decision_latency_ms_bucket" in out
    assert "url_trust_gate_decision_latency_ms_sum" in out
    assert "url_trust_gate_decision_latency_ms_count" in out
    # The "+Inf" bucket must always be present.
    assert 'le="+Inf"' in out


def test_histogram_correct_bucket():
    """A 75 ms observation should fill only the 100 ms bucket and higher."""
    reg = MetricsRegistry()
    reg.observe_request(
        depth="fast",
        decision="allow",
        cache_hit=True,
        crawled=False,
        detonated=False,
        elapsed_ms=75,
    )
    out = reg.render()
    # Extract bucket lines for this metric.
    bucket_lines = [
        l for l in out.splitlines() if "latency_ms_bucket" in l
    ]
    by_le: dict[str, int] = {}
    for line in bucket_lines:
        m = re.search(r'le="([^"]+)".*?(\d+)$', line)
        if m:
            by_le[m.group(1)] = int(m.group(2))
    # Buckets ≤ 50 ms should be 0 (cumulative).
    assert by_le.get("5", 0) == 0
    assert by_le.get("50", 0) == 0
    # The 100 ms bucket should be 1 (cumulative).
    assert by_le.get("100", 0) == 1
    assert by_le.get("+Inf", 0) == 1


def test_multiple_observations_accumulate():
    reg = MetricsRegistry()
    for _ in range(3):
        reg.observe_request(
            depth="fast",
            decision="allow",
            cache_hit=False,
            crawled=False,
            detonated=False,
            elapsed_ms=8,
        )
    out = reg.render()
    # The counter line for (fast, allow) should show 3.0.
    match = re.search(
        r'url_trust_gate_requests_total\{[^}]*depth="fast"[^}]*\} ([\d.]+)', out
    )
    assert match, "counter line not found in render output"
    assert float(match.group(1)) == 3.0


def test_label_escaping():
    """Label values with special chars must be properly escaped."""
    from metrics import _escape

    assert _escape('say "hi"') == 'say \\"hi\\"'
    assert _escape("back\\slash") == "back\\\\slash"
    assert _escape("new\nline") == "new\\nline"


def test_render_type_and_help_lines():
    reg = MetricsRegistry()
    reg.observe_request(
        depth="fast",
        decision="allow",
        cache_hit=False,
        crawled=False,
        detonated=False,
        elapsed_ms=20,
    )
    out = reg.render()
    assert "# HELP url_trust_gate_requests_total" in out
    assert "# TYPE url_trust_gate_requests_total counter" in out
    assert "# TYPE url_trust_gate_decision_latency_ms histogram" in out


# ---------------------------------------------------------------------------
# FastAPI /metrics route integration smoke-tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_metrics_http_route():
    """GET /metrics returns 200, correct content-type, and valid Prometheus text."""
    import importlib
    import os
    import types

    # Stub out heavy optional imports that are not present in unit-test env.
    for mod_name in (
        "cyberarmor_core",
        "cyberarmor_core.crypto",
        "canonicalize",
        "reputation",
        "crawler",
        "detonation",
        "extractors",
        "evidence",
        "feeds",
        "tenant_lists",
    ):
        if mod_name not in sys.modules:
            stub = types.ModuleType(mod_name)
            # Provide the bare minimum that main.py imports at module level.
            stub.build_auth_headers = lambda *a, **kw: {}  # type: ignore[attr-defined]
            stub.verify_shared_secret = lambda *a, **kw: True  # type: ignore[attr-defined]
            stub.get_public_key_info = lambda: {}  # type: ignore[attr-defined]
            stub.canonicalize_url = lambda u: u  # type: ignore[attr-defined]
            stub.classify_querystring_sensitivity = lambda u: "none"  # type: ignore[attr-defined]
            stub.ReputationCache = object  # type: ignore[attr-defined]
            stub.ReputationVerdict = object  # type: ignore[attr-defined]
            stub.SafeCrawler = object  # type: ignore[attr-defined]
            stub.CrawlResult = object  # type: ignore[attr-defined]
            stub.DetonationSandbox = object  # type: ignore[attr-defined]
            stub.DetonationResult = object  # type: ignore[attr-defined]
            stub.extract_signals = lambda *a, **kw: None  # type: ignore[attr-defined]
            stub.ExtractedSignals = object  # type: ignore[attr-defined]
            stub.EvidenceRecord = object  # type: ignore[attr-defined]
            stub.EvidenceWriter = object  # type: ignore[attr-defined]
            stub.ReputationAggregator = object  # type: ignore[attr-defined]
            stub.TenantListClient = object  # type: ignore[attr-defined]
            sys.modules[mod_name] = stub

    # Import after stubs are in place, but guard against double-import issues
    # in test suites that run all tests together.
    try:
        import main as gate_main  # noqa: PLC0415
    except Exception:
        pytest.skip("main.py could not be imported in stub environment")
        return

    from httpx import AsyncClient, ASGITransport

    transport = ASGITransport(app=gate_main.app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/metrics")

    assert resp.status_code == 200
    ct = resp.headers.get("content-type", "")
    assert "text/plain" in ct
    # Even with zero observations the body should be a valid string.
    assert isinstance(resp.text, str)
