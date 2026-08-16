"""Tests for external reputation feed adapters.

All tests are fully offline — every httpx request is intercepted by a
mock transport so no real API calls are made.  Tests cover:

  - SmartScreenFeed: token fetch, URL indicator lookup, cache, auth
    errors, network failures.
  - VirusTotalFeed: lookup, TTL cache hit, 404 clean verdict, network
    failure, confidence calculation.
  - ReputationAggregator: from_env() wiring and score-merge logic.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from feeds import (
    AggregatedReputation,
    FeedVerdict,
    ReputationAggregator,
    SafeBrowsingFeed,
    SmartScreenFeed,
    VirusTotalFeed,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _async_response(status: int, body: Any) -> AsyncMock:
    """Return an async context-manager mock that yields a response-like object."""
    resp = MagicMock()
    resp.status_code = status
    resp.text = json.dumps(body) if isinstance(body, (dict, list)) else str(body)
    resp.json.return_value = body if isinstance(body, (dict, list)) else {}

    client_mock = AsyncMock()
    client_mock.__aenter__.return_value = client_mock
    client_mock.__aexit__.return_value = False
    client_mock.get.return_value = resp
    client_mock.post.return_value = resp
    return client_mock


# ---------------------------------------------------------------------------
# SmartScreenFeed
# ---------------------------------------------------------------------------


class TestSmartScreenFeed:
    def test_not_configured_when_env_missing(self, monkeypatch):
        monkeypatch.delenv("SMARTSCREEN_TENANT_ID", raising=False)
        monkeypatch.delenv("SMARTSCREEN_CLIENT_ID", raising=False)
        monkeypatch.delenv("SMARTSCREEN_CLIENT_SECRET", raising=False)
        feed = SmartScreenFeed()
        assert not feed.configured

    def test_configured_when_all_env_set(self, monkeypatch):
        monkeypatch.setenv("SMARTSCREEN_TENANT_ID", "tid")
        monkeypatch.setenv("SMARTSCREEN_CLIENT_ID", "cid")
        monkeypatch.setenv("SMARTSCREEN_CLIENT_SECRET", "secret")
        feed = SmartScreenFeed()
        assert feed.configured

    @pytest.mark.anyio
    async def test_lookup_returns_empty_verdict_when_not_configured(self):
        feed = SmartScreenFeed(tenant_id="", client_id="", client_secret="")
        result = await feed.lookup("https://evil.example.com/")
        assert isinstance(result, FeedVerdict)
        assert not result.matched

    @pytest.mark.anyio
    async def test_lookup_malicious_indicator(self):
        feed = SmartScreenFeed(tenant_id="t", client_id="c", client_secret="s")

        token_resp = {"access_token": "fake-token", "expires_in": 3600}
        indicator_resp = {
            "value": [
                {
                    "threatType": "malware",
                    "confidence": 80,
                    "isActive": True,
                    "networkDestinationUrl": "https://evil.example.com/",
                }
            ]
        }

        with patch("feeds.httpx.AsyncClient") as mock_cls:
            # First call: token endpoint; second call: indicator lookup.
            post_client = _async_response(200, token_resp)
            get_client = _async_response(200, indicator_resp)

            call_count = 0

            def side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return post_client
                return get_client

            mock_cls.side_effect = side_effect
            result = await feed.lookup("https://evil.example.com/")

        assert result.matched
        assert result.confidence == pytest.approx(0.80)
        assert "malware" in result.threat_types

    @pytest.mark.anyio
    async def test_token_cached_on_second_call(self):
        feed = SmartScreenFeed(tenant_id="t", client_id="c", client_secret="s")
        # Pre-populate token cache so no token request is made.
        feed._token_cache = ("cached-token", time.monotonic() + 3000)

        empty_resp = {"value": []}
        with patch("feeds.httpx.AsyncClient") as mock_cls:
            client = _async_response(200, empty_resp)
            mock_cls.return_value = client
            await feed.lookup("https://clean.example.com/")
            # Only one AsyncClient instantiation — indicator lookup only.
            assert mock_cls.call_count == 1

    @pytest.mark.anyio
    async def test_lookup_returns_empty_on_network_error(self):
        feed = SmartScreenFeed(tenant_id="t", client_id="c", client_secret="s")

        with patch("feeds.httpx.AsyncClient") as mock_cls:
            mock_cls.side_effect = Exception("network down")
            result = await feed.lookup("https://example.com/")

        assert not result.matched

    @pytest.mark.anyio
    async def test_lookup_returns_empty_on_token_failure(self):
        feed = SmartScreenFeed(tenant_id="t", client_id="c", client_secret="s")

        with patch("feeds.httpx.AsyncClient") as mock_cls:
            client = _async_response(401, {"error": "unauthorized"})
            mock_cls.return_value = client
            result = await feed.lookup("https://example.com/")

        assert not result.matched


# ---------------------------------------------------------------------------
# VirusTotalFeed
# ---------------------------------------------------------------------------


class TestVirusTotalFeed:
    def test_not_configured_when_key_missing(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        feed = VirusTotalFeed()
        assert not feed.configured

    def test_configured_when_key_set(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key")
        feed = VirusTotalFeed()
        assert feed.configured

    @pytest.mark.anyio
    async def test_url_id_encoding(self):
        """The VT URL ID must be URL-safe base64 without padding."""
        import base64

        url = "https://evil.example.com/path?q=1"
        vt = VirusTotalFeed(api_key="k")
        url_id = vt._url_id(url)
        # Decode and verify round-trip.
        padded = url_id + "=" * (4 - len(url_id) % 4)
        assert base64.urlsafe_b64decode(padded).decode() == url

    @pytest.mark.anyio
    async def test_lookup_returns_empty_when_not_configured(self):
        feed = VirusTotalFeed(api_key="")
        result = await feed.lookup("https://example.com/")
        assert not result.matched

    @pytest.mark.anyio
    async def test_lookup_clean_url(self):
        feed = VirusTotalFeed(api_key="test-key")
        vt_body = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 50,
                        "undetected": 10,
                    },
                    "categories": {},
                }
            }
        }
        with patch("feeds.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = _async_response(200, vt_body)
            result = await feed.lookup("https://clean.example.com/")

        assert not result.matched

    @pytest.mark.anyio
    async def test_lookup_malicious_url(self):
        feed = VirusTotalFeed(api_key="test-key")
        vt_body = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 20,
                        "suspicious": 5,
                        "harmless": 30,
                        "undetected": 15,
                    },
                    "categories": {
                        "engine_a": "Phishing",
                        "engine_b": "malware",
                    },
                }
            }
        }
        with patch("feeds.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = _async_response(200, vt_body)
            result = await feed.lookup("https://evil.example.com/")

        assert result.matched
        # confidence = (20 + 5*0.5) / (20+5+30+15) = 22.5/70 ≈ 0.321
        assert result.confidence == pytest.approx(22.5 / 70, abs=1e-3)
        assert len(result.threat_types) >= 1

    @pytest.mark.anyio
    async def test_lookup_404_is_clean(self):
        feed = VirusTotalFeed(api_key="test-key")
        with patch("feeds.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = _async_response(404, {})
            result = await feed.lookup("https://unknown.example.com/")

        assert not result.matched

    @pytest.mark.anyio
    async def test_cache_hit_avoids_second_request(self):
        feed = VirusTotalFeed(api_key="test-key", cache_ttl_s=300)
        vt_body = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 10,
                        "suspicious": 0,
                        "harmless": 40,
                        "undetected": 10,
                    },
                    "categories": {},
                }
            }
        }
        url = "https://cached.example.com/"
        with patch("feeds.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = _async_response(200, vt_body)
            r1 = await feed.lookup(url)
            r2 = await feed.lookup(url)
            # Second lookup hits cache; only one AsyncClient instantiation.
            assert mock_cls.call_count == 1

        assert r1.matched
        assert r2.matched
        assert r1 is r2  # same object from cache

    @pytest.mark.anyio
    async def test_cache_expires(self):
        feed = VirusTotalFeed(api_key="test-key", cache_ttl_s=1)
        vt_body = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 0,
                        "harmless": 10,
                        "undetected": 5,
                    },
                    "categories": {},
                }
            }
        }
        url = "https://expiry.example.com/"
        with patch("feeds.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = _async_response(200, vt_body)
            await feed.lookup(url)
            # Force expire the cache entry.
            feed._cache[url] = (feed._cache[url][0], time.monotonic() - 1)
            await feed.lookup(url)
            # Two requests — the second was a cache miss.
            assert mock_cls.call_count == 2

    @pytest.mark.anyio
    async def test_lookup_returns_empty_on_network_error(self):
        feed = VirusTotalFeed(api_key="test-key")
        with patch("feeds.httpx.AsyncClient") as mock_cls:
            mock_cls.side_effect = Exception("timeout")
            result = await feed.lookup("https://example.com/")

        assert not result.matched


# ---------------------------------------------------------------------------
# ReputationAggregator
# ---------------------------------------------------------------------------


class TestReputationAggregator:
    @pytest.mark.anyio
    async def test_aggregator_empty_feeds(self):
        agg = ReputationAggregator(feeds=[])
        result = await agg.lookup("https://example.com/")
        assert isinstance(result, AggregatedReputation)
        assert not result.matched
        assert result.phishing == 0.0
        assert result.malware == 0.0

    @pytest.mark.anyio
    async def test_aggregator_maps_phishing_type(self):
        feed = MagicMock(spec=["name", "lookup"])
        feed.name = "test"
        feed.lookup = AsyncMock(
            return_value=FeedVerdict(
                feed="test",
                matched=True,
                threat_types=["SOCIAL_ENGINEERING"],
                confidence=0.9,
            )
        )
        agg = ReputationAggregator(feeds=[feed])
        result = await agg.lookup("https://evil.com/")
        assert result.matched
        assert result.phishing == pytest.approx(0.9)
        assert result.malware == 0.0

    @pytest.mark.anyio
    async def test_aggregator_maps_malware_type(self):
        feed = MagicMock(spec=["name", "lookup"])
        feed.name = "test"
        feed.lookup = AsyncMock(
            return_value=FeedVerdict(
                feed="test",
                matched=True,
                threat_types=["MALWARE"],
                confidence=0.95,
            )
        )
        agg = ReputationAggregator(feeds=[feed])
        result = await agg.lookup("https://evil.com/")
        assert result.matched
        assert result.malware == pytest.approx(0.95)
        assert result.phishing == 0.0

    @pytest.mark.anyio
    async def test_aggregator_unknown_threat_type_falls_back_to_malware(self):
        feed = MagicMock(spec=["name", "lookup"])
        feed.name = "test"
        feed.lookup = AsyncMock(
            return_value=FeedVerdict(
                feed="test",
                matched=True,
                threat_types=["COMPLETELY_UNKNOWN_TYPE"],
                confidence=0.7,
            )
        )
        agg = ReputationAggregator(feeds=[feed])
        result = await agg.lookup("https://evil.com/")
        assert result.matched
        assert result.malware == pytest.approx(0.7)

    @pytest.mark.anyio
    async def test_aggregator_takes_max_across_feeds(self):
        def _feed(name: str, confidence: float, types):
            f = MagicMock(spec=["name", "lookup"])
            f.name = name
            f.lookup = AsyncMock(
                return_value=FeedVerdict(
                    feed=name, matched=True, threat_types=types, confidence=confidence
                )
            )
            return f

        agg = ReputationAggregator(feeds=[
            _feed("f1", 0.6, ["MALWARE"]),
            _feed("f2", 0.9, ["MALWARE"]),
        ])
        result = await agg.lookup("https://evil.com/")
        assert result.malware == pytest.approx(0.9)

    @pytest.mark.anyio
    async def test_aggregator_ignores_exceptions_from_feeds(self):
        feed = MagicMock(spec=["name", "lookup"])
        feed.name = "broken"
        feed.lookup = AsyncMock(side_effect=RuntimeError("feed exploded"))
        agg = ReputationAggregator(feeds=[feed])
        result = await agg.lookup("https://example.com/")
        # Should not raise; should return an empty (clean) verdict.
        assert not result.matched

    def test_from_env_picks_up_safe_browsing_key(self, monkeypatch):
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", "sb-key")
        monkeypatch.delenv("SMARTSCREEN_TENANT_ID", raising=False)
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        agg = ReputationAggregator.from_env()
        assert any(f.name == "google-safe-browsing" for f in agg._feeds)

    def test_from_env_picks_up_virustotal_key(self, monkeypatch):
        monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
        monkeypatch.delenv("SMARTSCREEN_TENANT_ID", raising=False)
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key")
        agg = ReputationAggregator.from_env()
        assert any(f.name == "virustotal" for f in agg._feeds)

    def test_from_env_picks_up_smartscreen_creds(self, monkeypatch):
        monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
        monkeypatch.setenv("SMARTSCREEN_TENANT_ID", "tid")
        monkeypatch.setenv("SMARTSCREEN_CLIENT_ID", "cid")
        monkeypatch.setenv("SMARTSCREEN_CLIENT_SECRET", "sec")
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        agg = ReputationAggregator.from_env()
        assert any(f.name == "microsoft-smartscreen" for f in agg._feeds)

    def test_from_env_no_creds_returns_empty_aggregator(self, monkeypatch):
        monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
        monkeypatch.delenv("SMARTSCREEN_TENANT_ID", raising=False)
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        agg = ReputationAggregator.from_env()
        assert agg._feeds == []
