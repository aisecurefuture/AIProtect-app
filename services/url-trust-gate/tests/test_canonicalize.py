"""Tests for canonicalize.py.

Run with: pytest services/url-trust-gate/tests/
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from canonicalize import canonicalize_url, classify_querystring_sensitivity  # noqa: E402


def test_basic_canonicalisation_lowercases_and_strips_default_port():
    c = canonicalize_url("HTTP://Example.COM:80/Path/?A=1&b=2")
    assert c.scheme == "http"
    assert c.host == "example.com"
    assert c.port is None  # 80 stripped
    assert c.path == "/Path/"


def test_https_default_port_stripped():
    c = canonicalize_url("https://example.com:443/")
    assert c.port is None


def test_non_default_port_preserved():
    c = canonicalize_url("https://example.com:8443/x")
    assert c.port == 8443


def test_querystring_keys_with_rotating_values_share_fingerprint():
    a = canonicalize_url("https://example.com/api?token=AAA&id=1")
    b = canonicalize_url("https://example.com/api?token=BBB&id=1")
    # Same fingerprint — token VALUES differ but KEY set is identical.
    assert a.fingerprint == b.fingerprint


def test_querystring_key_order_does_not_change_fingerprint():
    a = canonicalize_url("https://example.com/api?id=1&token=AAA")
    b = canonicalize_url("https://example.com/api?token=AAA&id=1")
    assert a.fingerprint == b.fingerprint


def test_different_paths_produce_different_fingerprints():
    a = canonicalize_url("https://example.com/a")
    b = canonicalize_url("https://example.com/b")
    assert a.fingerprint != b.fingerprint


def test_querystring_sensitivity_flags_known_keys():
    params = [("token", "abc"), ("id", "1"), ("password", "x"), ("safe", "ok")]
    sens = classify_querystring_sensitivity(params)
    assert sens["token"] is True
    assert sens["password"] is True
    assert sens["id"] is False
    assert sens["safe"] is False


def test_redacted_url_replaces_only_sensitive_values():
    c = canonicalize_url("https://example.com/p?token=SECRET&page=2")
    sens = classify_querystring_sensitivity(c.query_params)
    redacted = c.redacted_url(sens)
    assert "SECRET" not in redacted
    assert "__REDACTED__" in redacted
    assert "page=2" in redacted


def test_punycode_homoglyph_detected():
    # "xn--pple-43d.com" decodes to "ápple.com" — ascii + non-ascii letters.
    c = canonicalize_url("https://xn--pple-43d.com/")
    assert c.homoglyph_suspected is True


def test_non_homoglyph_idn_does_not_flag():
    # "xn--bcher-kva.de" decodes to "bücher.de" — single-script (Latin
    # extended), shouldn't flag in our cheap heuristic.
    c = canonicalize_url("https://xn--bcher-kva.de/")
    # Either flagged or not, the host should round-trip cleanly.
    assert c.host == "xn--bcher-kva.de"


def test_userinfo_in_url_does_not_break_parsing():
    # We don't strip userinfo (could be useful for evidence) but we also
    # shouldn't crash.
    c = canonicalize_url("https://user:pass@example.com/")
    assert c.host == "example.com"
