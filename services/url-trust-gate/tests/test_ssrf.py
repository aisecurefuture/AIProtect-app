"""SSRF guard tests for the safe crawler.

These tests do NOT make real HTTP calls — they only exercise the
destination classifier. The network namespace is the real boundary in
production; this is the belt-and-braces layer.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from crawler import _ssrf_safe_destination  # noqa: E402


def _addrinfo(addrs):
    return [(socket.AF_INET, None, None, None, (a, 0)) for a in addrs]


def test_rejects_loopback():
    with patch("crawler.socket.getaddrinfo", return_value=_addrinfo(["127.0.0.1"])):
        assert _ssrf_safe_destination("http://localhost/") is False


def test_rejects_rfc1918():
    for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
        with patch("crawler.socket.getaddrinfo", return_value=_addrinfo([ip])):
            assert _ssrf_safe_destination(f"http://{ip}/") is False


def test_rejects_link_local():
    with patch("crawler.socket.getaddrinfo", return_value=_addrinfo(["169.254.1.2"])):
        assert _ssrf_safe_destination("http://anywhere/") is False


def test_rejects_aws_metadata():
    with patch(
        "crawler.socket.getaddrinfo", return_value=_addrinfo(["169.254.169.254"])
    ):
        assert _ssrf_safe_destination("http://anywhere/") is False


def test_rejects_dns_rebinding_with_mixed_records():
    # DNS rebinding: server returns one public + one internal address.
    # We MUST reject if ANY resolved IP is internal.
    with patch(
        "crawler.socket.getaddrinfo",
        return_value=_addrinfo(["8.8.8.8", "10.0.0.1"]),
    ):
        assert _ssrf_safe_destination("http://attacker.example/") is False


def test_accepts_public_ip():
    with patch("crawler.socket.getaddrinfo", return_value=_addrinfo(["8.8.8.8"])):
        assert _ssrf_safe_destination("http://example.com/") is True


def test_rejects_non_http_schemes():
    assert _ssrf_safe_destination("file:///etc/passwd") is False
    assert _ssrf_safe_destination("gopher://example.com/") is False
    assert _ssrf_safe_destination("ftp://example.com/") is False


def test_rejects_empty_host():
    assert _ssrf_safe_destination("http:///path") is False


def test_rejects_dns_failure():
    # If DNS resolution fails, we err on the side of refusing rather
    # than letting the HTTP client connect to a stale hostname.
    with patch(
        "crawler.socket.getaddrinfo", side_effect=socket.gaierror("no such host")
    ):
        assert _ssrf_safe_destination("http://nope.example/") is False


def test_allowlist_bypasses_private_check():
    # The PoC overlay sets URL_TRUST_GATE_CRAWLER_SSRF_ALLOWLIST so the
    # gate's safe crawler can fetch from a same-network test fixture.
    # Verify the allowlist takes effect.
    import crawler as crawler_module

    original = crawler_module._SSRF_ALLOWLIST_HOSTS
    try:
        crawler_module._SSRF_ALLOWLIST_HOSTS = {"poc-test-server"}
        # No DNS lookup is required when host is on the allowlist.
        assert _ssrf_safe_destination("http://poc-test-server:8088/x") is True
    finally:
        crawler_module._SSRF_ALLOWLIST_HOSTS = original


def test_allowlist_default_empty_does_not_change_behaviour():
    # Default deployment must still reject loopback even when the
    # allowlist module-level set exists.
    import crawler as crawler_module

    assert crawler_module._SSRF_ALLOWLIST_HOSTS == set() or isinstance(
        crawler_module._SSRF_ALLOWLIST_HOSTS, set
    )
    with patch("crawler.socket.getaddrinfo", return_value=_addrinfo(["127.0.0.1"])):
        assert _ssrf_safe_destination("http://localhost/") is False
