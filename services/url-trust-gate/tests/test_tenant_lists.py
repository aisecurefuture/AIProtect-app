"""Tests for tenant_lists.py."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tenant_lists import _domain_match, _url_match, _merge  # noqa: E402


def test_domain_exact_match():
    assert _domain_match("example.com", "example.com") is True
    assert _domain_match("foo.example.com", "example.com") is False


def test_domain_dotted_suffix_matches_subdomains():
    assert _domain_match("foo.example.com", ".example.com") is True
    assert _domain_match("a.b.example.com", ".example.com") is True
    # Apex itself does NOT match the dotted form.
    assert _domain_match("example.com", ".example.com") is False


def test_domain_match_is_case_insensitive():
    assert _domain_match("Example.COM", "example.com") is True


def test_url_exact_match():
    assert _url_match("https://example.com/x", "https://example.com/x") is True
    assert _url_match("https://example.com/x", "https://example.com/y") is False


def test_url_prefix_match():
    assert _url_match("https://example.com/admin/page", "https://example.com/admin/*") is True
    assert _url_match("https://example.com/api/v1", "https://example.com/admin/*") is False


def test_merge_picks_up_block_and_allow_arrays():
    policies = [
        {
            "enabled": True,
            "rules": {
                "block_domains": ["bad.example", ".phishing.test"],
                "allow_domains": ["corp.example.com"],
            },
        },
        {
            "enabled": True,
            "rules": {"block_urls": ["https://bad.example/login*"]},
        },
        {
            "enabled": False,  # disabled — should be ignored
            "rules": {"allow_domains": ["should-not-leak.example"]},
        },
    ]
    merged = _merge(policies)
    assert "bad.example" in merged.block_domains
    assert ".phishing.test" in merged.block_domains
    assert "corp.example.com" in merged.allow_domains
    assert "https://bad.example/login*" in merged.block_urls
    assert "should-not-leak.example" not in merged.allow_domains


def test_merge_dedupes():
    policies = [
        {"enabled": True, "rules": {"block_domains": ["bad.example", "bad.example"]}},
    ]
    merged = _merge(policies)
    assert merged.block_domains.count("bad.example") == 1
