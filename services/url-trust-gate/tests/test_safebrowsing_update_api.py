"""Safe Browsing v4 Update API — canonicalization, expressions, honesty.

WHY THIS FEED CHANGED
--------------------
It was the **Lookup API** (``v4/threatMatches:find``): one HTTPS round trip to
Google per URL checked. Correct for a low-volume tool, wrong here. This gate is
consulted on every top-level navigation and from the MITM proxy's Step 0, so at
the 800-seat pilot scale it is on the order of 10^5 lookups/day against a
default quota near 10^4 -- and every one of them puts a customer's browsing on
Google's wire, one URL at a time, which is its own problem for a financial firm.

The **Update API** inverts it: Google publishes SHA-256 prefixes, the client
downloads them and matches locally. No per-lookup quota, no per-lookup latency,
and only a 4-byte prefix is ever transmitted -- for the ~1-in-4-billion
collisions that need confirming.

WHY CANONICALIZATION IS THE THING UNDER TEST
--------------------------------------------
Local matching only works if this client hashes a URL to the SAME bytes Google
did. Every canonicalization step exists because Google's matcher performs it,
and a mismatch is not cosmetic: an under-canonicalized URL computes a different
SHA-256 and MISSES a listed threat. That failure is silent and always in the
unsafe direction -- the URL is reported clean.

So the vectors below are Google's own published ones, not invented cases. If a
future change breaks one, it breaks the feed's ability to detect real malware
while everything still looks like it works.

No network: every test here is pure functions or an injected transport.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Loaded by path under a unique name: several services in this repo share
# top-level module names and sys.modules is process-wide.
_spec = importlib.util.spec_from_file_location(
    "utg_safebrowsing_v4", ROOT / "safebrowsing_v4.py"
)
sb = importlib.util.module_from_spec(_spec)
sys.modules["utg_safebrowsing_v4"] = sb   # dataclasses needs this registered
_spec.loader.exec_module(sb)


class TestCanonicalizationMatchesGooglesVectors:
    """Google's published canonicalization test vectors, verbatim."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            # Repeated percent-unescaping. One pass leaves an attacker a layer
            # of encoding to hide behind.
            ("http://host/%25%32%35", "http://host/%25"),
            ("http://host/%25%32%35%25%32%35", "http://host/%25%25"),
            ("http://host/%2525252525252525", "http://host/%25"),
            ("http://host/asdf%25%32%35asd", "http://host/asdf%25asd"),
            # Fully percent-encoded host and path.
            (
                "http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/"
                "%77%77%77%2E%65%62%61%79%2E%63%6F%6D/",
                "http://168.188.99.26/.secure/www.ebay.com/",
            ),
            # Integer-form IP. Used precisely because a naive matcher treats it
            # as a different host from the dotted quad.
            ("http://3279880203/blah", "http://195.127.0.11/blah"),
            # Path traversal resolution.
            ("http://www.google.com/blah/..", "http://www.google.com/"),
            # Fragments are never part of the match.
            ("http://www.evil.com/blah#frag", "http://www.evil.com/blah"),
            ("http://evil.com/foo#bar#baz", "http://evil.com/foo"),
            # Case and stray dots in the host.
            ("http://www.GOOgle.com/", "http://www.google.com/"),
            ("http://www.google.com..../", "http://www.google.com/"),
            # Embedded control characters.
            ("http://www.google.com/foo\tbar\rbaz\n2", "http://www.google.com/foobarbaz2"),
            # A query containing '?' is left alone.
            ("http://www.google.com/q?r?s", "http://www.google.com/q?r?s"),
            ("http://www.google.com/", "http://www.google.com/"),
        ],
    )
    def test_vector(self, raw, expected):
        assert sb.canonicalize(raw) == expected


class TestExpressionsMatchGooglesWorkedExamples:
    """The exact expression sets from the spec's two worked examples."""

    def test_host_with_path_and_query(self):
        got = sb.url_expressions("http://a.b.c/1/2.html?param=1")
        assert sorted(got) == sorted([
            "a.b.c/1/2.html?param=1", "a.b.c/1/2.html", "a.b.c/", "a.b.c/1/",
            "b.c/1/2.html?param=1", "b.c/1/2.html", "b.c/", "b.c/1/",
        ])

    def test_deep_subdomain(self):
        """Regression: the last-five-components entry was being skipped.

        For a.b.c.d.e.f.g the spec starts at the LAST FIVE components --
        c.d.e.f.g -- and successively drops the leading one. An off-by-one that
        starts one past it omits c.d.e.f.g, so a threat listed on that parent
        domain does not match. Silent, and in the unsafe direction.
        """
        got = sb.url_expressions("http://a.b.c.d.e.f.g/1.html")
        assert sorted(got) == sorted([
            "a.b.c.d.e.f.g/1.html", "a.b.c.d.e.f.g/",
            "c.d.e.f.g/1.html", "c.d.e.f.g/",
            "d.e.f.g/1.html", "d.e.f.g/",
            "e.f.g/1.html", "e.f.g/",
            "f.g/1.html", "f.g/",
        ])

    def test_never_exceeds_thirty(self):
        """The spec's hard cap. Exceeding it is wasted hashing per request."""
        deep = "http://a.b.c.d.e.f.g.h/1/2/3/4/5/6/7.html?x=1&y=2"
        assert len(sb.url_expressions(deep)) <= 30

    def test_the_bare_tld_is_never_an_expression(self):
        """Listing on a TLD would match the entire internet under it."""
        for url in ("http://a.b.c/1", "http://www.google.com/", "http://x.y.z.co/p"):
            for expression in sb.url_expressions(url):
                host = expression.split("/")[0]
                assert "." in host, f"{expression!r} would match a whole TLD"


class TestTheDatabaseDoesNotClaimCleanWhenItHasNothing:
    """The honesty property. An empty database has not cleared anything."""

    def test_an_unsynced_database_is_not_authoritative(self):
        db = sb.SafeBrowsingDatabase()
        matches, authoritative = db.lookup("http://evil.example/")
        assert matches == []
        assert authoritative is False, (
            "an empty database reported an authoritative verdict; 'no match' "
            "from a list that was never downloaded is not a clean URL, and a "
            "caller cannot tell the difference"
        )

    def test_a_synced_database_is_authoritative_even_with_no_match(self):
        db = sb.SafeBrowsingDatabase()
        db.apply_update("MALWARE", {
            "responseType": "FULL_UPDATE",
            "additions": [{"rawHashes": {
                "prefixSize": 4,
                "rawHashes": base64.b64encode(b"\x00\x01\x02\x03").decode(),
            }}],
            "newClientState": "state-1",
        })
        db.last_sync_at = 1.0
        matches, authoritative = db.lookup("http://definitely-not-listed.example/")
        assert matches == []
        assert authoritative is True

    def test_a_listed_url_produces_a_prefix_match(self):
        """End to end: hash a real expression, list it, and find it."""
        url = "http://malware.example/bad"
        full = hashlib.sha256(sb.url_expressions(url)[0].encode()).digest()
        db = sb.SafeBrowsingDatabase()
        db.apply_update("MALWARE", {
            "responseType": "FULL_UPDATE",
            "additions": [{"rawHashes": {
                "prefixSize": 4,
                "rawHashes": base64.b64encode(full[:4]).decode(),
            }}],
            "newClientState": "state-1",
        })
        db.last_sync_at = 1.0
        matches, authoritative = db.lookup(url)
        assert authoritative is True
        assert matches and matches[0].threat_type == "MALWARE"
        assert matches[0].expression_hash == full


class TestUpdateApplication:
    def test_a_full_update_replaces_rather_than_merges(self):
        """FULL_UPDATE means "forget what you had". Merging keeps delisted
        threats alive forever and slowly turns the list into a fiction."""
        db = sb.SafeBrowsingDatabase()
        first = {"responseType": "FULL_UPDATE", "additions": [{"rawHashes": {
            "prefixSize": 4, "rawHashes": base64.b64encode(b"AAAA").decode()}}]}
        second = {"responseType": "FULL_UPDATE", "additions": [{"rawHashes": {
            "prefixSize": 4, "rawHashes": base64.b64encode(b"BBBB").decode()}}]}
        db.apply_update("MALWARE", first)
        db.apply_update("MALWARE", second)
        assert db.prefix_count == 1

    def test_removals_index_into_the_sorted_prefix_list(self):
        """Google's removal indices assume sorted order.

        Applying them against an unsorted set deletes the WRONG entries --
        silently, and always by leaving some threat unlisted.
        """
        db = sb.SafeBrowsingDatabase()
        raw = b"CCCC" + b"AAAA" + b"BBBB"   # deliberately unsorted on the wire
        db.apply_update("MALWARE", {
            "responseType": "FULL_UPDATE",
            "additions": [{"rawHashes": {
                "prefixSize": 4, "rawHashes": base64.b64encode(raw).decode()}}],
        })
        assert db.prefix_count == 3
        # index 0 of the SORTED list is b"AAAA"
        db.apply_update("MALWARE", {
            "responseType": "PARTIAL_UPDATE",
            "removals": [{"rawIndices": {"indices": [0]}}],
        })
        remaining = db._lists["MALWARE"].prefixes
        assert b"AAAA" not in remaining
        assert {b"BBBB", b"CCCC"} == remaining

    def test_a_malformed_addition_is_skipped_not_guessed(self):
        """Bytes that do not divide by prefixSize are not silently sliced."""
        db = sb.SafeBrowsingDatabase()
        db.apply_update("MALWARE", {
            "responseType": "FULL_UPDATE",
            "additions": [{"rawHashes": {
                "prefixSize": 4,
                "rawHashes": base64.b64encode(b"ABCDE").decode(),  # 5 bytes
            }}],
        })
        assert db.prefix_count == 0


class TestTheFeedWrapper:
    def test_an_unconfigured_feed_is_never_authoritative(self):
        from feeds import SafeBrowsingFeed
        import asyncio
        feed = SafeBrowsingFeed(api_key="")
        verdict = asyncio.run(feed.lookup("http://anything/"))
        assert verdict.matched is False
        assert verdict.authoritative is False, (
            "a feed with no API key reported an authoritative verdict"
        )

    def test_a_configured_but_unsynced_feed_is_not_authoritative(self):
        from feeds import SafeBrowsingFeed
        import asyncio
        feed = SafeBrowsingFeed(api_key="test-key")
        verdict = asyncio.run(feed.lookup("http://anything/"))
        assert verdict.matched is False
        assert verdict.authoritative is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))


class TestAConfirmedMalwareVerdictBlocks:
    """A high-confidence malware hit must not come out as a warning.

    THE DEFECT. `_fallback_decision` had a branch for phishing and none for
    malware, so `scores.malware` -- set, populated by the reputation feeds, and
    consulted by nothing -- fell through to the generic `overall_risk >= 0.5`
    line and produced `warn`.

    Measured 2026-08-01 against Google's own live test URLs through the running
    gate: phishing.html blocked, malware.html warned. Both are 0.95-confidence
    Safe Browsing verdicts from the same feed; only one had a line of code.
    """

    def _scores(self, **kw):
        from main import TrustGateScores
        return TrustGateScores(**kw)

    def test_confirmed_malware_blocks(self):
        from main import _fallback_decision
        d = _fallback_decision(self._scores(malware=0.95, overall_risk=0.95))
        assert d.action == "block", (
            "a confirmed Safe Browsing MALWARE verdict produced "
            f"{d.action!r} -- the same action as 'moderate risk'"
        )

    def test_confirmed_phishing_still_blocks(self):
        from main import _fallback_decision
        d = _fallback_decision(self._scores(phishing=0.95, overall_risk=0.95))
        assert d.action == "block"

    def test_moderate_risk_without_a_named_threat_still_only_warns(self):
        """The control: the new branch must not turn every moderate score into
        a block, which would make the gate unusable."""
        from main import _fallback_decision
        d = _fallback_decision(self._scores(overall_risk=0.6))
        assert d.action == "warn"

    def test_a_clean_url_is_still_allowed(self):
        from main import _fallback_decision
        d = _fallback_decision(self._scores(overall_risk=0.1))
        assert d.action == "allow"
