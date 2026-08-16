"""A cached verdict must never outlive the conditions that produced it.

WHY A CACHE AT ALL
==================
A scan is a pure function of (text, configuration), and nothing memoised it:
identical text scanned twice paid full transformer inference twice, measured at
~3.58 s and ~14 core-seconds per /scan. For a consumer product -- where the
same prompts and the same handful of URLs recur constantly across users -- that
is the largest avoidable cost in the system.

WHY IT IS DANGEROUS
===================
A result cache in a security service can persist a wrong answer, and the two
ways it can be wrong are both silent:

  1. CACHING A DEGRADED VERDICT. A response carrying `detector_unavailable`
     describes a moment when a model was broken, not a property of the text.
     Cache it and a transient fault becomes a persistent lie about coverage,
     pinned in front of a model that has since recovered, for the whole TTL.
  2. CACHING ACROSS A CONFIGURATION CHANGE. Move a threshold or narrow the
     profile and yesterday's verdict is no longer an answer to today's
     question.

Both are pinned here, along with the privacy property: the cache stores
verdicts, never the text that produced them.
"""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scan_cache import ScanCache  # noqa: E402


def _cache(**kw):
    kw.setdefault("enabled", True)
    return ScanCache(**kw)


class IncompleteScansAreNeverCached(unittest.TestCase):
    def test_a_scan_that_reported_a_gap_is_refused(self):
        c = _cache()
        c.put("k", {"risk_score": 0.0, "scan_complete": False})
        self.assertIsNone(c.get("k"))
        self.assertEqual(c.stats()["refused_incomplete"], 1)

    def test_a_nonempty_detectors_unavailable_is_refused(self):
        c = _cache()
        c.put("k", {"scan_complete": True,
                    "detectors_unavailable": [{"detector": "toxicity_model"}]})
        self.assertIsNone(c.get("k"))

    def test_a_detector_unavailable_finding_is_refused(self):
        """Even when the top-level flags look clean.

        The single-detector routes do not carry `scan_complete`, so the
        findings list is the only place the gap appears. A cache that only
        checked the summary fields would happily memoise those.
        """
        c = _cache()
        c.put("k", {"risk_score": 0.0,
                    "detections": [{"type": "detector_unavailable",
                                    "detector": "ner_model"}]})
        self.assertIsNone(c.get("k"))

    def test_a_genuinely_clean_scan_is_cached(self):
        """The negative case matters too: a cache that refuses everything is
        indistinguishable from one that is broken, and would be 'fixed' by
        being deleted."""
        c = _cache()
        c.put("k", {"risk_score": 0.0, "detections": [], "scan_complete": True})
        self.assertIsNotNone(c.get("k"))
        self.assertEqual(c.stats()["hits"], 1)


class ConfigurationIsPartOfIdentity(unittest.TestCase):
    def test_a_different_fingerprint_is_a_different_key(self):
        c = _cache()
        a = c.key("scan", "same text", "fingerprint-v1")
        b = c.key("scan", "same text", "fingerprint-v2")
        self.assertNotEqual(a, b)

    def test_a_different_namespace_is_a_different_key(self):
        """/scan/toxicity and /scan/output-safety answer different questions
        about the same string; one keyspace for both would cross them."""
        c = _cache()
        self.assertNotEqual(
            c.key("toxicity", "t", "fp"), c.key("output-safety", "t", "fp")
        )

    def test_same_inputs_are_the_same_key(self):
        c = _cache()
        self.assertEqual(c.key("scan", "t", "fp"), c.key("scan", "t", "fp"))


class TheCacheHoldsNoPlaintext(unittest.TestCase):
    def test_the_key_does_not_contain_the_text(self):
        c = _cache()
        secret = "my password is hunter2 and my ssn is 123-45-6789"
        key = c.key("scan", secret, "fp")
        self.assertNotIn("hunter2", key)
        self.assertNotIn("123-45-6789", key)

    def test_the_keyspace_is_salted_per_process(self):
        """Two processes must not produce the same digest for the same text.

        An unsalted digest is an offline-checkable fingerprint of user content:
        anyone holding the keyspace could confirm whether a given message was
        scanned. That is a weaker property than it sounds like for B2C, where
        the text is a private individual's chat message.
        """
        self.assertNotEqual(
            _cache().key("scan", "text", "fp"), _cache().key("scan", "text", "fp")
        )


class BoundsAndFreshness(unittest.TestCase):
    def test_entries_expire(self):
        c = _cache(ttl_seconds=0.05)
        c.put("k", {"scan_complete": True})
        self.assertIsNotNone(c.get("k"))
        time.sleep(0.08)
        self.assertIsNone(c.get("k"))
        self.assertEqual(c.stats()["expired"], 1)

    def test_the_cache_is_bounded(self):
        """Unbounded in-process state in this service reached 7.3 GiB against
        an 8 GiB cap in 27 hours once already (the promptware tracker). This
        one is an LRU from the start rather than after the incident."""
        c = _cache(max_entries=10)
        for i in range(50):
            c.put(f"k{i}", {"scan_complete": True})
        self.assertLessEqual(c.stats()["entries"], 10)
        self.assertGreater(c.stats()["evictions"], 0)

    def test_a_hit_cannot_be_mutated_by_its_caller(self):
        """Callers stamp profile markers onto the response they get back. A
        shared dict would let one request rewrite another request's answer."""
        c = _cache()
        c.put("k", {"scan_complete": True, "detections": []})
        first = c.get("k")
        first["detections"].append({"type": "injected"})
        first["scan_complete"] = "tampered"
        second = c.get("k")
        self.assertEqual(second["detections"], [])
        self.assertIs(second["scan_complete"], True)

    def test_disabled_is_disabled(self):
        """Default OFF: enabling a cache changes what a caller observes, and
        the B2B deployment serves a regulated pilot. That is their decision to
        opt into, not one to inherit from a B2C change."""
        c = ScanCache(enabled=False)
        c.put("k", {"scan_complete": True})
        self.assertIsNone(c.get("k"))
        self.assertEqual(c.stats()["entries"], 0)


if __name__ == "__main__":
    unittest.main()
