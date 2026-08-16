"""The served demo must be fetchable by the gate, or it silently does nothing.

The founder opened the crafted pages as file:// in Chrome and saw nothing
logged. By design: the gate evaluates a URL by FETCHING it (a file:// path on
the operator's Mac is unreachable from the container), and the extension's hook
only evaluates http/https navigations. The fix is a served path -- but a served
path is only useful if three things line up, and each has already silently
failed once in this codebase:

  1. the demo-content service exists and mounts the pages,
  2. the gate is SSRF-ALLOWLISTED to fetch demo-content (the guard refuses
     RFC1918/loopback by default -- that is the point of it), and
  3. the demo posts the URL the GATE can reach (service DNS name), not the one
     the operator browses to (127.0.0.1) -- they differ, and using the wrong
     one fetches nothing.

These are asserted structurally so the demo cannot rot into a no-op the way the
bypass-hosts sync did.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

_GATE = Path(__file__).resolve().parents[1]
_REPO = _GATE.parent.parent
_COMPOSE = _REPO / "infra" / "docker-compose" / "docker-compose.yml"
_PAGES = _REPO / "scripts" / "poc" / "test-pages"


def _compose():
    return yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))


def _env(service: dict) -> dict:
    e = service.get("environment") or {}
    if isinstance(e, list):
        out = {}
        for item in e:
            if "=" in item:
                k, v = item.split("=", 1)
                out[k] = v
        return out
    return e


class TheDemoPagesExist(unittest.TestCase):

    def test_all_four_named_attack_types_are_present(self):
        # The founder named these four explicitly.
        for page in ("hidden-instruction.html", "credential-harvest.html",
                     "brand-impersonation.html", "zero-width-injection.html"):
            with self.subTest(page=page):
                self.assertTrue((_PAGES / page).exists(),
                                f"{page} is missing; the demo cannot show it")

    def test_a_benign_control_exists(self):
        """Without a benign page that is ALLOWED, a demo where everything blocks
        proves nothing -- it could be blocking indiscriminately."""
        self.assertTrue((_PAGES / "benign.html").exists())


class TheServiceIsAlwaysOn(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.services = _compose().get("services") or {}

    def test_demo_content_is_in_the_main_stack(self):
        self.assertIn(
            "demo-content", self.services,
            "demo-content is not in the main compose stack, so the demo path "
            "only exists behind the poc profile and is not always available",
        )

    def test_it_is_not_profile_gated(self):
        """A profiled service does not start with a plain `up` -- which is
        exactly how the founder would run it."""
        self.assertNotIn(
            "profiles", self.services.get("demo-content", {}),
            "demo-content is profile-gated, so it will not be running when the "
            "demo is attempted",
        )

    def test_it_mounts_the_pages_read_only(self):
        vols = self.services["demo-content"].get("volumes") or []
        joined = " ".join(str(v) for v in vols)
        self.assertIn("scripts/poc/test-pages", joined, "pages are not mounted")
        self.assertIn(":ro", joined,
                      "the demo host serving a fake credential form must be "
                      "read-only")

    def test_it_is_not_exposed_beyond_loopback(self):
        ports = self.services["demo-content"].get("ports") or []
        for pmap in ports:
            with self.subTest(port=pmap):
                self.assertTrue(
                    str(pmap).startswith("127.0.0.1:"),
                    f"{pmap} exposes the demo host beyond loopback; it serves a "
                    f"fake login form and must not be publicly reachable",
                )


class TheGateCanReachIt(unittest.TestCase):

    def test_the_gate_ssrf_allowlists_demo_content(self):
        gate = (_compose().get("services") or {}).get("url-trust-gate", {})
        allowlist = _env(gate).get("URL_TRUST_GATE_CRAWLER_SSRF_ALLOWLIST", "")
        self.assertIn(
            "demo-content", allowlist,
            "the gate does not allowlist demo-content, so its SSRF guard will "
            "refuse to fetch the demo pages (they resolve to a private address) "
            "and every verdict will be ssrf_blocked -- the demo would show "
            "nothing, exactly like the file:// attempt",
        )


class TheRunnerPostsTheReachableUrl(unittest.TestCase):
    """The runner must post the DNS name the gate resolves, not the loopback
    address the operator browses to. They differ, and the wrong one fetches
    nothing from inside the container."""

    def test_the_runner_targets_the_service_name(self):
        runner = (_REPO / "scripts" / "poc" / "run_served_demo.py").read_text(encoding="utf-8")
        self.assertIn(
            "http://demo-content:8090", runner,
            "the runner does not post the demo-content SERVICE URL; if it posts "
            "127.0.0.1 the gate resolves that to itself and fetches nothing",
        )


if __name__ == "__main__":
    unittest.main()
