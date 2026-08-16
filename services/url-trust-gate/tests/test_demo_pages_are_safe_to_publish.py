"""If the demo pages are served publicly, they must not be real phishing.

The founder chose to publish these for the URL Trust Gate demo. That is a
legitimate, common practice for security tooling (EICAR, testsafebrowsing,
WICAR) -- BUT only for INERT, clearly-labelled fixtures. A page that
impersonates a real brand with a working credential form, hosted on the product
domain, could get that domain flagged by Safe Browsing and could function as
real phishing if the disclaimer were stripped.

So the safety properties are pinned here, because "add a disclaimer" is a
one-time intention and this is what keeps it true:

  * no REAL brand name appears (fictional Contoso/Fabrikam only -- names
    reserved for exactly this), so no real brand is impersonated and no
    blocklist has a real brand to match;
  * every page is noindex,nofollow so it is not crawled into search;
  * every page carries a visible disclaimer banner, not a buried footer;
  * every form target is INERT -- a relative path this static host 404s, or a
    .test hostname that by RFC 6761 never resolves -- so nothing can ever be
    collected or transmitted.

Detection is unaffected by the fictional brands: these pages are caught by the
credential-form heuristic and the prompt-injection ML classifier, not by the
real-brand keyword list (measured on the box 2026-08-14 -- the brand page
scored prompt_injection=1.00, never brand_impersonation).
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_PAGES = Path(__file__).resolve().parents[3] / "scripts" / "poc" / "test-pages"

#: The real-brand keywords the detector matches (extractors.py _BRAND_KEYWORDS),
#: plus a couple of common impersonation targets. None may appear in a page we
#: publish -- impersonating any of these for real is the risk being avoided.
_REAL_BRANDS = (
    "microsoft", "office365", "google", "okta", "duo", "github",
    "salesforce", "docusign", "adobe", "paypal", "apple", "amazon",
    "netflix", "chase", "wells fargo", "bank of america",
)

_HTML = sorted(_PAGES.glob("*.html"))


class NoRealBrandIsImpersonated(unittest.TestCase):

    def test_no_page_names_a_real_brand(self):
        for page in _HTML:
            text = page.read_text(encoding="utf-8").lower()
            for brand in _REAL_BRANDS:
                with self.subTest(page=page.name, brand=brand):
                    self.assertNotIn(
                        brand, text,
                        f"{page.name} contains the real brand {brand!r}. Publicly "
                        f"hosting a page that impersonates a real brand can get "
                        f"the domain blocklisted and could function as real "
                        f"phishing. Use a fictional brand (Contoso/Fabrikam).",
                    )


class EveryPageIsLabelledAndUnindexed(unittest.TestCase):

    def test_every_page_is_noindex(self):
        for page in _HTML:
            with self.subTest(page=page.name):
                self.assertRegex(
                    page.read_text(encoding="utf-8"),
                    r'name=["\']robots["\']\s+content=["\'][^"\']*noindex',
                    f"{page.name} is missing a noindex robots meta; a published "
                    f"phishing-shaped page must not be indexed",
                )

    def test_the_risky_pages_carry_a_visible_disclaimer(self):
        # The pages with a credential form are the ones that must announce
        # themselves loudly. The benign/injection pages get one too, but these
        # are the non-negotiable ones.
        for name in ("credential-harvest.html", "brand-impersonation.html"):
            with self.subTest(page=name):
                text = (_PAGES / name).read_text(encoding="utf-8")
                self.assertIn("ca-disclaimer", text,
                              f"{name} has no disclaimer banner")
                self.assertIn("TEST FIXTURE", text.upper(),
                              f"{name}'s disclaimer does not say it is a test")


class EveryFormTargetIsInert(unittest.TestCase):
    """A credential form that can actually POST somewhere is the line between a
    test fixture and a phishing kit."""

    _ACTION = re.compile(r'<form[^>]*\baction=["\']([^"\']*)["\']', re.I)

    def test_no_form_posts_to_a_resolvable_endpoint(self):
        for page in _HTML:
            for action in self._ACTION.findall(page.read_text(encoding="utf-8")):
                with self.subTest(page=page.name, action=action):
                    inert = (
                        action.startswith("/")                      # relative; host 404s
                        or ".test/" in action or action.endswith(".test")  # RFC 6761
                        or action.startswith("#")
                        or action == ""
                    )
                    self.assertTrue(
                        inert,
                        f"{page.name} posts to {action!r}, which may resolve. A "
                        f"published credential form must post nowhere real -- use "
                        f"a relative path or a .test hostname.",
                    )


if __name__ == "__main__":
    unittest.main()
