"""Signal extraction from crawl + detonation artefacts.

The detection service does the ML-heavy lifting; this module's job is to
pull cheap, deterministic signals out of fetched content so we can:
  - score baseline risk even when detection is unreachable,
  - decide what subset of detection endpoints to call,
  - emit IOCs for the evidence layer.

Every extractor here MUST be deterministic and side-effect free.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from canonicalize import CanonicalUrl
    from crawler import CrawlResult
    from detonation import DetonationResult
    from main import IOC

# Cheap regex IOCs. Detection layer does the real work; these are just
# enough to produce a useful evidence record without a round-trip.
_RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_RE_BTC = re.compile(r"\b(?:bc1|[13])[A-HJ-NP-Za-km-z1-9]{25,39}\b")
_RE_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Brand keywords used in phishing kits. Real implementation should use a
# tenant-configurable list + ML brand classifier; this is just the
# scaffold's dumb heuristic.
_BRAND_KEYWORDS = (
    "microsoft",
    "office365",
    "google",
    "okta",
    "duo",
    "github",
    "salesforce",
    "docusign",
    "adobe",
    "paypal",
)

# Words that often co-occur with credential harvesting forms.
_CRED_KEYWORDS = (
    "sign in",
    "log in",
    "verify your account",
    "verify your identity",
    "session expired",
    "re-authenticate",
)

# HTML markup stripped from text_for_ml before it reaches the ML classifier
# (services/detection's /scan). Confirmed live against a real false
# positive: protectai/deberta-v3-base-prompt-injection-v2 scored plain
# example.com markup at 99.97% confidence "prompt injection" -- raw HTML
# (tags, CSS, attributes) is badly out-of-distribution for a model tuned on
# chat-style prompts. The same content stripped to visible text scored 0.
#
# Comments are handled specially -- unwrapped (content kept, delimiters
# dropped) rather than deleted like every other tag. This is deliberate,
# not an oversight: detonation.py's hidden-text capture (deep mode) comes
# from a rendered browser DOM, and a rendering engine never exposes HTML
# comment nodes as text at all -- not as visible_text, not as
# hidden_text/css_hidden_text/unicode_hidden_text. For standard/fast-depth
# crawls (no detonation), this raw-text path is the ONLY place a
# comment-hidden prompt-injection payload could ever be seen. Stripping
# comments outright would silently remove that coverage; unwrapping them
# keeps the payload in text_for_ml while still cutting the markup noise
# that caused the false positive.
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_HTML_STYLE_SCRIPT_RE = re.compile(r"<(style|script)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


def _clean_html_for_ml(raw: str, content_type: str) -> str:
    if "html" not in (content_type or "").lower():
        return raw
    text = _HTML_COMMENT_RE.sub(r" \1 ", raw)  # unwrap, don't delete -- see note above
    text = _HTML_STYLE_SCRIPT_RE.sub(" ", text)  # code, not natural-language signal
    text = _HTML_TAG_RE.sub(" ", text)
    return _WHITESPACE_RE.sub(" ", text).strip()


@dataclass
class ExtractedSignals:
    text_for_ml: str = ""
    has_credential_form: bool = False
    has_brand_impersonation_keywords: bool = False
    hidden_text_blocks: List[str] = field(default_factory=list)
    iocs: List["IOC"] = field(default_factory=list)
    # Free-form notes, surfaced into evidence and the dashboard "why"
    # explainer. Keep these short and human-readable.
    notes: List[str] = field(default_factory=list)


def extract_signals(
    *,
    canonical: "CanonicalUrl",
    crawl: Optional["CrawlResult"],
    detonation: Optional["DetonationResult"],
) -> ExtractedSignals:
    from main import IOC  # local import to avoid cycle

    out = ExtractedSignals()

    # ---- URL-level signals (always available) -----------------------------
    if canonical.homoglyph_suspected:
        out.notes.append(
            f"homoglyph_suspected punycode={canonical.punycode_decoded_host}"
        )
        out.iocs.append(
            IOC(
                kind="domain",
                value=canonical.host,
                confidence=0.6,
                source="homoglyph",
            )
        )

    # ---- Crawl-level signals ----------------------------------------------
    if crawl is not None and crawl.content_bytes:
        # Decode best-effort. The detection service is the authoritative
        # text extractor; we do a cheap pass for heuristics + IOC scrape.
        # `text` stays raw (with tags) for _looks_like_form()'s regex, which
        # needs real <form>/<input> markup to match. Only what goes to the
        # ML classifier gets cleaned -- see _clean_html_for_ml's docstring.
        text = _decode_text(crawl.content_bytes, crawl.content_type)
        cleaned = _clean_html_for_ml(text, crawl.content_type)
        out.text_for_ml = cleaned[:64_000]  # cap to avoid blowing detection input

        lower = text.lower()
        if any(k in lower for k in _CRED_KEYWORDS) and _looks_like_form(text):
            out.has_credential_form = True
        if any(k in lower for k in _BRAND_KEYWORDS):
            out.has_brand_impersonation_keywords = True

        out.iocs.extend(_scrape_iocs(text))

    # ---- Detonation-level signals -----------------------------------------
    if detonation is not None:
        # Hidden text is the highest-signal artefact for promptware.
        for block in (
            detonation.hidden_text,
            detonation.css_hidden_text,
            detonation.unicode_hidden_text,
        ):
            if block and block.strip():
                out.hidden_text_blocks.append(block)

        # Append rendered visible text to ML input — JS-rendered SPAs are
        # invisible to the safe crawler.
        if detonation.visible_text:
            out.text_for_ml = (
                (out.text_for_ml + "\n" + detonation.visible_text)[:64_000]
            )

        if detonation.forms:
            for form in detonation.forms:
                # Any password input on a non-corporate domain is a strong
                # credential-harvest signal. The corporate-domain check is
                # tenant-policy-driven and lives in the policy service.
                inputs = form.get("inputs", []) if isinstance(form, dict) else []
                if any(
                    (i.get("type") or "").lower() == "password" for i in inputs
                ):
                    out.has_credential_form = True
                    break

    return out


def _decode_text(body: bytes, content_type: str) -> str:
    # Pull charset out of content-type; fall back to utf-8 with replacement.
    charset = "utf-8"
    if "charset=" in content_type.lower():
        try:
            charset = content_type.lower().split("charset=", 1)[1].split(";")[0].strip()
        except Exception:
            charset = "utf-8"
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


_FORM_RE = re.compile(r"<form\b", re.IGNORECASE)
_PASSWORD_RE = re.compile(
    r"<input\b[^>]*type=[\"']?password[\"']?", re.IGNORECASE
)


def _looks_like_form(html: str) -> bool:
    return bool(_FORM_RE.search(html) and _PASSWORD_RE.search(html))


def _scrape_iocs(text: str) -> List["IOC"]:
    from main import IOC

    iocs: List[IOC] = []
    for m in _RE_EMAIL.finditer(text):
        iocs.append(IOC(kind="email", value=m.group(0), confidence=0.3, source="regex"))
    for m in _RE_BTC.finditer(text):
        iocs.append(IOC(kind="wallet", value=m.group(0), confidence=0.5, source="regex"))
    for m in _RE_ETH.finditer(text):
        iocs.append(IOC(kind="wallet", value=m.group(0), confidence=0.5, source="regex"))
    for m in _RE_IPV4.finditer(text):
        iocs.append(IOC(kind="ip", value=m.group(0), confidence=0.2, source="regex"))
    # De-dup while preserving order.
    seen = set()
    deduped: List[IOC] = []
    for i in iocs:
        key = (i.kind, i.value)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(i)
    return deduped[:50]  # hard cap so a junk page can't blow the evidence record
