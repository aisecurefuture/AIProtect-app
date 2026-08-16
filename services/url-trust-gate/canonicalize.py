"""URL canonicalisation + querystring sensitivity classification.

Done before any network I/O so we have a stable cache key, a redacted
form for logging, and an early signal for homoglyph / punycode abuse.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit

# Querystring keys that almost always carry sensitive values. We REDACT
# these in evidence + logs but keep the key so detection patterns that
# rely on key names (e.g. "?token=" → suspicious for AI agents) still fire.
_SENSITIVE_KEY_PATTERNS = [
    re.compile(r"^(token|access_token|id_token|refresh_token|api_key|apikey)$", re.I),
    re.compile(r"^(session|sessionid|sid|jwt|bearer)$", re.I),
    re.compile(r"^(password|passwd|pwd|secret)$", re.I),
    re.compile(r"^(email|e[-_]?mail|user|username|login)$", re.I),
    re.compile(r"^(phone|mobile|ssn|dob|address)$", re.I),
    re.compile(r"^(card|cc|cvv|account)$", re.I),
]


@dataclass
class CanonicalUrl:
    url: str  # canonical form, with original querystring values intact
    scheme: str
    host: str
    port: int | None
    path: str
    query_params: List[Tuple[str, str]]
    fragment: str
    # SHA-256 of (scheme + host + path + sorted(non-sensitive querystring
    # keys)). Stable cache/evidence key that does NOT include sensitive
    # values, so identical URLs with rotating session tokens collapse to
    # the same fingerprint.
    fingerprint: str = ""
    homoglyph_suspected: bool = False
    punycode_decoded_host: str | None = None

    def redacted_url(self, sensitivity: Dict[str, bool]) -> str:
        """Return the canonical URL with sensitive querystring values redacted."""
        redacted_pairs: List[str] = []
        for key, value in self.query_params:
            if sensitivity.get(key, False):
                redacted_pairs.append(f"{quote(key)}=__REDACTED__")
            else:
                redacted_pairs.append(f"{quote(key)}={quote(value)}")
        netloc = self.host if self.port is None else f"{self.host}:{self.port}"
        return urlunsplit(
            (self.scheme, netloc, self.path, "&".join(redacted_pairs), "")
        )


def canonicalize_url(raw: str) -> CanonicalUrl:
    """Normalise a URL into a stable canonical form.

    The canonical form:
      - lowercases scheme and host
      - strips default ports (80 for http, 443 for https)
      - decodes punycode for IDN homoglyph detection
      - removes fragment from the cache key (kept on the object for evidence)
      - preserves querystring order (some sites are order-sensitive)
    """

    # urlsplit handles userinfo, IPv6, etc. correctly.
    parts = urlsplit(raw.strip())
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    port = parts.port

    if scheme == "http" and port == 80:
        port = None
    if scheme == "https" and port == 443:
        port = None

    # Decode punycode for homoglyph inspection. We keep the encoded form
    # in `host` (browsers will use that) but flag if the decoded form
    # contains mixed-script characters that visually mimic ASCII.
    decoded_host = None
    homoglyph = False
    if host.startswith("xn--") or "xn--" in host:
        try:
            decoded_host = host.encode("ascii").decode("idna")
            homoglyph = _looks_homoglyph(decoded_host)
        except Exception:
            decoded_host = None

    # Path normalisation. We don't collapse `..` or `//` because some apps
    # are sensitive to that; we just unquote+requote to a stable encoding.
    path = parts.path or "/"
    try:
        path = quote(unquote(path), safe="/%:@!$&'()*+,;=-._~")
    except Exception:
        pass

    query_params = parse_qsl(parts.query, keep_blank_values=True)

    fp_input = f"{scheme}|{host}|{port or ''}|{path}|" + ",".join(
        sorted(k for k, _ in query_params)
    )
    fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

    netloc = host if port is None else f"{host}:{port}"
    canonical = urlunsplit((scheme, netloc, path, parts.query, parts.fragment or ""))

    return CanonicalUrl(
        url=canonical,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query_params=query_params,
        fragment=parts.fragment or "",
        fingerprint=fingerprint,
        homoglyph_suspected=homoglyph,
        punycode_decoded_host=decoded_host,
    )


def classify_querystring_sensitivity(
    params: List[Tuple[str, str]],
) -> Dict[str, bool]:
    """Return {key: is_sensitive} for each querystring key.

    Sensitivity is determined by name, not value. We never inspect values
    here — value-based PII detection is the detection service's job.
    """

    out: Dict[str, bool] = {}
    for key, _ in params:
        out[key] = any(p.search(key) for p in _SENSITIVE_KEY_PATTERNS)
    return out


def _looks_homoglyph(decoded: str) -> bool:
    """Cheap heuristic: True if the decoded IDN mixes scripts.

    Real homoglyph detection needs Unicode confusables tables (TR39). For
    the scaffold we just flag mixed-script labels, which catches the most
    common "аpple.com" (Cyrillic 'а') style attacks without dependencies.
    """

    has_latin = False
    has_non_latin = False
    for ch in decoded:
        if ch.isascii() and ch.isalpha():
            has_latin = True
        elif ch.isalpha():
            has_non_latin = True
        if has_latin and has_non_latin:
            return True
    return False
