"""Google Safe Browsing v4 **Update API** — local hash-prefix matching.

WHY THIS EXISTS
---------------
``feeds.SafeBrowsingFeed`` used the **Lookup API**
(``v4/threatMatches:find``): one HTTPS round trip to Google per URL checked.
That is the right shape for a low-volume tool and the wrong shape here.

The URL Trust Gate is consulted on every top-level navigation
(``url_trust_gate.js``) and from the MITM proxy's Step 0. At the 800-seat pilot
scale that is on the order of 10^5 lookups a day, against a default quota
around 10^4 — and every one of them puts a customer's browsing history on
Google's wire, one URL at a time, which is its own problem for a financial
firm.

The **Update API** inverts it. Google publishes SHA-256 prefixes of the threat
lists; this client downloads them, keeps them in memory, and matches locally.
There is **no per-lookup quota, no per-lookup latency, and no per-URL
disclosure** — the only URLs that ever reach Google are the tiny fraction whose
4-byte prefix collides, and even then only the prefix is sent.

``feeds.py:12`` already anticipated this: *"cache; the interface here is shaped
to allow that drop-in."*

WHAT IS DELIBERATELY NOT HERE
-----------------------------
**Rice compression.** The API only sends Rice-encoded deltas if the client
declares support in ``supportedCompressions``. This one does not, so responses
are raw hashes. Rice would cut update bandwidth, and implementing a bit-level
decoder that is wrong in a rare case would silently corrupt a threat list —
which fails open, invisibly. Bandwidth is the cheaper thing to spend.

**On-disk persistence.** State lives in memory; a restart re-fetches a full
update. That costs one larger download per restart and removes an entire class
of "the cache on disk disagrees with the cache in memory" bug. Revisit only if
restart frequency makes the download cost real.

FAIL-OPEN, STATED PLAINLY
-------------------------
If the database has never synced, :meth:`lookup` reports **not matched, not
authoritative** — never "clean". The caller must be able to tell "checked
against 2.4M prefixes and found nothing" from "never had a list to check
against". Those are different claims and this module keeps them different.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import logging
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import httpx

logger = logging.getLogger("url_trust_gate.safebrowsing")

UPDATE_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch"
FULL_HASH_ENDPOINT = "https://safebrowsing.googleapis.com/v4/fullHashes:find"

#: The lists this client subscribes to, as (threatType, platformType).
#:
#: NOT every (threatType, platformType) pair exists. Requesting one that does
#: not gets HTTP 500 `{"message": "Could not fetch threat list updates.",
#: "status": "INTERNAL"}` for the WHOLE request -- one bad descriptor takes
#: down the other three lists with it. Measured live 2026-08-01.
#:
#: POTENTIALLY_HARMFUL_APPLICATION was in this set with ANY_PLATFORM and is the
#: reason. PHA is published only for the mobile platform types; there is no
#: ANY_PLATFORM PHA list to fetch. It is dropped rather than re-requested under
#: ANDROID: this gate scores URLs for desktop browsing, where an Android
#: application-reputation list adds nothing. Add it back with platformType
#: "ANDROID" when the mobile SDK needs it.
THREAT_LISTS: Tuple[Tuple[str, str], ...] = (
    ("MALWARE", "ANY_PLATFORM"),
    ("SOCIAL_ENGINEERING", "ANY_PLATFORM"),
    ("UNWANTED_SOFTWARE", "ANY_PLATFORM"),
)

#: Threat types this client holds lists for. Derived so the two cannot drift.
THREAT_TYPES: Tuple[str, ...] = tuple(t for t, _ in THREAT_LISTS)

_ESCAPE_BELOW = 0x20
_ESCAPE_AT_OR_ABOVE = 0x7F


# ---------------------------------------------------------------------------
# URL canonicalization  (Safe Browsing spec, "Canonicalization")
# ---------------------------------------------------------------------------
#
# Every step here exists because Google's own matcher does it, and a mismatch
# is not a cosmetic difference: an under-canonicalized URL computes a different
# SHA-256 and MISSES a listed threat. The failure is silent and always in the
# unsafe direction, which is why this is implemented against the published test
# vectors rather than by eyeballing.


def _strip_control_chars(url: str) -> str:
    """Remove tab, CR and LF anywhere in the URL. Spec step 1."""
    return url.replace("\t", "").replace("\r", "").replace("\n", "")


def _unescape_repeatedly(value: str) -> str:
    """Percent-unescape until it stops changing.

    ``%25%32%35`` unescapes to ``%25`` and then to ``%``. A single pass leaves
    an attacker one layer of encoding to hide behind.
    """
    for _ in range(64):  # bounded: a pathological input must not spin
        unquoted = urllib.parse.unquote(value)
        if unquoted == value:
            return value
        value = unquoted
    return value


def _canonical_host(host: str) -> str:
    """Lowercase, strip stray dots, and normalise every integer IP form."""
    host = host.strip().lower().strip(".")
    host = re.sub(r"\.{2,}", ".", host)
    if not host:
        return ""

    # 3279880203 -> 195.127.0.11, and the octal/hex dotted forms too. Attackers
    # use these precisely because a naive matcher treats them as new hosts.
    try:
        if re.fullmatch(r"\d+", host):
            return str(ipaddress.IPv4Address(int(host)))
        if re.fullmatch(r"(0x[0-9a-f]+|0[0-7]*|\d+)(\.(0x[0-9a-f]+|0[0-7]*|\d+)){3}", host):
            parts = []
            for chunk in host.split("."):
                if chunk.startswith("0x"):
                    parts.append(int(chunk, 16))
                elif chunk.startswith("0") and len(chunk) > 1:
                    parts.append(int(chunk, 8))
                else:
                    parts.append(int(chunk))
            if all(0 <= p <= 255 for p in parts):
                return ".".join(str(p) for p in parts)
    except (ValueError, ipaddress.AddressValueError):
        pass
    return host


def _canonical_path(path: str) -> str:
    """Resolve ``/./`` and ``/../``, collapse ``//``. Spec step 3."""
    if not path:
        return "/"
    out: List[str] = []
    for segment in path.split("/"):
        if segment == ".":
            continue
        if segment == "..":
            if out:
                out.pop()
            continue
        out.append(segment)
    resolved = "/".join(out)
    if not resolved.startswith("/"):
        resolved = "/" + resolved
    resolved = re.sub(r"/{2,}", "/", resolved)
    if path.endswith(("/.", "/..")) and not resolved.endswith("/"):
        resolved += "/"
    return resolved or "/"


def _percent_escape(value: str) -> str:
    """Escape <0x20, >=0x7f, ``#`` and ``%``. Spec step 4."""
    out: List[str] = []
    for ch in value:
        code = ord(ch)
        if code < _ESCAPE_BELOW or code >= _ESCAPE_AT_OR_ABOVE or ch in "#%":
            out.extend(f"%{b:02X}" for b in ch.encode("utf-8"))
        else:
            out.append(ch)
    return "".join(out)


def canonicalize(url: str) -> str:
    """The Safe Browsing canonical form of ``url``."""
    url = _strip_control_chars(url).strip()
    url = url.split("#", 1)[0]  # fragment is never part of the match

    if "://" not in url:
        url = "http://" + url

    scheme, _, remainder = url.partition("://")
    scheme = scheme.lower()

    authority, slash, rest = remainder.partition("/")
    path_and_query = (slash + rest) if slash else "/"

    # userinfo is not matched on
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]

    port = ""
    if authority.startswith("["):  # IPv6 literal
        host, _, tail = authority.partition("]")
        host += "]"
        if tail.startswith(":"):
            port = tail
    elif ":" in authority:
        authority, _, port = authority.partition(":")
        port = ":" + port
        host = authority
    else:
        host = authority

    host = _canonical_host(_unescape_repeatedly(host))

    path, _, query = path_and_query.partition("?")
    path = _canonical_path(_unescape_repeatedly(path))

    canonical = f"{scheme}://{_percent_escape(host)}{_percent_escape(path)}"
    if _:
        canonical += "?" + _percent_escape(_unescape_repeatedly(query))
    return canonical


# ---------------------------------------------------------------------------
# Expression generation  (Safe Browsing spec, "Suffix/Prefix Expressions")
# ---------------------------------------------------------------------------


def host_suffixes(host: str) -> List[str]:
    """Up to 5 host candidates: the exact host, then parent domains.

    A listed entry may cover ``evil.com`` while the visited host is
    ``a.b.evil.com``; without the parents that match is missed.
    """
    try:
        ipaddress.ip_address(host.strip("[]"))
        return [host]  # an IP has no parent domains
    except ValueError:
        pass

    labels = host.split(".")
    out = [host]
    # Spec: "the exact hostname; up to four hostnames formed by starting with
    # the LAST FIVE COMPONENTS and successively removing the leading
    # component." The last-five entry is itself one of the four -- starting the
    # range one past it drops c.d.e.f.g for a.b.c.d.e.f.g, which is a real miss:
    # a threat listed on that parent would not match.
    # `len(labels) - 1` stops before the bare TLD.
    start = max(0, len(labels) - 5)
    for i in range(start, len(labels) - 1):
        candidate = ".".join(labels[i:])
        if candidate not in out:
            out.append(candidate)
    return out[:5]


def path_prefixes(path: str, query: Optional[str]) -> List[str]:
    """Up to 6 path candidates: exact (with and without query), then prefixes."""
    out: List[str] = []
    if query is not None:
        out.append(f"{path}?{query}")
    out.append(path)

    out.append("/")

    # DIRECTORY components only. The spec's own worked example for
    # `http://a.b.c/1/2.html?param=1` lists exactly four path candidates --
    # `/1/2.html?param=1`, `/1/2.html`, `/`, `/1/` -- and NOT `/1/2.html/`.
    # Including the final component when the path names a file invents an
    # expression Google never hashes: harmless for matching (it just never
    # hits) but it inflates every lookup and would quietly drift from the spec.
    segments = [s for s in path.split("/") if s]
    if not path.endswith("/"):
        segments = segments[:-1]
    accumulated = ""
    for segment in segments[:3]:  # 3 + the root above = the 4 the spec allows
        accumulated += "/" + segment
        candidate = accumulated + "/"
        if candidate not in out:
            out.append(candidate)

    deduped: List[str] = []
    for candidate in out:
        if candidate not in deduped:
            deduped.append(candidate)
    return deduped[:6]


def url_expressions(url: str) -> List[str]:
    """Every host/path combination Safe Browsing would hash. At most 30."""
    canonical = canonicalize(url)
    _, _, remainder = canonical.partition("://")
    authority, slash, rest = remainder.partition("/")
    path_and_query = (slash + rest) if slash else "/"
    path, sep, query = path_and_query.partition("?")

    expressions: List[str] = []
    for host in host_suffixes(authority):
        for suffix in path_prefixes(path or "/", query if sep else None):
            expression = f"{host}{suffix}"
            if expression not in expressions:
                expressions.append(expression)
    return expressions[:30]


def expression_hashes(url: str) -> List[bytes]:
    """Full SHA-256 of every expression for ``url``."""
    return [hashlib.sha256(e.encode("utf-8")).digest() for e in url_expressions(url)]


# ---------------------------------------------------------------------------
# The local database
# ---------------------------------------------------------------------------


@dataclass
class _ListState:
    """One threat list: its prefixes and the state token for the next update."""

    threat_type: str
    prefixes: Set[bytes] = field(default_factory=set)
    state: str = ""
    prefix_sizes: Set[int] = field(default_factory=set)


@dataclass
class LocalMatch:
    threat_type: str
    prefix: bytes
    expression_hash: bytes


class SafeBrowsingDatabase:
    """Threat-list prefixes held in memory, matched locally.

    ``synced`` is the honest bit. Until a fetch has succeeded this database has
    nothing to match against, and every caller must be able to tell that from a
    genuine miss.
    """

    def __init__(self) -> None:
        self._lists: Dict[str, _ListState] = {
            t: _ListState(threat_type=t) for t in THREAT_TYPES
        }
        self.last_sync_at: Optional[float] = None
        self.last_error: Optional[str] = None

    @property
    def synced(self) -> bool:
        return self.last_sync_at is not None

    @property
    def prefix_count(self) -> int:
        return sum(len(s.prefixes) for s in self._lists.values())

    def states(self) -> Dict[str, str]:
        return {name: s.state for name, s in self._lists.items()}

    def apply_update(self, threat_type: str, response: dict) -> None:
        """Apply one ``listUpdateResponse``."""
        state = self._lists.setdefault(threat_type, _ListState(threat_type))

        if (response.get("responseType") or "").upper() == "FULL_UPDATE":
            state.prefixes = set()
            state.prefix_sizes = set()

        # Removals are INDICES INTO THE SORTED prefix list, so the ordering
        # Google assumes has to be reproduced exactly. Applying them against an
        # unsorted set would delete the wrong entries -- silently, and always
        # by leaving a threat unlisted.
        removals: List[int] = []
        for removal in response.get("removals") or []:
            removals.extend((removal.get("rawIndices") or {}).get("indices") or [])
        if removals:
            ordered = sorted(state.prefixes)
            drop = {ordered[i] for i in removals if 0 <= i < len(ordered)}
            state.prefixes -= drop

        for addition in response.get("additions") or []:
            raw = addition.get("rawHashes") or {}
            size = int(raw.get("prefixSize") or 4)
            blob = raw.get("rawHashes") or ""
            if not blob:
                continue
            data = base64.b64decode(blob)
            if size <= 0 or len(data) % size:
                logger.warning(
                    "safebrowsing_malformed_addition threat=%s prefix_size=%s bytes=%d "
                    "-- skipped; this list is now INCOMPLETE",
                    threat_type, size, len(data),
                )
                continue
            state.prefix_sizes.add(size)
            for offset in range(0, len(data), size):
                state.prefixes.add(data[offset:offset + size])

        new_state = response.get("newClientState")
        if new_state:
            state.state = new_state

    def lookup(self, url: str) -> Tuple[List[LocalMatch], bool]:
        """``(matches, authoritative)`` for ``url``.

        ``authoritative`` is False when nothing has ever been downloaded. An
        empty match list then means "we could not check", NOT "clean", and a
        caller that conflates them is reporting a pass for a check that never
        ran.
        """
        if not self.synced:
            return [], False

        hashes = expression_hashes(url)
        matches: List[LocalMatch] = []
        for name, state in self._lists.items():
            if not state.prefixes:
                continue
            sizes = state.prefix_sizes or {4}
            for full in hashes:
                for size in sizes:
                    candidate = full[:size]
                    if candidate in state.prefixes:
                        matches.append(
                            LocalMatch(threat_type=name, prefix=candidate,
                                       expression_hash=full)
                        )
                        break
        return matches, True


# ---------------------------------------------------------------------------
# The update client
# ---------------------------------------------------------------------------


class SafeBrowsingUpdateClient:
    """Keeps a :class:`SafeBrowsingDatabase` current and confirms prefix hits."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        client_id: str = "cyberarmor-url-trust-gate",
        client_version: str = "0.1.0",
        timeout_s: float = 30.0,
    ) -> None:
        self._api_key = api_key or os.getenv("SAFE_BROWSING_API_KEY", "")
        self._client_id = client_id
        self._client_version = client_version
        self._timeout_s = timeout_s
        self.db = SafeBrowsingDatabase()
        #: Google tells us the soonest it will accept another fetch. Ignoring it
        #: gets the key rate-limited, which takes the whole feed offline.
        self.minimum_wait_until: float = 0.0
        self._full_hash_cache: Dict[bytes, Tuple[List[str], float]] = {}

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    def _client_block(self) -> dict:
        return {"clientId": self._client_id, "clientVersion": self._client_version}

    def _auth_headers(self) -> dict:
        """The API key as a HEADER, never as a query parameter.

        `?key=<secret>` leaks. httpx logs the full request URL at INFO, so the
        first deploy of this module wrote a live Safe Browsing key into
        `docker logs` in plaintext -- and from there into any log shipper,
        screenshot or paste of those logs. Measured 2026-08-01; that key had to
        be rotated.

        Google APIs accept `X-Goog-Api-Key` for exactly this reason. A secret
        in a header is not logged by anything that logs URLs, and there is no
        situation where the query-parameter form is worth the exposure.
        """
        return {"X-Goog-Api-Key": self._api_key}

    async def sync(self, client: Optional[httpx.AsyncClient] = None) -> bool:
        """Fetch and apply one round of list updates. True if applied."""
        if not self._api_key:
            return False
        if time.monotonic() < self.minimum_wait_until:
            return False

        requests = []
        for threat_type, platform_type in THREAT_LISTS:
            entry = {
                "threatType": threat_type,
                "platformType": platform_type,
                "threatEntryType": "URL",
                # supportedCompressions is declared EXPLICITLY rather than
                # omitted. Naming RAW states exactly what this client can
                # decode; claiming RICE without a decoder would corrupt a
                # threat list silently, and that failure is fail-open.
                "constraints": {"supportedCompressions": ["RAW"]},
            }
            # `state` is OMITTED on the first fetch, not sent as "". The field
            # is an opaque resume token; an empty string is a value, not an
            # absence, and sending one asks the server to resume from a state
            # it never issued.
            state = self.db.states().get(threat_type, "")
            if state:
                entry["state"] = state
            requests.append(entry)
        body = {"client": self._client_block(), "listUpdateRequests": requests}

        owns_client = client is None
        client = client or httpx.AsyncClient(timeout=self._timeout_s, trust_env=False)
        try:
            resp = await client.post(UPDATE_ENDPOINT, json=body, headers=self._auth_headers())
            if resp.status_code != 200:
                self.db.last_error = f"HTTP {resp.status_code}"
                # The body on one line: Google's error JSON is pretty-printed,
                # and a multi-line log entry is the one shape an operator
                # grepping for "safebrowsing" will only see the first line of.
                detail = " ".join((resp.text or "")[:400].split())
                logger.warning(
                    "safebrowsing_update_failed status=%s detail=%s -- the "
                    "local threat list is now STALE, not empty; lookups still "
                    "match whatever was last downloaded",
                    resp.status_code, detail,
                )
                return False

            data = resp.json() or {}
            for entry in data.get("listUpdateResponses") or []:
                threat_type = entry.get("threatType") or ""
                if threat_type:
                    self.db.apply_update(threat_type, entry)

            wait = str(data.get("minimumWaitDuration") or "").rstrip("s")
            try:
                self.minimum_wait_until = time.monotonic() + float(wait or 0)
            except ValueError:
                self.minimum_wait_until = time.monotonic() + 1800.0

            self.db.last_sync_at = time.time()
            self.db.last_error = None
            logger.info(
                "safebrowsing_synced prefixes=%d lists=%d next_fetch_in_s=%.0f",
                self.db.prefix_count, len(THREAT_TYPES),
                max(0.0, self.minimum_wait_until - time.monotonic()),
            )
            return True
        except Exception as exc:
            self.db.last_error = f"{type(exc).__name__}: {exc}"
            logger.warning("safebrowsing_update_unreachable err=%s", exc)
            return False
        finally:
            if owns_client:
                await client.aclose()

    async def confirm(
        self, matches: Sequence[LocalMatch], client: Optional[httpx.AsyncClient] = None
    ) -> List[str]:
        """Confirm prefix hits against Google. Returns matched threat types.

        A 4-byte prefix collides roughly once in 4 billion, so this runs on a
        vanishingly small share of traffic -- and only the PREFIX is sent, never
        the URL. That is the privacy property the Lookup API cannot offer.
        """
        if not matches or not self._api_key:
            return []

        now = time.monotonic()
        confirmed: List[str] = []
        unknown: List[LocalMatch] = []
        for m in matches:
            cached = self._full_hash_cache.get(m.expression_hash)
            if cached and cached[1] > now:
                confirmed.extend(cached[0])
            else:
                unknown.append(m)
        if not unknown:
            return sorted(set(confirmed))

        prefixes = sorted({m.prefix for m in unknown})
        body = {
            "client": self._client_block(),
            "clientStates": [s for s in self.db.states().values() if s],
            "threatInfo": {
                "threatTypes": list(THREAT_TYPES),
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"hash": base64.b64encode(p).decode("ascii")} for p in prefixes
                ],
            },
        }

        owns_client = client is None
        client = client or httpx.AsyncClient(timeout=5.0, trust_env=False)
        try:
            resp = await client.post(FULL_HASH_ENDPOINT, json=body, headers=self._auth_headers())
            if resp.status_code != 200:
                logger.warning(
                    "safebrowsing_fullhash_failed status=%s -- a prefix matched "
                    "and could NOT be confirmed; reported as unconfirmed rather "
                    "than as either safe or malicious",
                    resp.status_code,
                )
                return []
            data = resp.json() or {}
            wanted = {m.expression_hash for m in unknown}
            for match in data.get("matches") or []:
                raw = match.get("threat", {}).get("hash")
                if not raw:
                    continue
                full = base64.b64decode(raw)
                if full in wanted:
                    threat = match.get("threatType") or ""
                    if threat:
                        confirmed.append(threat)
                        ttl = str(match.get("cacheDuration") or "300").rstrip("s")
                        try:
                            expiry = now + float(ttl)
                        except ValueError:
                            expiry = now + 300.0
                        prior = self._full_hash_cache.get(full, ([], 0.0))[0]
                        self._full_hash_cache[full] = (
                            sorted(set(prior + [threat])), expiry,
                        )
            return sorted(set(confirmed))
        except Exception as exc:
            logger.warning("safebrowsing_fullhash_unreachable err=%s", exc)
            return []
        finally:
            if owns_client:
                await client.aclose()
