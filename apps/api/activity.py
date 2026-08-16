"""The Activity feed: what we did for you, in plain language.

TWO THINGS THIS FILE HAS TO GET RIGHT
=====================================

1. NEVER SHOW SOMEBODY ELSE'S EVENTS.

   Every consumer account writes into the SAME audit service under the same
   constant tenant (`aiprotect`) -- that is deliberate and correct for a
   single-user product, where one hash chain is the right shape. But it means
   the audit log is not partitioned by account, and the only thing separating
   one person's history from another's is the `agent_id` filter on the query.

   So the device ids are resolved from the SIGNED-IN ACCOUNT, server-side,
   every time. A device id from the client is never passed through to the
   audit query -- that would be a full read of every AIProtect customer's
   activity behind a parameter anyone can edit.

2. AN EMPTY FEED MUST NOT LOOK LIKE A QUIET ONE.

   "Nothing has happened" and "we could not reach the audit service" render
   identically if you let them, and the second one is the product silently
   losing its own memory. `ActivityFeed.available` keeps them apart.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.orm import Session as DbSession

import devices as dv

logger = logging.getLogger("aiprotect.activity")

AUDIT_URL = os.getenv("AIPROTECT_AUDIT_URL", "http://audit:8003")
AUDIT_SECRET = os.getenv("AUDIT_API_SECRET", "")
AUDIT_TIMEOUT_S = float(os.getenv("AIPROTECT_AUDIT_TIMEOUT_S", "4.0"))

#: How many devices we will query in one feed request. A Family plan can have
#: 30, and the audit API filters one agent_id at a time; fanning out 30 HTTP
#: calls to render a screen is its own outage. Devices are queried
#: most-recently-seen first and the cap is REPORTED, never silent -- a feed
#: that quietly omits half your devices is worse than one that says it did.
MAX_DEVICES_PER_QUERY = int(os.getenv("AIPROTECT_ACTIVITY_MAX_DEVICES", "10"))

PAGE_SIZE = 50


#: event_type -> (headline, tone). Anything unmapped renders honestly rather
#: than being dropped: an event we cannot describe still happened.
_EVENT_COPY: Dict[str, tuple[str, str]] = {
    "url.blocked": ("Blocked a dangerous link", "bad"),
    "url.warned": ("Warned you about a link", "attention"),
    "url.checked": ("Checked a link", "good"),
    "malicious_url": ("Blocked a dangerous link", "bad"),
    "phishing": ("Blocked a page trying to steal your details", "bad"),
    "prompt_injection": ("Found hidden instructions aimed at an AI", "attention"),
    "promptware": ("Found hidden instructions aimed at an AI", "attention"),
    "data_exfil": ("Stopped information going somewhere unexpected", "bad"),
    "pii.detected": ("Found personal information before you shared it", "attention"),
    "secrets.detected": ("Stopped a password or key being shared", "bad"),
    "shadow_ai": ("Noticed a new AI service being used", "good"),
    "device.enrolled": ("Added a device", "good"),
    "device.revoked": ("Removed a device", "good"),
}


@dataclass
class ActivityItem:
    id: str
    at: str
    headline: str
    tone: str
    device_name: str
    surface: Optional[str] = None
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "at": self.at,
            "headline": self.headline,
            "tone": self.tone,
            "device": self.device_name,
            "surface": self.surface,
            "detail": self.detail,
        }


@dataclass
class ActivityFeed:
    items: List[ActivityItem] = field(default_factory=list)
    #: False when the audit service could not be reached. An empty feed and a
    #: broken one are different facts and a client must be able to tell them
    #: apart -- see the header.
    available: bool = True
    #: Non-empty when the feed is incomplete for a reason the person should
    #: know about, e.g. more devices than we query in one page.
    caveats: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "items": [i.to_dict() for i in self.items],
            "available": self.available,
            "caveats": self.caveats,
        }


def _describe(event: Dict[str, Any], device_name: str) -> ActivityItem:
    event_type = str(event.get("event_type") or "")
    headline, tone = _EVENT_COPY.get(
        event_type,
        # Honest fallback. Dropping unmapped events would make the feed a
        # curated highlight reel that quietly omits whatever is newest.
        (f"Recorded a {event_type.replace('.', ' ').replace('_', ' ')} event", "good"),
    )
    evidence = event.get("evidence") or {}
    detail = ""
    if isinstance(evidence, dict):
        # Never the URL itself: the feed is rendered on a shared screen more
        # often than anyone plans for. The host is enough to recognise it.
        host = evidence.get("host") or evidence.get("domain")
        if host:
            detail = str(host)
    return ActivityItem(
        id=str(event.get("event_id") or event.get("id") or ""),
        at=str(event.get("timestamp") or ""),
        headline=headline,
        tone=tone,
        device_name=device_name,
        surface=evidence.get("surface") if isinstance(evidence, dict) else None,
        detail=detail,
    )


async def fetch(
    db: DbSession, *, subscription_id: str, limit: int = PAGE_SIZE
) -> ActivityFeed:
    """Build the feed for ONE subscription.

    The device set is resolved here, from the database, using the subscription
    of the signed-in account. Nothing about which devices to query comes from
    the caller.
    """
    owned = dv.active_devices(db, subscription_id)
    # Revoked devices still have history worth showing -- "blocked on the
    # laptop you removed last week" is a legitimate memory. But the active set
    # is what we page over first.
    owned_by_id = {d.id: d for d in owned}

    caveats: List[str] = []
    queried = sorted(
        owned, key=lambda d: (d.last_seen_at is None, d.last_seen_at), reverse=True
    )[:MAX_DEVICES_PER_QUERY]
    if len(owned) > len(queried):
        caveats.append(
            f"Showing activity from your {len(queried)} most recently used "
            f"devices out of {len(owned)}."
        )

    if not queried:
        return ActivityFeed(items=[], available=True, caveats=caveats)

    items: List[ActivityItem] = []
    reachable = False
    try:
        async with httpx.AsyncClient(timeout=AUDIT_TIMEOUT_S) as client:
            for device in queried:
                resp = await client.get(
                    f"{AUDIT_URL.rstrip('/')}/events",
                    params={"agent_id": device.id, "limit": limit},
                    headers={"x-api-key": AUDIT_SECRET},
                )
                if resp.status_code != 200:
                    continue
                reachable = True
                payload = resp.json()
                events = payload.get("events", payload) if isinstance(payload, dict) else payload
                for event in events or []:
                    # Belt and braces: the query was already scoped by
                    # agent_id, but a response is not a promise. An event
                    # attributed to a device this account does not own never
                    # reaches the feed.
                    if str(event.get("agent_id")) not in owned_by_id:
                        continue
                    items.append(_describe(event, device.name))
    except httpx.HTTPError as exc:
        logger.warning("activity_audit_unreachable err=%s", exc)
        return ActivityFeed(items=[], available=False, caveats=caveats)

    if not reachable:
        return ActivityFeed(items=[], available=False, caveats=caveats)

    items.sort(key=lambda i: i.at, reverse=True)
    return ActivityFeed(items=items[:limit], available=True, caveats=caveats)
