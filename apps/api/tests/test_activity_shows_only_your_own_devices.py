"""The Activity feed must never show one customer another customer's history.

THE HAZARD, AND WHY IT IS NOT OBVIOUS
====================================
Every consumer account writes into the SAME audit service under the same
constant tenant (`aiprotect`). That is deliberate and right for a single-user
product -- one hash chain is the correct shape, and the audit service's
UniqueConstraint("tenant_id","prev_event_id") degenerates rather than breaking.

But it means the audit log is NOT partitioned by account. The only thing
standing between one person's history and everybody's is the `agent_id` filter
on the query. So:

  * the device set is resolved from the SIGNED-IN ACCOUNT, server-side
  * a device id from the caller is never passed through to the audit query
  * and the response is filtered again on the way back, because a query being
    scoped is not the same as a response being trustworthy

An `agent_id` accepted from the client would be a full read of every AIProtect
customer's activity, behind a parameter anyone can edit.

SECOND PROPERTY: an empty feed and a broken one must not look the same. "You
have had a quiet week" and "we cannot reach our own audit log" render
identically if you let them.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

API = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(API))

import httpx  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

import activity  # noqa: E402
import devices as dv  # noqa: E402
import entitlements as ent  # noqa: E402
from models import Account, Base, Subscription  # noqa: E402


def _db():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _subscription(db, email, tier="personal"):
    acct = Account(email=email)
    db.add(acct)
    db.flush()
    sub = Subscription(owner_account_id=acct.id, tier=tier, state=ent.ACTIVE)
    db.add(sub)
    db.flush()
    return sub


def _event(agent_id, event_type="url.blocked", evt_id="evt_1"):
    return {
        "event_id": evt_id,
        "agent_id": agent_id,
        "event_type": event_type,
        "timestamp": "2026-08-16T10:00:00Z",
        "evidence": {"host": "phish.example"},
    }


class _FakeAudit:
    """Stands in for the audit service, and records what it was ASKED.

    The questions matter as much as the answers here: the test asserts on the
    agent_ids that reached the query, because that is where the isolation
    actually lives.
    """

    def __init__(self, by_agent, status=200):
        self.by_agent = by_agent
        self.status = status
        self.asked = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, params=None, headers=None):
        agent = (params or {}).get("agent_id")
        self.asked.append(agent)
        return httpx.Response(
            self.status, json={"events": self.by_agent.get(agent, [])}
        )


def _run(coro):
    import asyncio
    return asyncio.run(coro)


class TheFeedIsScopedToTheAccount(unittest.TestCase):
    def test_only_your_own_devices_are_queried(self):
        """THE CORE PROPERTY."""
        db = _db()
        mine = _subscription(db, "mine@example.com")
        theirs = _subscription(db, "theirs@example.com")

        my_device = dv.enroll_device(
            db, subscription=mine, name="My phone", surface_kind="mobile-app"
        ).device
        their_device = dv.enroll_device(
            db, subscription=theirs, name="Their phone", surface_kind="mobile-app"
        ).device

        fake = _FakeAudit({
            my_device.id: [_event(my_device.id, evt_id="mine")],
            their_device.id: [_event(their_device.id, evt_id="theirs")],
        })
        with mock.patch.object(activity.httpx, "AsyncClient", return_value=fake):
            feed = _run(activity.fetch(db, subscription_id=mine.id))

        self.assertEqual(fake.asked, [my_device.id])
        self.assertNotIn(their_device.id, fake.asked)
        self.assertEqual([i.id for i in feed.items], ["mine"])

    def test_a_stray_event_in_the_response_is_dropped(self):
        """Belt and braces. The query was scoped, but a response is not a
        promise -- a bug or a compromise upstream must not become a leak."""
        db = _db()
        mine = _subscription(db, "mine@example.com")
        theirs = _subscription(db, "theirs@example.com")
        my_device = dv.enroll_device(
            db, subscription=mine, name="My phone", surface_kind="mobile-app"
        ).device
        their_device = dv.enroll_device(
            db, subscription=theirs, name="Their phone", surface_kind="mobile-app"
        ).device

        # The audit service answers with somebody else's event anyway.
        fake = _FakeAudit({
            my_device.id: [
                _event(my_device.id, evt_id="mine"),
                _event(their_device.id, evt_id="leaked"),
            ]
        })
        with mock.patch.object(activity.httpx, "AsyncClient", return_value=fake):
            feed = _run(activity.fetch(db, subscription_id=mine.id))

        self.assertEqual([i.id for i in feed.items], ["mine"])

    def test_the_device_name_comes_from_our_database(self):
        """'Blocked on your iPhone' -- the name is the one the person chose,
        not a string from the event payload."""
        db = _db()
        sub = _subscription(db, "a@example.com")
        device = dv.enroll_device(
            db, subscription=sub, name="Patrick's iPhone", surface_kind="mobile-app"
        ).device
        fake = _FakeAudit({device.id: [_event(device.id)]})
        with mock.patch.object(activity.httpx, "AsyncClient", return_value=fake):
            feed = _run(activity.fetch(db, subscription_id=sub.id))
        self.assertEqual(feed.items[0].device_name, "Patrick's iPhone")


class AnEmptyFeedIsNotABrokenOne(unittest.TestCase):
    def test_an_unreachable_audit_service_is_reported(self):
        db = _db()
        sub = _subscription(db, "a@example.com")
        dv.enroll_device(db, subscription=sub, name="phone",
                         surface_kind="mobile-app")

        class Boom(_FakeAudit):
            async def get(self, *a, **k):
                raise httpx.ConnectError("refused")

        with mock.patch.object(activity.httpx, "AsyncClient",
                               return_value=Boom({})):
            feed = _run(activity.fetch(db, subscription_id=sub.id))

        self.assertFalse(feed.available, "a broken feed claimed to be empty")
        self.assertEqual(feed.items, [])

    def test_a_non_200_is_not_silently_an_empty_feed(self):
        db = _db()
        sub = _subscription(db, "a@example.com")
        dv.enroll_device(db, subscription=sub, name="phone",
                         surface_kind="mobile-app")
        fake = _FakeAudit({}, status=500)
        with mock.patch.object(activity.httpx, "AsyncClient", return_value=fake):
            feed = _run(activity.fetch(db, subscription_id=sub.id))
        self.assertFalse(feed.available)

    def test_a_genuinely_quiet_account_is_available_and_empty(self):
        db = _db()
        sub = _subscription(db, "a@example.com")
        device = dv.enroll_device(db, subscription=sub, name="phone",
                                  surface_kind="mobile-app").device
        fake = _FakeAudit({device.id: []})
        with mock.patch.object(activity.httpx, "AsyncClient", return_value=fake):
            feed = _run(activity.fetch(db, subscription_id=sub.id))
        self.assertTrue(feed.available)
        self.assertEqual(feed.items, [])

    def test_an_account_with_no_devices_is_available_not_broken(self):
        db = _db()
        sub = _subscription(db, "a@example.com")
        feed = _run(activity.fetch(db, subscription_id=sub.id))
        self.assertTrue(feed.available)
        self.assertEqual(feed.items, [])


class TheFeedIsHonestAboutWhatItOmits(unittest.TestCase):
    def test_a_large_family_is_told_the_feed_is_partial(self):
        """Family allows 30 devices; the audit API filters one agent at a
        time. Capping is fine. Capping SILENTLY is not -- a feed that quietly
        omits half your devices reads as 'nothing happened there'."""
        db = _db()
        sub = _subscription(db, "a@example.com", tier="family")
        for i in range(activity.MAX_DEVICES_PER_QUERY + 5):
            dv.enroll_device(db, subscription=sub, name=f"device-{i}",
                             surface_kind="mobile-app")
        fake = _FakeAudit({})
        with mock.patch.object(activity.httpx, "AsyncClient", return_value=fake):
            feed = _run(activity.fetch(db, subscription_id=sub.id))
        self.assertEqual(len(fake.asked), activity.MAX_DEVICES_PER_QUERY)
        self.assertTrue(feed.caveats, "the cap was applied silently")

    def test_an_unmapped_event_type_is_still_shown(self):
        """Dropping events we have no copy for would make the feed a curated
        highlight reel that omits whatever is newest."""
        db = _db()
        sub = _subscription(db, "a@example.com")
        device = dv.enroll_device(db, subscription=sub, name="phone",
                                  surface_kind="mobile-app").device
        fake = _FakeAudit({
            device.id: [_event(device.id, event_type="brand.new.thing")]
        })
        with mock.patch.object(activity.httpx, "AsyncClient", return_value=fake):
            feed = _run(activity.fetch(db, subscription_id=sub.id))
        self.assertEqual(len(feed.items), 1)
        self.assertIn("brand new thing", feed.items[0].headline)

    def test_the_full_url_is_not_put_in_the_feed(self):
        """This screen gets read on a shared sofa more often than anyone
        plans for. The host is enough to recognise an event."""
        db = _db()
        sub = _subscription(db, "a@example.com")
        device = dv.enroll_device(db, subscription=sub, name="phone",
                                  surface_kind="mobile-app").device
        event = _event(device.id)
        event["evidence"] = {
            "host": "phish.example",
            "url": "https://phish.example/reset?token=SECRET",
        }
        fake = _FakeAudit({device.id: [event]})
        with mock.patch.object(activity.httpx, "AsyncClient", return_value=fake):
            feed = _run(activity.fetch(db, subscription_id=sub.id))
        rendered = str(feed.to_dict())
        self.assertIn("phish.example", rendered)
        self.assertNotIn("SECRET", rendered)


if __name__ == "__main__":
    unittest.main()
