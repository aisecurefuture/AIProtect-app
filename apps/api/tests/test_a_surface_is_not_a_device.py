"""One device, many surfaces -- enforced against a real database.

Decided 2026-08-16 (docs/MULTI-DEVICE.md). A laptop running the browser
extension AND the desktop agent is ONE device: one subscription slot, one
rate-limit bucket, two separately revocable credentials.

There are two ways to get it wrong and they fail in opposite directions:

  merge them   -> a laptop burns three subscription slots and the person
                  concludes the plan is too small
  split them   -> each surface counts as a device for rate limiting, so a
                  three-surface laptop silently gets 3x the ceiling, with no
                  second ceiling underneath to catch it

Plus the revocation rule, which is the one with a security consequence: a lost
laptop must be revoked entirely, and revoking it surface-by-surface from a UI
is how one gets missed. A missed surface is a live credential on a stolen
machine, behind a screen that says it was removed.
"""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

API = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(API))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

import devices as dv  # noqa: E402
import entitlements as ent  # noqa: E402
from models import Account, Base, Subscription  # noqa: E402


def _db():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _subscription(db, tier="personal", state=ent.ACTIVE, email="a@example.com"):
    acct = Account(email=email)
    db.add(acct)
    db.flush()
    sub = Subscription(owner_account_id=acct.id, tier=tier, state=state)
    db.add(sub)
    db.flush()
    return sub


class ASurfaceDoesNotConsumeASlot(unittest.TestCase):
    def test_a_second_surface_on_one_machine_is_not_a_second_device(self):
        """THE CORE PROPERTY."""
        db = _db()
        sub = _subscription(db)                       # personal: 3 devices

        laptop = dv.enroll_device(
            db, subscription=sub, name="MacBook",
            surface_kind="browser-extension", platform="macos",
        )
        self.assertEqual(dv.active_device_count(db, sub.id), 1)

        code = dv.create_join_code(db, device=laptop.device)
        joined = dv.join_surface(
            db, subscription_id=sub.id, code=code.code, surface_kind="desktop-agent",
        )

        self.assertEqual(joined.device.id, laptop.device.id, "it made a new device")
        self.assertEqual(dv.active_device_count(db, sub.id), 1)
        self.assertEqual(len(dv.surfaces_of(db, laptop.device)), 2)

    def test_the_two_surfaces_share_the_device_id(self):
        """This is what makes them share a rate-limit bucket downstream. If
        the ids differed, the laptop would quietly get double the ceiling."""
        db = _db()
        sub = _subscription(db)
        first = dv.enroll_device(
            db, subscription=sub, name="MacBook", surface_kind="browser-extension"
        )
        code = dv.create_join_code(db, device=first.device)
        second = dv.join_surface(
            db, subscription_id=sub.id, code=code.code, surface_kind="desktop-agent"
        )
        self.assertEqual(first.device.id, second.device.id)

    def test_each_surface_gets_its_own_credential(self):
        db = _db()
        sub = _subscription(db)
        first = dv.enroll_device(
            db, subscription=sub, name="MacBook", surface_kind="browser-extension"
        )
        code = dv.create_join_code(db, device=first.device)
        second = dv.join_surface(
            db, subscription_id=sub.id, code=code.code, surface_kind="desktop-agent"
        )
        self.assertNotEqual(first.credential, second.credential)

    def test_a_surface_cannot_be_installed_twice_on_one_device(self):
        db = _db()
        sub = _subscription(db)
        first = dv.enroll_device(
            db, subscription=sub, name="MacBook", surface_kind="browser-extension"
        )
        code = dv.create_join_code(db, device=first.device)
        with self.assertRaises(dv.JoinFailed):
            dv.join_surface(
                db, subscription_id=sub.id, code=code.code,
                surface_kind="browser-extension",
            )


class TheCapRefusesAndNeverEvicts(unittest.TestCase):
    def test_enrolling_past_the_cap_is_refused(self):
        db = _db()
        sub = _subscription(db)                       # personal: 3
        for i in range(3):
            dv.enroll_device(
                db, subscription=sub, name=f"device-{i}", surface_kind="mobile-app"
            )
        with self.assertRaises(dv.EnrollmentRefused) as ctx:
            dv.enroll_device(
                db, subscription=sub, name="one too many", surface_kind="mobile-app"
            )
        self.assertEqual(ctx.exception.decision.upgrade_to, "pro")

    def test_a_refusal_leaves_every_existing_device_untouched(self):
        """The eviction that must not happen, asserted directly."""
        db = _db()
        sub = _subscription(db)
        made = [
            dv.enroll_device(
                db, subscription=sub, name=f"device-{i}", surface_kind="mobile-app"
            ).device.id
            for i in range(3)
        ]
        with self.assertRaises(dv.EnrollmentRefused):
            dv.enroll_device(db, subscription=sub, name="nope",
                             surface_kind="mobile-app")
        still_here = {d.id for d in dv.active_devices(db, sub.id)}
        self.assertEqual(still_here, set(made))

    def test_surfaces_do_not_count_toward_the_cap(self):
        """Three devices each with two surfaces is still three devices."""
        db = _db()
        sub = _subscription(db)
        for i in range(3):
            e = dv.enroll_device(
                db, subscription=sub, name=f"laptop-{i}",
                surface_kind="browser-extension",
            )
            code = dv.create_join_code(db, device=e.device)
            dv.join_surface(
                db, subscription_id=sub.id, code=code.code,
                surface_kind="desktop-agent",
            )
        self.assertEqual(dv.active_device_count(db, sub.id), 3)

    def test_a_lapsed_subscription_cannot_enrol(self):
        db = _db()
        sub = _subscription(db, state=ent.LAPSED)
        with self.assertRaises(dv.EnrollmentRefused):
            dv.enroll_device(
                db, subscription=sub, name="phone", surface_kind="mobile-app"
            )


class RevocationIsTotal(unittest.TestCase):
    def test_revoking_a_device_revokes_every_surface_on_it(self):
        """A lost laptop is lost entirely. Revoking surface-by-surface from a
        UI is how one gets missed, and a missed surface is a live credential."""
        db = _db()
        sub = _subscription(db)
        e = dv.enroll_device(
            db, subscription=sub, name="MacBook", surface_kind="browser-extension"
        )
        code = dv.create_join_code(db, device=e.device)
        second = dv.join_surface(
            db, subscription_id=sub.id, code=code.code, surface_kind="desktop-agent"
        )

        revoked = dv.revoke_device(db, device=e.device)
        self.assertEqual(revoked, 2)
        self.assertIsNone(dv.authenticate_surface(db, credential=e.credential))
        self.assertIsNone(dv.authenticate_surface(db, credential=second.credential))

    def test_revoking_one_surface_leaves_the_others_working(self):
        """Uninstalling the extension must not turn off the agent."""
        db = _db()
        sub = _subscription(db)
        e = dv.enroll_device(
            db, subscription=sub, name="MacBook", surface_kind="browser-extension"
        )
        code = dv.create_join_code(db, device=e.device)
        agent = dv.join_surface(
            db, subscription_id=sub.id, code=code.code, surface_kind="desktop-agent"
        )
        dv.revoke_surface(db, surface=e.surface)
        self.assertIsNone(dv.authenticate_surface(db, credential=e.credential))
        self.assertIsNotNone(dv.authenticate_surface(db, credential=agent.credential))

    def test_a_revoked_device_frees_its_slot(self):
        db = _db()
        sub = _subscription(db)
        first = dv.enroll_device(
            db, subscription=sub, name="old phone", surface_kind="mobile-app"
        )
        for i in range(2):
            dv.enroll_device(
                db, subscription=sub, name=f"other-{i}", surface_kind="mobile-app"
            )
        dv.revoke_device(db, device=first.device)
        dv.enroll_device(db, subscription=sub, name="new phone",
                         surface_kind="mobile-app")
        self.assertEqual(dv.active_device_count(db, sub.id), 3)

    def test_a_revoked_device_is_kept_for_attribution(self):
        """Not deleted: Activity still has to say which device an old event
        happened on, including one that is no longer enrolled."""
        from models import Device
        db = _db()
        sub = _subscription(db)
        e = dv.enroll_device(
            db, subscription=sub, name="old phone", surface_kind="mobile-app"
        )
        dv.revoke_device(db, device=e.device)
        self.assertIsNotNone(db.get(Device, e.device.id))


class AWipedDeviceDoesNotBurnASlot(unittest.TestCase):
    def test_a_matching_machine_is_offered_not_merged(self):
        """Rule 2. The suggestion is a question for the person, never a
        decision: a wrong automatic match merges two real machines, and that
        failure is invisible to whoever it happens to."""
        db = _db()
        sub = _subscription(db)
        e = dv.enroll_device(
            db, subscription=sub, name="iPhone", surface_kind="mobile-app",
            machine_hint="hint-abc",
        )
        dv.revoke_device(db, device=e.device)

        candidate = dv.suggest_existing_device(
            db, subscription_id=sub.id, machine_hint="hint-abc"
        )
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.id, e.device.id)
        # Nothing has changed yet -- it is still revoked until confirmed.
        self.assertFalse(candidate.active)

    def test_reclaiming_reuses_the_slot(self):
        db = _db()
        sub = _subscription(db)
        e = dv.enroll_device(
            db, subscription=sub, name="iPhone", surface_kind="mobile-app",
            machine_hint="hint-abc",
        )
        dv.revoke_device(db, device=e.device)
        for i in range(2):
            dv.enroll_device(db, subscription=sub, name=f"o-{i}",
                             surface_kind="mobile-app")

        candidate = dv.suggest_existing_device(
            db, subscription_id=sub.id, machine_hint="hint-abc"
        )
        reclaimed = dv.reclaim_device(db, device=candidate, surface_kind="mobile-app")
        self.assertEqual(dv.active_device_count(db, sub.id), 3)
        self.assertEqual(reclaimed.device.id, e.device.id)

    def test_reclaiming_issues_a_fresh_credential(self):
        """The old install is gone; its credential must not still work."""
        db = _db()
        sub = _subscription(db)
        e = dv.enroll_device(
            db, subscription=sub, name="iPhone", surface_kind="mobile-app",
            machine_hint="hint-abc",
        )
        old = e.credential
        dv.revoke_device(db, device=e.device)
        reclaimed = dv.reclaim_device(db, device=e.device, surface_kind="mobile-app")
        self.assertNotEqual(reclaimed.credential, old)
        self.assertIsNone(dv.authenticate_surface(db, credential=old))
        self.assertIsNotNone(
            dv.authenticate_surface(db, credential=reclaimed.credential)
        )

    def test_no_hint_offers_nothing(self):
        db = _db()
        sub = _subscription(db)
        self.assertIsNone(
            dv.suggest_existing_device(db, subscription_id=sub.id, machine_hint=None)
        )


class JoinCodesAreNotAStandingInvitation(unittest.TestCase):
    def test_a_code_works_once(self):
        db = _db()
        sub = _subscription(db)
        e = dv.enroll_device(db, subscription=sub, name="MacBook",
                             surface_kind="browser-extension")
        code = dv.create_join_code(db, device=e.device)
        dv.join_surface(db, subscription_id=sub.id, code=code.code,
                        surface_kind="desktop-agent")
        with self.assertRaises(dv.JoinFailed):
            dv.join_surface(db, subscription_id=sub.id, code=code.code,
                            surface_kind="mobile-app")

    def test_an_expired_code_is_refused(self):
        db = _db()
        sub = _subscription(db)
        e = dv.enroll_device(db, subscription=sub, name="MacBook",
                             surface_kind="browser-extension")
        code = dv.create_join_code(db, device=e.device)
        code.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.flush()
        with self.assertRaises(dv.JoinFailed):
            dv.join_surface(db, subscription_id=sub.id, code=code.code,
                            surface_kind="desktop-agent")

    def test_another_accounts_code_is_indistinguishable_from_a_bad_one(self):
        """A distinct message would confirm that a guessed code belongs to
        somebody -- which is exactly what an attacker guessing codes wants."""
        db = _db()
        mine = _subscription(db, email="mine@example.com")
        theirs = _subscription(db, email="theirs@example.com")

        e = dv.enroll_device(db, subscription=theirs, name="Their laptop",
                             surface_kind="browser-extension")
        code = dv.create_join_code(db, device=e.device)

        with self.assertRaises(dv.JoinFailed) as ctx:
            dv.join_surface(db, subscription_id=mine.id, code=code.code,
                            surface_kind="desktop-agent")
        self.assertEqual(str(ctx.exception), "That code is not valid.")

    def test_the_code_alphabet_avoids_characters_people_confuse(self):
        """It gets read off one screen and typed into another, sometimes by a
        child. O/0, I/1 and S/5 are where that goes wrong."""
        from models import JoinCode
        seen = "".join(JoinCode.new_code() for _ in range(200))
        for ambiguous in "O0I1S5":
            self.assertNotIn(ambiguous, seen)


if __name__ == "__main__":
    unittest.main()
