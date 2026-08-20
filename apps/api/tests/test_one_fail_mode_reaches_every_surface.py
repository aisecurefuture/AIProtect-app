"""One fail mode, chosen once, obeyed by every surface on every device.

THE DEFECT THIS IS SHAPED AROUND (CyberArmor.ai, 2026-08-06)
============================================================
`transparent_proxy` had a single FAIL_OPEN flag and two code paths reading it.
The policy path honoured it; the redact path blocked unconditionally. So an
endpoint configured fail-open had its AI traffic blocked anyway, while every
operator-facing description of that endpoint's configuration said the
opposite.

What the person saw was `API Error: 403` from Claude Code. They concluded
their Anthropic account had been blocked, asked another assistant, were told
the wording was Anthropic's, and uninstalled the agent to get working again.
Two people spent most of a day on it, and the uninstall destroyed the log.

The lesson is not "fix that branch". It is that ONE SETTING READ BY TWO CODE
PATHS WILL EVENTUALLY DISAGREE, and that the disagreement is invisible until
somebody is already uninstalling. In this product the paths are the browser
extension, the desktop agent, and the local proxy -- three, not two, and on
machines nobody can log into.

So the value is validated in one place (protection_settings.py), interpreted
in one place per client (verdict.js), and rides on every response a surface
already fetches, so no surface can hold a stale copy it does not know is stale.

THE CONSUMER DEFAULT DIFFERS FROM B2B, ON PURPOSE
=================================================
B2B defaults to fail-closed. That assumes an administrator who chose it. A
household has none, and for them fail-closed means the web breaks and the
product is uninstalled. Consumer default is OPEN, offered in the portal with
its consequences written out.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

API = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(API))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

import entitlements as ent  # noqa: E402
import protection_settings as ps  # noqa: E402
from models import Account, Base, Subscription  # noqa: E402


def _db():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _subscription(db, email="a@example.com"):
    acct = Account(email=email)
    db.add(acct)
    db.flush()
    sub = Subscription(owner_account_id=acct.id, tier="personal", state=ent.ACTIVE)
    db.add(sub)
    db.flush()
    return sub


class TheDefaultIsOpenAndItIsAProductDecision(unittest.TestCase):
    def test_a_new_subscription_fails_open(self):
        db = _db()
        sub = _subscription(db)
        self.assertEqual(sub.fail_mode, ps.FAIL_OPEN)
        self.assertEqual(ps.as_dict(sub)["fail_mode"], ps.FAIL_OPEN)

    def test_the_default_constant_is_open(self):
        """Flipping this to closed is a product decision, not a refactor. B2B
        made the opposite call for tenants with an administrator; a household
        has none, and a broken browser gets the product uninstalled."""
        self.assertEqual(ps.DEFAULT_FAIL_MODE, ps.FAIL_OPEN)

    def test_deep_inspection_is_off_until_somebody_opts_in(self):
        """The local proxy installs a root certificate into the machine's
        trust store. That is not something to switch on for somebody."""
        db = _db()
        self.assertFalse(_subscription(db).deep_inspection)
        self.assertFalse(ps.DEFAULT_DEEP_INSPECTION)


class AnUnrecognisedValueNeverBecomesBlocking(unittest.TestCase):
    def test_garbage_resolves_to_the_default_not_to_closed(self):
        # A null from a pre-migration row, a typo, or a value from a newer
        # portal than this install knows must not brick every surface.
        for bad in [None, "", "closd", "CLOSED", "true", 0, [], {}]:
            self.assertEqual(ps.resolve_fail_mode(bad), ps.DEFAULT_FAIL_MODE, repr(bad))

    def test_only_the_two_real_modes_validate(self):
        self.assertTrue(ps.is_valid_fail_mode("open"))
        self.assertTrue(ps.is_valid_fail_mode("closed"))
        for bad in [None, "CLOSED", "block", "", 1]:
            self.assertFalse(ps.is_valid_fail_mode(bad), repr(bad))

    def test_a_stored_null_is_resolved_before_it_reaches_a_device(self):
        db = _db()
        sub = _subscription(db)
        sub.fail_mode = None
        self.assertEqual(ps.as_dict(sub)["fail_mode"], ps.FAIL_OPEN)


class TheSettingIsAccountWide(unittest.TestCase):
    def test_it_lives_on_the_subscription_not_the_device(self):
        """A per-device fail mode lets somebody believe they chose 'block when
        you can't check' while a device they forgot about keeps failing open.
        A security setting that is believed and false is worse than none."""
        from models import Device

        self.assertFalse(
            hasattr(Device, "fail_mode"),
            "fail_mode has been added to Device. Account-wide is the whole "
            "point -- see the docstring.",
        )
        self.assertTrue(hasattr(Subscription, "fail_mode"))

    def test_one_change_covers_every_surface(self):
        db = _db()
        sub = _subscription(db)
        sub.fail_mode = ps.FAIL_CLOSED
        db.flush()
        # Whatever surface asks -- extension, agent, proxy -- gets one answer.
        self.assertEqual(ps.as_dict(sub)["fail_mode"], ps.FAIL_CLOSED)


class EverySurfaceFacingResponseCarriesIt(unittest.TestCase):
    """Structural. The cache is only correct if it is refreshed on success,
    and it is only refreshed if the responses actually carry the block."""

    def _main_src(self) -> str:
        return (API / "main.py").read_text()

    def test_the_check_endpoints_return_the_settings(self):
        src = self._main_src()
        # Both endpoints a surface calls on the hot path must carry it --
        # those are the calls whose success keeps the cached copy fresh.
        self.assertIn("settings: Dict[str, Any] = Depends(settings_of)", src)
        self.assertGreaterEqual(
            src.count('"protection": settings'), 2,
            "safe-links and privacy-check must BOTH return the settings; the "
            "cached fail mode goes stale otherwise, and it is consulted "
            "exactly when the API cannot be reached to refresh it.",
        )

    def test_me_carries_it_too(self):
        self.assertIn('"protection": protection_settings.as_dict(sub)', self._main_src())

    def test_the_explanation_travels_with_the_value(self):
        """A surface that has to tell somebody what this setting does should
        not be inventing its own wording for it."""
        db = _db()
        sub = _subscription(db)
        for mode in (ps.FAIL_OPEN, ps.FAIL_CLOSED):
            sub.fail_mode = mode
            out = ps.as_dict(sub)
            self.assertTrue(out["fail_mode_explanation"])
            self.assertNotEqual(
                out["fail_mode_explanation"], ps.describe(
                    ps.FAIL_CLOSED if mode == ps.FAIL_OPEN else ps.FAIL_OPEN
                ),
                "both modes explain themselves identically",
            )

    def test_the_closed_explanation_admits_the_cost(self):
        """Fail-closed takes things offline. Offering it without saying so is
        how somebody enables it and then uninstalls the product."""
        text = ps.describe(ps.FAIL_CLOSED).lower()
        self.assertTrue(
            any(w in text for w in ("stop working", "unreachable", "until it's back")),
            f"the fail-closed explanation hides its cost: {text!r}",
        )


if __name__ == "__main__":
    unittest.main()
