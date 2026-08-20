#!/usr/bin/env python3
"""Prove each configured Stripe price charges what tiers.json says it should.

WHY THIS EXISTS
===============
`apps/api/billing.py` already guarantees the CLIENT cannot mismatch a tier and
a price: the request names only a tier, and the price is resolved server-side.
That closed one door. This closes the other one.

The price ids come from six environment variables whose names differ by one
word and whose values are opaque and nearly identical:

    STRIPE_PRICE_PERSONAL_ANNUAL=price_1U6VwjIPTrvvrCDya38JVfHe
    STRIPE_PRICE_FAMILY_ANNUAL=price_1U6W2jIPTrvvrCDyzZV5TuXE

Swap two of those and every check in the system still passes. "family" is a
real tier, that price id is a real price, the checkout succeeds, the webhook
grants Family -- and the customer pays $39.99 for 30 devices and 7 people.
Nothing in the request is wrong; the CONFIGURATION is wrong, and the only
place the truth exists is inside Stripe.

So this asks Stripe what each configured price actually costs and compares it
to shared/tiers.json, which is the same file the entitlement check reads.

Run it before a deploy, and after any pricing change:

    STRIPE_SECRET_KEY=sk_... python3 scripts/deployment/verify_stripe_prices.py

Exit 0 = every price charges what its tier promises. Non-zero = do not deploy.

Without STRIPE_SECRET_KEY it runs OFFLINE: it still catches missing variables
and duplicate ids -- which is most of the damage -- and says plainly that it
could not check the amounts. It does not report success for a check it did not
perform.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "apps" / "api"))

TIERS = json.loads((REPO / "shared" / "tiers.json").read_text())
CADENCES = ("monthly", "annual")
INTERVAL = {"monthly": "month", "annual": "year"}


def expected(tier_name: str, cadence: str) -> float:
    tier = TIERS["tiers"][tier_name]
    return tier["price_annual"] if cadence == "annual" else tier["price_monthly"]


def env_name(tier_name: str, cadence: str) -> str:
    return f"STRIPE_PRICE_{tier_name.upper()}_{cadence.upper()}"


def main() -> int:
    problems: list[str] = []
    warnings: list[str] = []
    configured: dict[str, tuple[str, str]] = {}   # price_id -> (tier, cadence)

    for tier_name in TIERS["upgrade_path"]:
        for cadence in CADENCES:
            name = env_name(tier_name, cadence)
            price_id = os.getenv(name, "").strip()
            if not price_id:
                problems.append(f"{name} is not set")
                continue
            # THE DUPLICATE CHECK, and it needs no network. Two slots sharing
            # one price id means one tier is being sold at another's price.
            if price_id in configured:
                other = configured[price_id]
                problems.append(
                    f"{name} and {env_name(*other)} both point at {price_id} -- "
                    f"one of these tiers is charged the other's price"
                )
            configured[price_id] = (tier_name, cadence)

    key = os.getenv("STRIPE_SECRET_KEY", "").strip()
    if not key:
        warnings.append(
            "STRIPE_SECRET_KEY is not set, so the AMOUNTS were not verified. "
            "Missing variables and duplicate ids were still checked."
        )
    else:
        try:
            import stripe
        except ImportError:
            warnings.append("the stripe package is not installed; amounts NOT verified")
            key = ""
        else:
            stripe.api_key = key
            for price_id, (tier_name, cadence) in configured.items():
                label = f"{tier_name}/{cadence}"
                try:
                    price = stripe.Price.retrieve(price_id)
                except Exception as exc:  # noqa: BLE001 - surfaced, not swallowed
                    problems.append(f"{label}: could not read {price_id} from Stripe: {exc}")
                    continue

                want = expected(tier_name, cadence)
                got = (price.get("unit_amount") or 0) / 100.0
                if abs(got - want) > 1e-9:
                    problems.append(
                        f"{label}: Stripe charges ${got:.2f}, tiers.json promises ${want:.2f}"
                    )

                currency = (price.get("currency") or "").lower()
                if currency != TIERS["currency"].lower():
                    problems.append(f"{label}: currency {currency} != {TIERS['currency']}")

                recurring = price.get("recurring") or {}
                if not recurring:
                    problems.append(f"{label}: {price_id} is not a recurring price")
                else:
                    if recurring.get("interval") != INTERVAL[cadence]:
                        problems.append(
                            f"{label}: interval {recurring.get('interval')} "
                            f"!= {INTERVAL[cadence]}"
                        )
                    if recurring.get("interval_count", 1) != 1:
                        problems.append(
                            f"{label}: interval_count {recurring.get('interval_count')} != 1"
                        )
                    # A trial on the price is a SECOND copy of a number that
                    # already lives in tiers.json and is sent on every checkout.
                    if recurring.get("trial_period_days"):
                        warnings.append(
                            f"{label}: the Stripe price carries a "
                            f"{recurring['trial_period_days']}-day trial. The API sends "
                            f"{TIERS['trial']['days']} days on every checkout, so this "
                            f"copy is unused today and will drift."
                        )
                if not price.get("active", True):
                    problems.append(f"{label}: {price_id} is ARCHIVED in Stripe")

    print(f"tiers.json v{TIERS['version']} — {len(configured)} price ids configured")
    for w in warnings:
        print(f"  ! {w}")
    if problems:
        print("\nREFUSING:")
        for p in problems:
            print(f"  ✗ {p}")
        return 1
    if not key:
        print("\nno amount mismatches found — but amounts were NOT checked (see above)")
        return 0
    print("\nevery configured price charges what its tier promises")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
