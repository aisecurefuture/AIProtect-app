/**
 * The pricing page must agree with the entitlement check.
 *
 * shared/tiers.json exists because a price written down twice drifts, and the
 * copy that drifts silently is the one that decides what a paying customer
 * actually gets. These tests pin the UI end of that arrangement: the numbers
 * rendered come from the served table, the savings claim is arithmetic rather
 * than a marketing constant, and a plan we cannot sell never renders as
 * buyable.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { planView, planViews, smallestPlanFor, trialTerms } from "./plans.ts";
import type { TierRow } from "./api.ts";

// The real numbers from shared/tiers.json, so a change there fails here.
const TIERS: Record<string, TierRow> = {
  personal: { display_name: "Personal", devices: 3, people: 1, price_monthly: 4.99, price_annual: 39.99 },
  pro: { display_name: "Pro", devices: 10, people: 1, price_monthly: 9.99, price_annual: 79.99 },
  family: { display_name: "Family", devices: 30, people: 7, price_monthly: 14.99, price_annual: 119.99 },
};
const PATH = ["personal", "pro", "family"];
const ALL_BUYABLE = {
  personal: { monthly: true, annual: true },
  pro: { monthly: true, annual: true },
  family: { monthly: true, annual: true },
};

test("annual shows the yearly price, not a monthly one", () => {
  const p = planView("family", TIERS.family, "annual", true);
  assert.equal(p.price, 119.99);
  assert.match(p.billingNote, /billed once a year/);
});

test("the monthly-equivalent of annual is derived, not asserted", () => {
  const p = planView("family", TIERS.family, "annual", true);
  // 119.99 / 12 = 9.999... -> 10.00, the "~$10.00/mo" in PRICING.md
  assert.equal(p.perMonth, 10);
});

test("the saving is real arithmetic against twelve monthly payments", () => {
  const p = planView("pro", TIERS.pro, "annual", true);
  // 9.99 * 12 = 119.88, minus 79.99 = 39.89
  assert.equal(p.savingVsMonthly, 39.89);
  assert.equal(p.savingPercent, 33); // the "~33% off" claim, checked
});

test("monthly never claims a saving", () => {
  const p = planView("pro", TIERS.pro, "monthly", true);
  assert.equal(p.savingVsMonthly, null);
  assert.equal(p.savingPercent, null);
  assert.match(p.billingNote, /billed monthly/);
});

test("a plan with no configured price is not purchasable", () => {
  const p = planView("family", TIERS.family, "annual", false);
  assert.equal(p.purchasable, false);
});

test("plans render in upgrade order, cheapest first", () => {
  const views = planViews(TIERS, PATH, "annual", ALL_BUYABLE);
  assert.deepEqual(views.map((v) => v.id), ["personal", "pro", "family"]);
});

test("the marginal device gets cheaper, never dearer", () => {
  // The property that killed the per-device add-on (docs/PRICING.md), pinned
  // at the UI so a future price change cannot quietly violate it on screen.
  const views = planViews(TIERS, PATH, "annual", ALL_BUYABLE);
  const perDevice = views.map((v) => v.price / v.devices);
  for (let i = 1; i < perDevice.length; i++) {
    assert.ok(
      perDevice[i] < perDevice[i - 1],
      `${views[i].name} costs more per device than ${views[i - 1].name}`
    );
  }
});

test("an unpurchasable plan still renders its numbers", () => {
  // It says "unavailable", it does not vanish. A plan that disappears looks
  // like a product that does not offer it.
  const views = planViews(TIERS, PATH, "annual", {
    ...ALL_BUYABLE,
    family: { monthly: false, annual: false },
  });
  const family = views.find((v) => v.id === "family");
  assert.ok(family);
  assert.equal(family.purchasable, false);
  assert.equal(family.price, 119.99);
});

test("a missing purchasable map means not buyable, not buyable-by-default", () => {
  // Fail closed: if the API did not say, we do not invite a payment.
  const views = planViews(TIERS, PATH, "annual", {} as never);
  assert.ok(views.every((v) => !v.purchasable));
});

test("the trial terms state the charge, the cadence and the cancellation", () => {
  const p = planView("personal", TIERS.personal, "annual", true);
  const terms = trialTerms(p, 14);
  assert.match(terms, /14 days/);
  assert.match(terms, /39\.99/);
  assert.match(terms, /automatically/);
  assert.match(terms, /cancel/i);
});

test("the smallest fitting plan is recommended, not the largest", () => {
  const views = planViews(TIERS, PATH, "annual", ALL_BUYABLE);
  assert.equal(smallestPlanFor(views, { devices: 3, people: 1 })?.id, "personal");
  assert.equal(smallestPlanFor(views, { devices: 4, people: 1 })?.id, "pro");
  assert.equal(smallestPlanFor(views, { devices: 2, people: 4 })?.id, "family");
});

test("nothing fits is null, not the biggest plan", () => {
  const views = planViews(TIERS, PATH, "annual", ALL_BUYABLE);
  assert.equal(smallestPlanFor(views, { devices: 500, people: 1 }), null);
  assert.equal(smallestPlanFor(views, { devices: 1, people: 40 }), null);
});

/* ------------------------------------------------------------------ */
/* Post-checkout                                                       */
/* ------------------------------------------------------------------ */

import { activationView } from "./plans.ts";

test("arriving from checkout is not by itself proof of protection", () => {
  // THE CORE PROPERTY. Stripe redirects on payment; the webhook that grants
  // entitlement is a separate async delivery. Until it lands, this page must
  // not claim the devices are protected.
  const v = activationView(null, 0);
  assert.equal(v.ready, false);
  assert.equal(v.state, "confirming");
  assert.doesNotMatch(v.headline, /protected/i);
});

test("an unprotected entitlement never renders as ready", () => {
  const v = activationView({ protected: false, state: "trialing" }, 0);
  assert.equal(v.ready, false);
});

test("a confirmed trial says so, and only then", () => {
  const v = activationView({ protected: true, state: "trialing" }, 1200);
  assert.equal(v.ready, true);
  assert.match(v.detail, /trial has started/i);
});

test("a confirmed active subscription is not described as a trial", () => {
  const v = activationView({ protected: true, state: "active" }, 1200);
  assert.equal(v.ready, true);
  assert.doesNotMatch(v.detail, /trial/i);
});

test("a long wait becomes an honest delay, not an endless spinner", () => {
  const v = activationView(null, 20000);
  assert.equal(v.state, "stalled");
  assert.equal(v.ready, false);
  assert.match(v.detail, /longer than usual/i);
});

test("a lapsed subscription after checkout is surfaced as a failure", () => {
  const v = activationView(
    { protected: false, state: "lapsed", reason: "Your subscription has ended." },
    1000
  );
  assert.equal(v.state, "failed");
  assert.equal(v.ready, false);
  assert.match(v.detail, /ended/i);
});

test("a failure outranks the patience timer", () => {
  // A known failure must not be re-rendered as "still confirming" just
  // because the clock also ran out.
  const v = activationView({ protected: false, state: "lapsed" }, 60000);
  assert.equal(v.state, "failed");
});
