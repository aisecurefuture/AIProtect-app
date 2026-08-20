/**
 * Turning the tier table into what a person choosing a plan sees.
 *
 * Same discipline as protection.ts, for the same reason: every number here
 * exists once in shared/tiers.json, is served by GET /tiers, and must not be
 * re-derived by hand in a component. A pricing page that disagrees with the
 * entitlement check is a customer billed for one thing and given another --
 * which is the exact failure shared/tiers.json was created to prevent, and
 * re-introducing it in the UI would defeat the whole arrangement.
 *
 * THE RULE: no price, saving, or device count is ever computed in a component.
 */

import type { Cadence, TierRow } from "./api.ts";

export interface PlanView {
  /** Tier key -- "personal", "pro", "family". */
  id: string;
  name: string;
  devices: number;
  people: number;
  /** What they will be charged, for the chosen cadence. */
  price: number;
  /** How that price reads per month. Annual is billed once, shown monthly. */
  perMonth: number;
  /** Present only for annual, and only when it actually saves money. */
  savingVsMonthly: number | null;
  savingPercent: number | null;
  /** How the charge is actually taken -- never left implicit. */
  billingNote: string;
  /** False when the plan has no Stripe price configured. */
  purchasable: boolean;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

/**
 * One plan, at one cadence.
 *
 * `purchasable` is passed in rather than assumed true. A plan we cannot
 * actually sell renders as unavailable; it does not render a Buy button that
 * fails after the person has decided.
 */
export function planView(
  id: string,
  tier: TierRow,
  cadence: Cadence,
  purchasable: boolean
): PlanView {
  const annual = cadence === "annual";
  const price = annual ? tier.price_annual : tier.price_monthly;
  const perMonth = annual ? round2(tier.price_annual / 12) : tier.price_monthly;

  const twelveMonths = round2(tier.price_monthly * 12);
  const saving = annual ? round2(twelveMonths - tier.price_annual) : 0;
  const savesMoney = annual && saving > 0;

  return {
    id,
    name: tier.display_name,
    devices: tier.devices,
    people: tier.people,
    price,
    perMonth,
    savingVsMonthly: savesMoney ? saving : null,
    savingPercent: savesMoney
      ? Math.round((saving / twelveMonths) * 100)
      : null,
    billingNote: annual
      ? `$${price.toFixed(2)} billed once a year`
      : `$${price.toFixed(2)} billed monthly`,
    purchasable,
  };
}

/**
 * Every plan, in upgrade order.
 *
 * Order comes from the API's `upgrade_path`, not from Object.keys — the
 * cheapest-first ordering is a product decision that lives in tiers.json.
 */
export function planViews(
  tiers: Record<string, TierRow>,
  upgradePath: string[],
  cadence: Cadence,
  purchasable: Record<string, Record<Cadence, boolean>>
): PlanView[] {
  return upgradePath
    .filter((id) => tiers[id])
    .map((id) =>
      planView(id, tiers[id], cadence, purchasable?.[id]?.[cadence] ?? false)
    );
}

/**
 * What the trial actually commits someone to.
 *
 * Spelled out in full, deliberately. Auto-renewal after a trial is regulated
 * (FTC negative-option, EU consumer law, both app stores) and several
 * jurisdictions require the terms, price and renewal date be explicit BEFORE
 * the card is taken. For a company selling security a surprise charge is also
 * a disproportionate reputational hit, so this says the whole thing rather
 * than the minimum. See docs/PRICING.md.
 */
export function trialTerms(plan: PlanView, trialDays: number): string {
  return (
    `Free for ${trialDays} days. After that, ${plan.billingNote.toLowerCase()}, ` +
    `automatically, until you cancel. Cancel any time before the trial ends ` +
    `and you are not charged.`
  );
}

/**
 * The smallest plan that fits what someone says they have.
 *
 * Returns null when nothing fits, rather than the largest plan — recommending
 * a plan that does not cover their devices would be a worse answer than
 * admitting the range stops.
 */
export function smallestPlanFor(
  plans: PlanView[],
  need: { devices: number; people: number }
): PlanView | null {
  return (
    plans.find((p) => p.devices >= need.devices && p.people >= need.people) ??
    null
  );
}

/* ------------------------------------------------------------------ */
/* Post-checkout                                                       */
/* ------------------------------------------------------------------ */

export type ActivationState = "confirming" | "active" | "stalled" | "failed";

export interface ActivationView {
  state: ActivationState;
  headline: string;
  detail: string;
  /** True only when the subscription is genuinely live. */
  ready: boolean;
}

/**
 * What to say after Stripe sends someone back from checkout.
 *
 * THE TRAP THIS AVOIDS. Stripe redirects the browser to the success URL as
 * soon as payment is taken. The webhook that actually moves the subscription
 * to `trialing` is a SEPARATE, asynchronous delivery — it usually lands within
 * a second or two, and it is not guaranteed to have arrived when this page
 * renders. Every naive version of this screen says "You're protected!" on
 * arrival, because arriving here means the payment worked.
 *
 * But "we took your money" and "your devices are protected" are different
 * facts, and this product's whole discipline is not collapsing that kind of
 * pair. So the headline is driven by the ENTITLEMENT, not by the redirect:
 * until the entitlement says protected, this page says it is confirming.
 *
 * `elapsedMs` lets a long wait become an honest "this is taking longer than
 * expected" instead of a spinner that never resolves.
 */
export function activationView(
  entitlement: { protected: boolean; state: string; reason?: string } | null,
  elapsedMs: number,
  patienceMs = 15000
): ActivationView {
  if (entitlement?.protected) {
    return {
      state: "active",
      headline: "Payment confirmed",
      detail:
        entitlement.state === "trialing"
          ? "Your trial has started. Two more steps and your first device is protected."
          : "Your subscription is active. Two more steps and your first device is protected.",
      ready: true,
    };
  }

  if (entitlement && !entitlement.protected && entitlement.state === "lapsed") {
    return {
      state: "failed",
      headline: "We couldn't confirm your subscription",
      detail:
        entitlement.reason ||
        "Your payment may not have gone through. Check your billing details.",
      ready: false,
    };
  }

  if (elapsedMs >= patienceMs) {
    return {
      state: "stalled",
      headline: "Still confirming your payment",
      detail:
        "This is taking longer than usual. Your payment went through — the " +
        "confirmation just hasn't reached us yet. You can carry on; we'll " +
        "keep checking.",
      ready: false,
    };
  }

  return {
    state: "confirming",
    headline: "Confirming your payment",
    detail: "This usually takes a couple of seconds.",
    ready: false,
  };
}
