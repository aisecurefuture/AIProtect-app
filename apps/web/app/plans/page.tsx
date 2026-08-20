"use client";
import { useEffect, useState } from "react";
import { getTiers, startCheckout, ApiError, type Cadence } from "@/lib/api";
import { planViews, trialTerms, type PlanView } from "@/lib/plans";

/**
 * The plan picker.
 *
 * Two things this screen must not do, both of which are the normal way to
 * build it:
 *
 *   1. Hardcode a price. Every number comes from GET /tiers, which reads
 *      shared/tiers.json -- the same file the entitlement check reads. A
 *      pricing page with its own copy of $14.99 is how a customer ends up
 *      charged for Family and capped at Pro.
 *   2. Take the card before stating the terms. The trial auto-renews, which
 *      is regulated on both sides of the Atlantic and, for a security
 *      product, a trust question before it is a compliance one. The full
 *      terms sit next to the button, not behind a link.
 */
export default function Plans() {
  const [cadence, setCadence] = useState<Cadence>("annual"); // annual is the default (docs/PRICING.md)
  const [data, setData] = useState<Awaited<ReturnType<typeof getTiers>> | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    getTiers()
      .then(setData)
      .catch(() => setError("We couldn't load the plans. Please try again."));
  }, []);

  async function choose(plan: PlanView) {
    setBusy(plan.id);
    setError("");
    try {
      // The tier only. The API resolves the price from it -- see lib/api.ts.
      const out = await startCheckout(plan.id, cadence);
      window.location.href = out.url;
    } catch (err) {
      setError(
        err instanceof ApiError && err.message === "plan_not_purchasable"
          ? "That plan isn't available to buy right now. Please try another, or contact support."
          : err instanceof ApiError
            ? "We couldn't start checkout. Please try again."
            : "We couldn't start checkout. Please try again."
      );
      setBusy(null);
    }
  }

  const plans = data
    ? planViews(data.tiers, data.upgrade_path, cadence, data.purchasable)
    : [];

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Choose a plan</h1>
        <p className="mt-1 text-sm opacity-70">
          {data
            ? `Free for ${data.trial_days} days. Cancel any time before it ends and you're not charged.`
            : "Loading plans…"}
        </p>
      </header>

      {error ? (
        <p role="alert" className="text-sm font-medium text-red-600 dark:text-red-400">
          {error}
        </p>
      ) : null}

      {/* Cadence. A radiogroup rather than a styled checkbox, so the choice is
          announced as a choice and both options are reachable by keyboard. */}
      <div
        role="radiogroup"
        aria-label="Billing period"
        className="flex rounded-xl border border-slate-300 p-1 dark:border-slate-700"
      >
        {(["annual", "monthly"] as Cadence[]).map((c) => (
          <button
            key={c}
            role="radio"
            aria-checked={cadence === c}
            onClick={() => setCadence(c)}
            className={`min-h-12 flex-1 rounded-lg text-sm font-medium capitalize ${
              cadence === c
                ? "bg-blue-600 text-white"
                : "text-slate-600 dark:text-slate-300"
            }`}
          >
            {c}
          </button>
        ))}
      </div>

      <ul className="space-y-4">
        {plans.map((p) => (
          <li
            key={p.id}
            className="rounded-2xl border border-slate-200 p-5 dark:border-slate-800"
          >
            <div className="flex items-baseline justify-between gap-3">
              <h2 className="text-lg font-semibold">{p.name}</h2>
              <p className="text-right">
                <span className="text-2xl font-semibold">
                  ${p.perMonth.toFixed(2)}
                </span>
                <span className="text-sm opacity-70">/mo</span>
              </p>
            </div>

            <p className="mt-1 text-sm opacity-70">{p.billingNote}</p>

            {p.savingVsMonthly !== null ? (
              <p className="mt-1 text-sm font-medium text-emerald-700 dark:text-emerald-400">
                Save ${p.savingVsMonthly.toFixed(2)} a year ({p.savingPercent}% off)
              </p>
            ) : null}

            <ul className="mt-3 space-y-1 text-sm opacity-90">
              <li>· {p.devices} devices</li>
              <li>· {p.people === 1 ? "1 person" : `Up to ${p.people} people`}</li>
            </ul>

            {p.purchasable ? (
              <>
                <button
                  onClick={() => choose(p)}
                  disabled={busy !== null}
                  className="mt-4 min-h-12 w-full rounded-lg bg-blue-600 font-medium text-white disabled:opacity-60"
                >
                  {busy === p.id ? "Starting…" : `Start ${data?.trial_days}-day trial`}
                </button>
                {/* The terms sit HERE, next to the button, before the card is
                    taken -- not behind a link somebody will not open. */}
                <p className="mt-2 text-xs opacity-70">
                  {data ? trialTerms(p, data.trial_days) : null}
                </p>
              </>
            ) : (
              <p className="mt-4 rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-100">
                Not available to buy right now.
              </p>
            )}
          </li>
        ))}
      </ul>

      <p className="text-xs opacity-60">
        Prices in USD, and the same on every channel. A laptop running the
        browser extension and the desktop app counts as one device.
      </p>
    </div>
  );
}
