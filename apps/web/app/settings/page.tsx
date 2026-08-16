"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getMe, getTiers, openBillingPortal, signOutEverywhere, setToken, ApiError } from "@/lib/api";
import { statusBanner, type Entitlement } from "@/lib/protection";
import { StatusCard } from "@/components/Status";

export default function Settings() {
  const router = useRouter();
  const [ent, setEnt] = useState<Entitlement | null>(null);
  const [email, setEmail] = useState("");
  const [tiers, setTiers] = useState<Awaited<ReturnType<typeof getTiers>> | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getMe().then((me) => { setEnt(me.entitlement); setEmail(me.account.email); })
      .catch(() => setError("We couldn't load your account."));
    getTiers().then(setTiers).catch(() => {});
  }, []);

  async function portal() {
    try { window.location.href = (await openBillingPortal()).url; }
    catch (err) { setError(err instanceof ApiError ? err.message : "Billing is unavailable."); }
  }

  async function signOutAll() {
    try { await signOutEverywhere(); } catch { /* signing out locally regardless */ }
    setToken(null);
    router.replace("/signin");
  }

  const banner = ent ? statusBanner(ent) : null;

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">Settings</h1>
        <p className="mt-1 text-sm opacity-70">{email}</p>
      </header>

      {error ? <p role="alert" className="text-sm text-red-600">{error}</p> : null}

      <section id="billing" className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide opacity-60">Subscription</h2>
        {banner && ent ? (
          <StatusCard tone={banner.tone} headline={banner.headline} detail={banner.detail}>
            <p className="mt-2 text-sm">
              {tiers?.tiers[ent.tier]?.display_name ?? ent.tier} — up to{" "}
              {ent.devices_allowed} devices
            </p>
          </StatusCard>
        ) : null}
        <button onClick={portal}
          className="min-h-12 w-full rounded-lg border border-slate-300 font-medium dark:border-slate-700">
          Manage payment, invoices and cancellation
        </button>
        {/* Cancellation lives in Stripe's portal rather than a bespoke flow:
            click-to-cancel requires cancelling be as easy as subscribing. */}
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide opacity-60">What we can see</h2>
        <p className="text-sm opacity-80">
          We scan links you check and text you paste into Privacy Guard. We don't
          store that text. We don't read your files, and we don't open documents —
          this product inspects AI traffic, it doesn't parse PDFs or spreadsheets.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide opacity-60">Account</h2>
        <button onClick={signOutAll}
          className="min-h-12 w-full rounded-lg border border-slate-300 font-medium dark:border-slate-700">
          Sign out on all devices
        </button>
      </section>
    </div>
  );
}
