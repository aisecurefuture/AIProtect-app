"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  getMe, getTiers, openBillingPortal, signOutEverywhere, setToken, ApiError,
  getProtectionSettings, putProtectionSettings, type ProtectionSettings,
} from "@/lib/api";
import { statusBanner, type Entitlement } from "@/lib/protection";
import { FAIL_MODE_OPTIONS, deepInspectionCopy, coverageSummary } from "@/lib/coverage";
import { StatusCard } from "@/components/Status";

export default function Settings() {
  const router = useRouter();
  const [ent, setEnt] = useState<Entitlement | null>(null);
  const [email, setEmail] = useState("");
  const [tiers, setTiers] = useState<Awaited<ReturnType<typeof getTiers>> | null>(null);
  const [prot, setProt] = useState<ProtectionSettings | null>(null);
  const [savingFailMode, setSavingFailMode] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    getMe().then((me) => { setEnt(me.entitlement); setEmail(me.account.email); })
      .catch(() => setError("We couldn't load your account."));
    getTiers().then(setTiers).catch(() => {});
    getProtectionSettings().then(setProt).catch(() => {});
  }, []);

  async function setFailMode(mode: "open" | "closed") {
    setSavingFailMode(true);
    setError("");
    try {
      setProt(await putProtectionSettings({ fail_mode: mode }));
    } catch (err) {
      setError(err instanceof ApiError ? "We couldn't save that." : "We couldn't save that.");
    } finally {
      setSavingFailMode(false);
    }
  }

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
        <h2 className="text-sm font-semibold uppercase tracking-wide opacity-60">
          Coverage
        </h2>
        <p className="text-sm opacity-80">{coverageSummary(prot?.deep_inspection ?? false)}</p>

        {/* "Protect everything" -- the local proxy. Read-only here on purpose:
            turning it ON installs a root certificate, which has to happen on
            the machine itself during install, not from a web page. */}
        {(() => {
          const copy = deepInspectionCopy(prot?.deep_inspection ?? false);
          return (
            <div className="rounded-2xl border border-slate-200 p-4 dark:border-slate-800">
              <h3 className="font-medium">{copy.headline}</h3>
              <p className="mt-1 text-sm opacity-80">{copy.benefit}</p>
              <p className="mt-2 text-sm font-medium">{copy.trustStoreWarning}</p>
              <ul className="mt-2 space-y-1 text-sm opacity-80">
                {copy.consequences.map((c) => (
                  <li key={c}>· {c}</li>
                ))}
              </ul>
              <p className="mt-3 text-xs opacity-70">
                {prot?.deep_inspection
                  ? "Turn this off from the AIProtect app on that computer."
                  : "Turn this on when you install the AIProtect app on a computer."}
              </p>
            </div>
          );
        })()}
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide opacity-60">
          When we can&rsquo;t check something
        </h2>
        <p className="text-sm opacity-80">
          This applies to every device on your plan &mdash; the extension and the
          app alike.
        </p>
        <div role="radiogroup" aria-label="When we can't check something" className="space-y-3">
          {FAIL_MODE_OPTIONS.map((opt) => {
            const active = (prot?.fail_mode ?? "open") === opt.value;
            return (
              <button
                key={opt.value}
                role="radio"
                aria-checked={active}
                disabled={savingFailMode}
                onClick={() => setFailMode(opt.value)}
                className={`w-full rounded-2xl border p-4 text-left disabled:opacity-60 ${
                  active
                    ? "border-blue-600 ring-1 ring-blue-600"
                    : "border-slate-200 dark:border-slate-800"
                }`}
              >
                <span className="flex items-center justify-between gap-3">
                  <span className="font-medium">{opt.label}</span>
                  {opt.recommended ? (
                    <span className="text-xs opacity-70">Recommended</span>
                  ) : null}
                </span>
                <span className="mt-1 block text-sm opacity-80">{opt.detail}</span>
                {/* The cost, always shown -- never behind a disclosure. */}
                {opt.consequence ? (
                  <span className="mt-2 block text-sm font-medium">
                    {opt.consequence}
                  </span>
                ) : null}
              </button>
            );
          })}
        </div>
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
