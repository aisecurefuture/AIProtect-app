"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { getMe, getActivity, type ActivityItem } from "@/lib/api";
import { statusBanner, type Entitlement } from "@/lib/protection";
import { StatusCard } from "@/components/Status";

// Colour is never the only signal -- see components/Status.tsx.
const TONE_MARK: Record<string, string> = { good: "\u2713", attention: "!", bad: "\u2715" };

export default function Home() {
  const [ent, setEnt] = useState<Entitlement | null>(null);
  const [devices, setDevices] = useState(0);
  const [error, setError] = useState("");
  const [activity, setActivity] = useState<{
    items: ActivityItem[]; available: boolean; caveats: string[];
  } | null>(null);

  useEffect(() => {
    getMe()
      .then((me) => { setEnt(me.entitlement); setDevices(me.devices_in_use); })
      .catch(() => setError("We couldn't load your account just now."));
    getActivity()
      .then(setActivity)
      // A failed request is NOT an empty feed. Fall through to available:false
      // so the UI says we could not load it rather than "nothing happened".
      .catch(() => setActivity({ items: [], available: false, caveats: [] }));
  }, []);

  if (error) return <p role="alert" className="text-sm text-red-600">{error}</p>;
  if (!ent) return <p className="text-sm opacity-70">Loading…</p>;

  const banner = statusBanner(ent);

  return (
    <div className="space-y-6">
      <StatusCard tone={banner.tone} headline={banner.headline} detail={banner.detail}>
        {banner.deadline ? (
          <p className="mt-2 text-sm font-medium">
            Until {new Date(banner.deadline).toLocaleDateString()}
          </p>
        ) : null}
        {banner.action ? (
          <Link href={banner.action.href}
            className="mt-3 inline-block rounded-lg border border-current px-3 py-2 text-sm font-medium">
            {banner.action.label}
          </Link>
        ) : null}
      </StatusCard>

      <section>
        <h2 className="text-sm font-semibold uppercase tracking-wide opacity-60">
          Quick actions
        </h2>
        <div className="mt-2 grid gap-3 sm:grid-cols-2">
          <Link href="/links" className="rounded-xl border border-slate-200 p-4 dark:border-slate-800">
            <h3 className="font-medium">Check a link</h3>
            <p className="mt-1 text-sm opacity-70">Is this safe to open?</p>
          </Link>
          <Link href="/privacy" className="rounded-xl border border-slate-200 p-4 dark:border-slate-800">
            <h3 className="font-medium">Check some text</h3>
            <p className="mt-1 text-sm opacity-70">Before you paste it into an AI.</p>
          </Link>
        </div>
      </section>

      <section>
        <h2 className="text-sm font-semibold uppercase tracking-wide opacity-60">Devices</h2>
        <p className="mt-2 text-sm">
          {devices} of {ent.devices_allowed} in use.{" "}
          <Link href="/devices" className="underline">Manage</Link>
        </p>
      </section>

      <section>
        <h2 className="text-sm font-semibold uppercase tracking-wide opacity-60">
          Recent activity
        </h2>
        {!activity ? (
          <p className="mt-2 text-sm opacity-70">Loading…</p>
        ) : !activity.available ? (
          // "You have had a quiet week" and "we cannot reach our own audit
          // log" must not render identically.
          <p className="mt-2 text-sm opacity-70">
            We couldn&apos;t load your activity just now. This doesn&apos;t mean
            nothing happened.
          </p>
        ) : activity.items.length === 0 ? (
          <p className="mt-2 text-sm opacity-70">Nothing to report yet.</p>
        ) : (
          <ul className="mt-2 space-y-2">
            {activity.items.slice(0, 8).map((item) => (
              <li key={item.id}
                  className="rounded-xl border border-slate-200 p-3 dark:border-slate-800">
                <p className="text-sm font-medium">
                  <span aria-hidden="true">{TONE_MARK[item.tone]} </span>
                  {item.headline}
                </p>
                <p className="mt-0.5 text-xs opacity-60">
                  {item.device}
                  {item.detail ? ` · ${item.detail}` : ""}
                  {item.at ? ` · ${new Date(item.at).toLocaleDateString()}` : ""}
                </p>
              </li>
            ))}
          </ul>
        )}
        {activity?.caveats.map((c) => (
          <p key={c} className="mt-2 text-xs opacity-60">{c}</p>
        ))}
      </section>
    </div>
  );
}
