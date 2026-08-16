"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { getMe } from "@/lib/api";
import { statusBanner, type Entitlement } from "@/lib/protection";
import { StatusCard } from "@/components/Status";

export default function Home() {
  const [ent, setEnt] = useState<Entitlement | null>(null);
  const [devices, setDevices] = useState(0);
  const [error, setError] = useState("");

  useEffect(() => {
    getMe()
      .then((me) => { setEnt(me.entitlement); setDevices(me.devices_in_use); })
      .catch(() => setError("We couldn't load your account just now."));
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

      {/* Activity is deliberately absent rather than faked with placeholder
          rows. The audit service is deployed but the API does not read from it
          yet, and a timeline of invented events in a security product is the
          worst possible placeholder. */}
    </div>
  );
}
