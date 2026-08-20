"use client";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { getMe } from "@/lib/api";
import { activationView } from "@/lib/plans";
import type { Entitlement } from "@/lib/protection";
import { StatusCard } from "@/components/Status";

/** Set once the extension has a store listing. Until then this page says so
 *  rather than linking somewhere that 404s. */
const STORE_URL = process.env.NEXT_PUBLIC_EXTENSION_STORE_URL ?? "";

const POLL_MS = 2000;
const GIVE_UP_POLLING_MS = 120000;

/**
 * Where Stripe sends someone after checkout.
 *
 * This page exists because `AIPROTECT_CHECKOUT_SUCCESS_URL` pointed at it and
 * it did not exist -- a customer who had just paid landed on a 404.
 *
 * The honesty problem it has to solve: arriving here means STRIPE took the
 * payment, not that this system knows about it. The subscription is moved to
 * `trialing` by a webhook, which is a separate asynchronous delivery. So the
 * headline is driven by the entitlement from GET /me, polled until it agrees
 * -- never by the fact of the redirect. See lib/plans.ts:activationView.
 */
export default function Welcome() {
  const [ent, setEnt] = useState<Entitlement | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const startedAt = useRef(Date.now());

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    async function poll() {
      if (cancelled) return;
      try {
        const me = await getMe();
        if (cancelled) return;
        setEnt(me.entitlement);
        if (me.entitlement.protected) return; // settled; stop polling
      } catch {
        /* transient -- keep polling, the state below stays "confirming" */
      }
      const waited = Date.now() - startedAt.current;
      setElapsed(waited);
      if (waited < GIVE_UP_POLLING_MS) timer = setTimeout(poll, POLL_MS);
    }

    poll();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, []);

  const view = activationView(ent, elapsed);
  const tone =
    view.state === "active" ? "good" : view.state === "failed" ? "bad" : "attention";

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Welcome to AIProtect</h1>
      </header>

      <StatusCard tone={tone} headline={view.headline} detail={view.detail}>
        {view.state === "failed" ? (
          <Link
            href="/settings#billing"
            className="mt-3 inline-block rounded-lg border border-current px-3 py-2 text-sm font-medium"
          >
            Check billing details
          </Link>
        ) : null}
      </StatusCard>

      {/* The setup steps are shown regardless -- they are useful reading while
          the webhook lands -- but the actions that need a live subscription
          stay disabled until it has. */}
      <section className="space-y-4">
        <h2 className="text-sm font-semibold uppercase tracking-wide opacity-60">
          Getting protected
        </h2>

        <ol className="space-y-4">
          <li className="rounded-2xl border border-slate-200 p-4 dark:border-slate-800">
            <h3 className="font-medium">1. Use it right here</h3>
            <p className="mt-1 text-sm opacity-80">
              Safe Links and Privacy Guard work in this browser now — check a
              link before you open it, or check text before you paste it into
              an AI assistant.
            </p>
            <div className="mt-3 flex gap-2">
              <Link
                href="/links"
                aria-disabled={!view.ready}
                className={`min-h-12 flex-1 rounded-lg border border-slate-300 text-center text-sm font-medium leading-[3rem] dark:border-slate-700 ${
                  view.ready ? "" : "pointer-events-none opacity-50"
                }`}
              >
                Check a link
              </Link>
              <Link
                href="/privacy"
                aria-disabled={!view.ready}
                className={`min-h-12 flex-1 rounded-lg border border-slate-300 text-center text-sm font-medium leading-[3rem] dark:border-slate-700 ${
                  view.ready ? "" : "pointer-events-none opacity-50"
                }`}
              >
                Check some text
              </Link>
            </div>
          </li>

          <li className="rounded-2xl border border-slate-200 p-4 dark:border-slate-800">
            <h3 className="font-medium">2. Protect your browsing</h3>
            {STORE_URL ? (
              <>
                <p className="mt-1 text-sm opacity-80">
                  The extension checks links before the page loads, and warns
                  you before you send personal information to an AI assistant.
                </p>
                <a
                  href={STORE_URL}
                  className="mt-3 block min-h-12 rounded-lg bg-blue-600 text-center font-medium leading-[3rem] text-white"
                >
                  Add the browser extension
                </a>
              </>
            ) : (
              /* Honest placeholder. An install button that goes nowhere is
                 worse than saying it is not ready -- see apps/web/README.md. */
              <p className="mt-1 text-sm opacity-80">
                The Chrome and Edge extension is not in the stores yet. It is
                the next thing we ship, and your plan already covers it — we'll
                email you the moment it's available.
              </p>
            )}
          </li>

          <li className="rounded-2xl border border-slate-200 p-4 dark:border-slate-800">
            <h3 className="font-medium">3. Add your devices</h3>
            <p className="mt-1 text-sm opacity-80">
              Each thing you install shows up under Devices. A laptop running
              both the extension and the desktop app counts as one device, not
              two.
            </p>
            <Link
              href="/devices"
              aria-disabled={!view.ready}
              className={`mt-3 block min-h-12 rounded-lg border border-slate-300 text-center text-sm font-medium leading-[3rem] dark:border-slate-700 ${
                view.ready ? "" : "pointer-events-none opacity-50"
              }`}
            >
              Manage devices
            </Link>
          </li>
        </ol>
      </section>

      <Link
        href="/home"
        className={`block min-h-12 rounded-lg text-center font-medium leading-[3rem] ${
          view.ready
            ? "bg-blue-600 text-white"
            : "pointer-events-none border border-slate-300 opacity-50 dark:border-slate-700"
        }`}
      >
        Go to Home
      </Link>
    </div>
  );
}
