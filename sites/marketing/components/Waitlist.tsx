"use client";

import { useState } from "react";

/**
 * Email capture, honest about not being wired up yet.
 *
 * There is no signup endpoint: the consumer API has never been deployed. A
 * form that silently swallows an address would be worse than no form -- the
 * person believes they are on a list that does not exist, and finds out by
 * never hearing from us.
 *
 * So: if NEXT_PUBLIC_WAITLIST_ENDPOINT is set at build time, this POSTs to it.
 * If it is not, the button is a mailto and says so. Either way the address
 * reaches a real place.
 */

const ENDPOINT = process.env.NEXT_PUBLIC_WAITLIST_ENDPOINT ?? "";
const CONTACT = "hello@aiprotect.app";

export default function Waitlist() {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "sending" | "done" | "error">("idle");
  const [message, setMessage] = useState("");

  if (!ENDPOINT) {
    // No backend. Say what will happen rather than pretending.
    return (
      <div>
        <a
          href={`mailto:${CONTACT}?subject=${encodeURIComponent("Notify me about AIProtect")}`}
          className="inline-flex min-h-12 items-center justify-center rounded-lg bg-brand-blue px-6 font-medium text-white transition hover:bg-brand-sky"
        >
          Email us to be notified
        </a>
        <p className="mt-2 text-xs text-slate-500">
          Opens your mail app — we haven&rsquo;t built the signup form yet.
        </p>
      </div>
    );
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setState("sending");
    setMessage("");
    try {
      const res = await fetch(ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email }),
      });
      if (!res.ok) throw new Error(String(res.status));
      setState("done");
    } catch {
      // A failed request is not a signup. Say so, and give a route that works.
      setState("error");
      setMessage(`Couldn't add you just now. Email ${CONTACT} and we'll do it by hand.`);
    }
  }

  if (state === "done") {
    return (
      <p className="rounded-lg border border-emerald-800 bg-emerald-950 px-4 py-3 text-sm text-emerald-100">
        You&rsquo;re on the list. We&rsquo;ll email you once, when it opens.
      </p>
    );
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-3 sm:flex-row">
      <label className="flex-1">
        <span className="sr-only">Email address</span>
        <input
          type="email" required autoComplete="email" value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@example.com"
          className="min-h-12 w-full rounded-lg border border-slate-700 bg-[#0e1422] px-4 text-white placeholder:text-slate-600 focus:border-brand-sky focus:outline-none"
        />
      </label>
      <button type="submit" disabled={state === "sending"}
        className="min-h-12 rounded-lg bg-brand-blue px-6 font-medium text-white transition hover:bg-brand-sky disabled:opacity-60">
        {state === "sending" ? "Adding…" : "Notify me"}
      </button>
      {message && (
        <p role="alert" className="text-sm text-amber-300 sm:basis-full">{message}</p>
      )}
    </form>
  );
}
