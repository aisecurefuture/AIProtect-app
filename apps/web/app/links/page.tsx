"use client";
import { useState } from "react";
import { checkLink, ApiError } from "@/lib/api";
import { verdictView, type VerdictView } from "@/lib/protection";
import { StatusCard, ChecksPerformed } from "@/components/Status";

export default function SafeLinks() {
  const [url, setUrl] = useState("");
  const [view, setView] = useState<VerdictView | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function check(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(""); setView(null);
    try {
      const out = await checkLink(url);
      setView(verdictView(out.consumer));
    } catch (err) {
      // A failed check is NOT a safe verdict. Say we could not check.
      setError(err instanceof ApiError ? err.message : "We couldn't check this link.");
    } finally { setBusy(false); }
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Safe Links</h1>
        <p className="mt-1 text-sm opacity-70">Paste a link and we'll tell you what we find.</p>
      </header>

      <form onSubmit={check} className="space-y-3">
        <label className="block">
          <span className="sr-only">Link</span>
          <input
            type="url" required inputMode="url" placeholder="https://…" value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="w-full rounded-lg border border-slate-300 px-3 py-3 dark:border-slate-700 dark:bg-slate-900"
          />
        </label>
        <button type="submit" disabled={busy}
          className="min-h-12 w-full rounded-lg bg-blue-600 font-medium text-white disabled:opacity-60">
          {busy ? "Checking…" : "Check this link"}
        </button>
      </form>

      {error ? (
        <StatusCard tone="attention" headline="We couldn't check that link" detail={error} />
      ) : null}

      {view ? (
        <StatusCard tone={view.tone} headline={view.headline} detail={view.detail}>
          <ChecksPerformed checks={view.checked} />
          {view.qualified ? (
            <p className="mt-3 text-sm font-medium">
              We haven't opened this page ourselves, so treat it with normal care.
            </p>
          ) : null}
        </StatusCard>
      ) : null}
    </div>
  );
}
