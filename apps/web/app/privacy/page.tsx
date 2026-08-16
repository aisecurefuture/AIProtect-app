"use client";
import { useState } from "react";
import { checkPrivacy, ApiError } from "@/lib/api";
import { privacyView, type PrivacyView } from "@/lib/protection";
import { StatusCard, Caveats } from "@/components/Status";

export default function PrivacyGuard() {
  const [text, setText] = useState("");
  const [view, setView] = useState<PrivacyView | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function check(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(""); setView(null);
    try { setView(privacyView(await checkPrivacy(text))); }
    catch (err) {
      setError(err instanceof ApiError ? err.message : "We couldn't check this text.");
    } finally { setBusy(false); }
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Privacy Guard</h1>
        <p className="mt-1 text-sm opacity-70">
          Check text for personal information before you share it with an AI assistant.
        </p>
      </header>

      <form onSubmit={check} className="space-y-3">
        <label className="block">
          <span className="sr-only">Text to check</span>
          <textarea
            required rows={7} value={text} onChange={(e) => setText(e.target.value)}
            placeholder="Paste the text you're about to send…"
            className="w-full rounded-lg border border-slate-300 px-3 py-3 dark:border-slate-700 dark:bg-slate-900"
          />
        </label>
        <button type="submit" disabled={busy}
          className="min-h-12 w-full rounded-lg bg-blue-600 font-medium text-white disabled:opacity-60">
          {busy ? "Checking…" : "Check this text"}
        </button>
      </form>

      {/* Said on the page itself, not buried in a policy: the text is sent to
          our servers to be scanned, and is not kept. */}
      <p className="text-xs opacity-60">
        Text you check is sent to our scanner and is not stored.
      </p>

      {error ? (
        <StatusCard tone="attention" headline="We couldn't check that text" detail={error} />
      ) : null}

      {view ? (
        <StatusCard tone={view.tone} headline={view.headline} detail={view.detail}>
          <Caveats caveats={view.caveats} />
          {view.findings.length ? (
            <ul className="mt-3 space-y-1 text-sm">
              {view.findings.map((f, i) => (
                <li key={i}>· {String((f as { type?: string }).type ?? "Sensitive item")}</li>
              ))}
            </ul>
          ) : null}
        </StatusCard>
      ) : null}
    </div>
  );
}
