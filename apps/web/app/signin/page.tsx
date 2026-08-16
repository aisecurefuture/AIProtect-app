"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { requestCode, verifyCode, setToken, ApiError } from "@/lib/api";

// Passwordless: no password to choose, forget, reuse or leak, and no reset
// flow to attack. Two steps, one field each.
export default function SignIn() {
  const router = useRouter();
  const [stage, setStage] = useState<"email" | "code">("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function send(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError("");
    try { await requestCode(email); setStage("code"); }
    catch (err) { setError(err instanceof ApiError ? err.message : "Something went wrong."); }
    finally { setBusy(false); }
  }

  async function confirm(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError("");
    try {
      const out = await verifyCode(email, code);
      setToken(out.token);
      router.replace("/home");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong.");
    } finally { setBusy(false); }
  }

  return (
    <div className="mx-auto max-w-sm pt-10">
      <h1 className="text-2xl font-semibold">AIProtect</h1>
      <p className="mt-1 text-sm opacity-70">AI security for your everyday devices.</p>

      {stage === "email" ? (
        <form onSubmit={send} className="mt-8 space-y-4">
          <label className="block">
            <span className="text-sm font-medium">Email</span>
            <input
              type="email" required autoComplete="email" value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-3 dark:border-slate-700 dark:bg-slate-900"
            />
          </label>
          <button type="submit" disabled={busy}
            className="min-h-12 w-full rounded-lg bg-blue-600 font-medium text-white disabled:opacity-60">
            {busy ? "Sending…" : "Email me a code"}
          </button>
        </form>
      ) : (
        <form onSubmit={confirm} className="mt-8 space-y-4">
          <p className="text-sm">We sent a code to <strong>{email}</strong>.</p>
          <label className="block">
            <span className="text-sm font-medium">Code</span>
            <input
              inputMode="numeric" autoComplete="one-time-code" required value={code}
              onChange={(e) => setCode(e.target.value)}
              className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-3 text-center text-2xl tracking-[0.4em] dark:border-slate-700 dark:bg-slate-900"
            />
          </label>
          <button type="submit" disabled={busy}
            className="min-h-12 w-full rounded-lg bg-blue-600 font-medium text-white disabled:opacity-60">
            {busy ? "Checking…" : "Sign in"}
          </button>
          <button type="button" onClick={() => setStage("email")}
            className="w-full text-sm underline opacity-70">Use a different email</button>
        </form>
      )}

      {error ? <p role="alert" className="mt-4 text-sm text-red-600">{error}</p> : null}
    </div>
  );
}
