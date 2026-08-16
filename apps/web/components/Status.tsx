import type { Tone } from "@/lib/protection";

const TONE_STYLES: Record<Tone, string> = {
  good: "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-100",
  attention:
    "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-100",
  bad: "border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950 dark:text-red-100",
};

/**
 * Colour is never the only signal.
 *
 * A red and an amber card differ by hue alone for a person with a colour
 * vision deficiency, and this is a security product -- the difference between
 * "blocked" and "be careful" has to survive that. Each tone carries a word and
 * a symbol as well, and the symbol is aria-hidden so a screen reader gets the
 * word rather than a decorative glyph.
 */
const TONE_WORD: Record<Tone, { label: string; mark: string }> = {
  good: { label: "OK", mark: "✓" },
  attention: { label: "Caution", mark: "!" },
  bad: { label: "Blocked", mark: "✕" },
};

export function StatusCard({
  tone,
  headline,
  detail,
  children,
}: {
  tone: Tone;
  headline: string;
  detail?: string;
  children?: React.ReactNode;
}) {
  const word = TONE_WORD[tone];
  return (
    <section className={`rounded-2xl border p-5 ${TONE_STYLES[tone]}`}>
      <div className="flex items-start gap-3">
        <span
          aria-hidden="true"
          className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-sm font-bold"
        >
          {word.mark}
        </span>
        <div className="min-w-0">
          <h2 className="text-lg font-semibold">
            <span className="sr-only">{word.label}: </span>
            {headline}
          </h2>
          {detail ? <p className="mt-1 text-sm opacity-90">{detail}</p> : null}
          {children}
        </div>
      </div>
    </section>
  );
}

/**
 * What we actually did, always visible.
 *
 * Deliberately NOT behind a "details" disclosure. A `safe` that rests on a
 * reputation lookup alone is a weaker claim than one where somebody opened the
 * page, and a person deciding whether to type a password into it deserves that
 * without having to go looking.
 */
export function ChecksPerformed({ checks }: { checks: string[] }) {
  if (!checks?.length) return null;
  return (
    <div className="mt-3">
      <h3 className="text-xs font-semibold uppercase tracking-wide opacity-70">
        What we checked
      </h3>
      <ul className="mt-1 space-y-0.5 text-sm opacity-90">
        {checks.map((c) => (
          <li key={c}>· {c}</li>
        ))}
      </ul>
    </div>
  );
}

export function Caveats({ caveats }: { caveats: string[] }) {
  if (!caveats?.length) return null;
  return (
    <ul className="mt-3 space-y-1 text-sm font-medium">
      {caveats.map((c) => (
        <li key={c}>⚠ {c}</li>
      ))}
    </ul>
  );
}
