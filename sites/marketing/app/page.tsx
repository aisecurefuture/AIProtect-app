import Image from "next/image";
import { tiers, trial, annualMonthly } from "@/lib/tiers";
import Waitlist from "@/components/Waitlist";

/**
 * THE CONSTRAINT ON THIS PAGE: it may only claim what the code does.
 *
 * This product inspects AI traffic and checks URLs. It does NOT parse
 * documents -- there is no PDF, DOCX, XLSX or OCR capability anywhere in the
 * codebase -- and it is not antivirus. Every sentence below is checkable
 * against something that exists, and the "What we don't do" section exists so
 * the limits are on the same page as the promises rather than in a support
 * article nobody reads.
 *
 * Nothing is deployed yet, so the call to action is a waitlist, not a buy
 * button. A "Get started" that leads nowhere is worse than the holding page
 * it replaces.
 */

const FEATURES = [
  {
    name: "Safe Links",
    line: "Checks a link before the page opens.",
    body:
      "Paste a link, or let the browser extension check it as you click. You " +
      "get one of three answers — safe, be careful, or blocked — with a plain " +
      "sentence saying why, and a list of what we actually checked.",
  },
  {
    name: "Privacy Guard",
    line: "Warns you before you share personal information with an AI.",
    body:
      "On ChatGPT, Claude, Gemini and others, we read the text in the box at " +
      "the moment you press send and tell you if it contains passwords, keys " +
      "or personal details. You can always send it anyway.",
  },
  {
    name: "AI Safety",
    line: "Spots pages that try to hijack an AI assistant.",
    body:
      "Some web pages hide instructions aimed at the AI reading them, to make " +
      "it leak information or misbehave. We flag those before they reach your " +
      "assistant.",
  },
];

export default function Home() {
  const plans = tiers();
  const t = trial();

  return (
    <>
      <header className="mx-auto flex max-w-5xl items-center justify-between px-5 py-6">
        <Image src="/lockup-on-dark.png" alt="AIProtect" width={150} height={148}
               priority className="h-10 w-auto" />
        <a href="#pricing" className="text-sm text-slate-300 hover:text-white">Pricing</a>
      </header>

      <main id="main">
        {/* ---------------- hero ---------------- */}
        <section className="mx-auto max-w-5xl px-5 pb-16 pt-8 sm:pt-16">
          <h1 className="max-w-2xl text-4xl font-semibold leading-tight tracking-tight text-white sm:text-5xl">
            AI security for your{" "}
            <span className="text-brand-cyan">everyday devices</span>.
          </h1>
          <p className="mt-5 max-w-xl text-lg text-slate-300">
            The protection businesses buy, built for one person and the people
            they share a home with. Checks the links you open. Warns you before
            you hand personal information to an AI.
          </p>
          <div className="mt-8 max-w-md">
            <Waitlist />
          </div>
          <p className="mt-4 text-sm text-slate-500">
            Not open yet — we&rsquo;ll email you once, when it is.
          </p>
        </section>

        {/* ---------------- what it does ---------------- */}
        <section className="border-t border-slate-800/80 bg-[#0b0f1a]">
          <div className="mx-auto max-w-5xl px-5 py-16">
            <h2 className="text-2xl font-semibold text-white">What it does</h2>
            <div className="mt-8 grid gap-6 sm:grid-cols-3">
              {FEATURES.map((f) => (
                <div key={f.name} className="rounded-2xl border border-slate-800 bg-[#0e1422] p-6">
                  <h3 className="font-semibold text-brand-sky">{f.name}</h3>
                  <p className="mt-2 font-medium text-slate-200">{f.line}</p>
                  <p className="mt-3 text-sm leading-relaxed text-slate-400">{f.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ---------------- honesty ---------------- */}
        <section className="mx-auto max-w-5xl px-5 py-16">
          <h2 className="text-2xl font-semibold text-white">What we can and can&rsquo;t see</h2>
          <div className="mt-8 grid gap-6 sm:grid-cols-2">
            <div className="rounded-2xl border border-slate-800 p-6">
              <h3 className="font-semibold text-slate-200">What we look at</h3>
              <ul className="mt-3 space-y-2 text-sm text-slate-400">
                <li>· Links you check, or click with the extension installed.</li>
                <li>· Text you&rsquo;re about to send to an AI assistant, at the moment you send it.</li>
                <li>· Only on the handful of AI sites we list — nowhere else on the web.</li>
              </ul>
            </div>
            {/* The limits sit beside the promises on purpose. A capability we
                do not have is a support ticket at best and a breach of trust
                at worst. */}
            <div className="rounded-2xl border border-slate-800 p-6">
              <h3 className="font-semibold text-slate-200">What we don&rsquo;t do</h3>
              <ul className="mt-3 space-y-2 text-sm text-slate-400">
                <li>· We don&rsquo;t open your documents. No PDFs, spreadsheets or photos.</li>
                <li>· We don&rsquo;t store the text you check.</li>
                <li>· We&rsquo;re not antivirus, and we don&rsquo;t scan your files.</li>
                <li>· We don&rsquo;t read your email or your messages.</li>
              </ul>
            </div>
          </div>
        </section>

        {/* ---------------- pricing ---------------- */}
        <section id="pricing" className="border-t border-slate-800/80 bg-[#0b0f1a]">
          <div className="mx-auto max-w-5xl px-5 py-16">
            <h2 className="text-2xl font-semibold text-white">Pricing</h2>
            <p className="mt-2 text-slate-400">
              {t.days}-day free trial. One subscription covers every device you own.
            </p>

            <div className="mt-8 grid gap-6 sm:grid-cols-3">
              {plans.map((p) => {
                const a = annualMonthly(p);
                const featured = p.id === "pro";
                return (
                  <div key={p.id}
                       className={`rounded-2xl border p-6 ${
                         featured ? "border-brand-sky bg-[#0e1422]" : "border-slate-800"
                       }`}>
                    {featured && (
                      <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-brand-sky">
                        Most people
                      </p>
                    )}
                    <h3 className="text-lg font-semibold text-white">{p.display_name}</h3>
                    <p className="mt-3">
                      <span className="text-3xl font-semibold text-white">${a.perMonth}</span>
                      <span className="text-slate-400"> /month</span>
                    </p>
                    <p className="mt-1 text-sm text-slate-500">
                      ${p.price_annual}/year — save {a.savePct}%. Or ${p.price_monthly} monthly.
                    </p>
                    <ul className="mt-5 space-y-2 text-sm text-slate-300">
                      <li>{p.devices} devices</li>
                      <li>{p.people === 1 ? "1 person" : `Up to ${p.people} people`}</li>
                      <li>Everything above, on every device</li>
                    </ul>
                  </div>
                );
              })}
            </div>

            {/* Said plainly because per-device add-ons are what people expect
                and being clear costs nothing. */}
            <p className="mt-6 text-sm text-slate-500">
              No per-device fees. If you need more devices, move up a plan.
              A laptop running the browser extension and the desktop app counts
              as one device.
            </p>
          </div>
        </section>

        {/* ---------------- where it runs ---------------- */}
        <section className="mx-auto max-w-5xl px-5 py-16">
          <h2 className="text-2xl font-semibold text-white">Where it runs</h2>
          <p className="mt-3 max-w-2xl text-slate-400">
            A browser extension for Chrome and Edge, and a web dashboard that
            works on a phone, a tablet or a desktop. Apps for iPhone, iPad and
            Android are being built — the plan you buy will cover them when
            they land.
          </p>
        </section>
      </main>

      <footer className="border-t border-slate-800/80">
        <div className="mx-auto flex max-w-5xl flex-col gap-3 px-5 py-10 text-sm text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <p>© {new Date().getFullYear()} AIProtect</p>
          <p>
            Built by the team behind{" "}
            <a href="https://cyberarmor.ai" className="text-brand-sky hover:underline">
              CyberArmor.ai
            </a>
          </p>
        </div>
      </footer>
    </>
  );
}
