/**
 * Turning API responses into what a person sees, WITHOUT flattening them.
 *
 * This is the file where the product's honesty either survives or dies. Three
 * services take real care to distinguish "we checked and it was fine" from "we
 * did not check":
 *
 *   entitlements.py  four subscription states, only one of which stops
 *                    protection, each carrying a reason
 *   consumer_verdict.py  `safe` plus `checks_performed` and `page_was_read`,
 *                    because a reputation-only answer is a weaker claim than
 *                    a fetched-and-scanned one
 *   detection main.py  `scan_complete` and `checks_skipped_by_profile`
 *
 * Every one of those distinctions dies at a `? "Protected" : "Not protected"`
 * ternary in a component. The backend cannot defend itself from the UI, so the
 * mapping lives here, in one tested place, instead of being re-improvised in
 * each screen.
 *
 * THE RULE: a green tick may only be shown for something actually checked.
 */

export type EntitlementState = "trialing" | "active" | "grace" | "lapsed";

export interface Entitlement {
  state: EntitlementState | string;
  tier: string;
  devices_allowed: number;
  people_allowed: number;
  protected: boolean;
  reason: string;
  deadline: string | null;
}

export type Tone = "good" | "attention" | "bad";

export interface StatusBanner {
  tone: Tone;
  headline: string;
  detail: string;
  /** Present when there is something the person can actually do. */
  action?: { label: string; href: string };
  /** ISO date. A countdown is only honest if the deadline is real. */
  deadline?: string | null;
}

/**
 * The top-of-Home banner.
 *
 * `grace` is deliberately "attention", not "bad": the devices ARE protected.
 * Rendering a failed payment as an outage would frighten someone whose
 * protection is working, and rendering it as fine would hide a deadline.
 */
export function statusBanner(e: Entitlement): StatusBanner {
  if (!e.protected) {
    return {
      tone: "bad",
      headline: "Your devices are not protected",
      detail: e.reason || "Your subscription has ended.",
      action: { label: "Restart your subscription", href: "/settings#billing" },
    };
  }

  if (e.state === "grace") {
    return {
      tone: "attention",
      headline: "Your devices are still protected",
      detail: e.reason || "There's a problem with your subscription.",
      action: { label: "Fix payment", href: "/settings#billing" },
      deadline: e.deadline,
    };
  }

  if (e.state === "trialing") {
    return {
      tone: "good",
      headline: "You're protected",
      detail: "You're on a free trial. We'll remind you before it ends.",
      deadline: e.deadline,
    };
  }

  return { tone: "good", headline: "You're protected", detail: "" };
}

/* ------------------------------------------------------------------ */
/* Safe Links                                                          */
/* ------------------------------------------------------------------ */

export interface ConsumerVerdict {
  verdict: "safe" | "caution" | "blocked" | string;
  reason: string;
  checks_performed: string[];
  page_was_read: boolean;
}

export interface VerdictView {
  tone: Tone;
  headline: string;
  detail: string;
  /**
   * What we actually did, in words. Always rendered -- never behind a
   * "details" toggle. A person deciding whether to type a password into a page
   * deserves to know whether anybody opened it.
   */
  checked: string[];
  /** True when `safe` rests on reputation alone and nobody read the page. */
  qualified: boolean;
}

const CHECK_LABELS: Record<string, string> = {
  reputation_lookup: "Checked against known-bad lists",
  previous_result_reused: "Used a recent result for this link",
  page_fetched_and_scanned: "Opened and scanned the page",
  opened_in_sandbox: "Opened the page in a safe sandbox",
  page_not_fetched: "Did not open the page itself",
};

export function verdictView(v: ConsumerVerdict): VerdictView {
  const checked = (v.checks_performed || []).map((c) => CHECK_LABELS[c] ?? c);

  if (v.verdict === "blocked") {
    return {
      tone: "bad",
      headline: "Blocked",
      detail: v.reason,
      checked,
      qualified: false,
    };
  }
  if (v.verdict === "caution") {
    return {
      tone: "attention",
      headline: "Be careful",
      detail: v.reason,
      checked,
      qualified: false,
    };
  }
  if (v.verdict === "safe") {
    // THE ONE THAT MATTERS. `safe` from a reputation-only lookup is not the
    // same claim as `safe` from a page somebody actually read, and the
    // headline says so rather than hiding it in a tooltip.
    return {
      tone: "good",
      headline: v.page_was_read ? "Looks safe" : "Nothing known against it",
      detail: v.reason,
      checked,
      qualified: !v.page_was_read,
    };
  }

  // An unrecognised verdict is not good news. Never fall through to "safe".
  return {
    tone: "attention",
    headline: "We couldn't reach a verdict",
    detail: v.reason || "Treat this link with caution.",
    checked,
    qualified: true,
  };
}

/* ------------------------------------------------------------------ */
/* Privacy Guard                                                       */
/* ------------------------------------------------------------------ */

export interface PrivacyResult {
  found: Array<Record<string, unknown>>;
  scan_complete: boolean;
  checks_skipped_by_profile: string[];
}

export interface PrivacyView {
  tone: Tone;
  headline: string;
  detail: string;
  findings: Array<Record<string, unknown>>;
  /** Non-empty when the answer is incomplete. Rendered, never dropped. */
  caveats: string[];
}

export function privacyView(r: PrivacyResult): PrivacyView {
  const caveats: string[] = [];

  // A scan whose detector never ran is not a scan that found nothing. Saying
  // "nothing sensitive found" on an incomplete scan is the exact defect the
  // detection service adds `scan_complete` to prevent.
  if (r.scan_complete === false) {
    caveats.push(
      "Some checks didn't finish, so we may have missed something."
    );
  }
  for (const skipped of r.checks_skipped_by_profile || []) {
    if (skipped === "output_safety") continue; // not user-facing here
    caveats.push(`We don't run the ${skipped.replace(/_/g, " ")} check on your plan.`);
  }

  const count = (r.found || []).length;

  if (count > 0) {
    return {
      tone: "attention",
      headline: `Found ${count} thing${count === 1 ? "" : "s"} worth a second look`,
      detail: "Check these before you share this text with an AI assistant.",
      findings: r.found,
      caveats,
    };
  }

  return {
    tone: caveats.length ? "attention" : "good",
    headline: caveats.length
      ? "We didn't find anything, but the check was incomplete"
      : "Nothing sensitive found",
    detail: caveats.length
      ? ""
      : "We didn't spot personal information in this text.",
    findings: [],
    caveats,
  };
}

/* ------------------------------------------------------------------ */
/* Devices                                                             */
/* ------------------------------------------------------------------ */

export interface DeviceSummary {
  id: string;
  name: string;
  platform: string | null;
  surfaces: Array<{ kind: string; active: boolean }>;
}

/**
 * "MacBook — extension and desktop app".
 *
 * Surfaces are shown per device so the one-device-many-surfaces model is
 * visible rather than something the person has to infer from a device count
 * that does not match the number of things they installed.
 */
const SURFACE_LABELS: Record<string, string> = {
  "browser-extension": "browser extension",
  "desktop-agent": "desktop app",
  "mobile-app": "mobile app",
};

export function describeDevice(d: DeviceSummary): string {
  const active = (d.surfaces || []).filter((s) => s.active);
  if (!active.length) return "Nothing installed yet";
  return active.map((s) => SURFACE_LABELS[s.kind] ?? s.kind).join(" and ");
}

export function capMessage(inUse: number, allowed: number, upgradeTo?: string | null): string {
  if (inUse < allowed) {
    const left = allowed - inUse;
    return `${inUse} of ${allowed} devices — room for ${left} more`;
  }
  // At the cap there is no per-device add-on, so the only route is an upgrade.
  return upgradeTo
    ? `All ${allowed} devices in use. Upgrade to ${upgradeTo} to add more.`
    : `All ${allowed} devices in use. Remove one to add another.`;
}
