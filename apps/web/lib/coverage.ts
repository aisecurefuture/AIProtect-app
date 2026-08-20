/**
 * The two coverage choices, and what each one actually costs.
 *
 * These are the only settings in this product that can make somebody's
 * computer behave worse, so the copy is not decoration -- it is the thing
 * that decides whether a customer who turns one on understands what they did.
 * It lives here, tested, rather than being improvised in a component.
 *
 * WHY THAT MATTERS MORE THAN USUAL. On the B2B side, an endpoint failing
 * closed produced "API Error: 403" inside Claude Code. The user concluded
 * their Anthropic account was blocked and uninstalled the security agent to
 * get working again. Nobody had lied to them; nobody had told them either.
 *
 * A consumer has less context than that user did, not more.
 */

export type FailMode = "open" | "closed";

export interface FailModeOption {
  value: FailMode;
  label: string;
  /** What happens. Never a benefit without its cost. */
  detail: string;
  /** The specific thing that goes wrong, when there is one. */
  consequence: string | null;
  recommended: boolean;
}

/**
 * Both options, always presented together.
 *
 * Deliberately not a checkbox labelled "strict mode". A checkbox has an
 * unstated default and a name that flatters one side; two options with their
 * consequences written out do not.
 */
export const FAIL_MODE_OPTIONS: FailModeOption[] = [
  {
    value: "open",
    label: "Let it through, and tell me",
    detail:
      "If we can't check something, you'll see it wasn't checked, and nothing stops working.",
    consequence: "An unchecked link isn't a checked one.",
    recommended: true,
  },
  {
    value: "closed",
    label: "Block it until we can check",
    detail:
      "If we can't check something, it's blocked. This is the safer choice.",
    consequence:
      "If our service is unreachable, some sites and AI assistants will stop working until it's back.",
    recommended: false,
  },
];

export function failModeOption(mode: FailMode | string): FailModeOption {
  return (
    FAIL_MODE_OPTIONS.find((o) => o.value === mode) ?? FAIL_MODE_OPTIONS[0]
  );
}

export interface DeepInspectionCopy {
  headline: string;
  /** What it buys. */
  benefit: string;
  /** Everything it costs, each stated separately so none can be skimmed past. */
  consequences: string[];
  /** The one-line summary of the irreversible part. */
  trustStoreWarning: string;
  actionLabel: string;
}

/**
 * "Protect everything" — the local proxy.
 *
 * This is the most invasive thing the product can do: it installs a root
 * certificate into the machine's trust store so that AI apps with no
 * extension surface (Claude Desktop, the ChatGPT desktop app) can be
 * inspected. It is also the only way to cover them at all.
 *
 * Every consequence below is listed separately and none is folded into a
 * "learn more". A person agreeing to a root certificate on their own computer
 * is entitled to the whole list in front of them.
 */
export function deepInspectionCopy(enabled: boolean): DeepInspectionCopy {
  return {
    headline: enabled ? "Protecting everything" : "Protect everything",
    benefit:
      "Covers desktop AI apps like Claude and ChatGPT, not just your browser. " +
      "Without it, anything outside the browser is unprotected.",
    consequences: [
      "We install a certificate on this computer so we can inspect that traffic. It stays until you remove it or uninstall AIProtect.",
      "Your antivirus may flag the change. That is the certificate being installed, and it is expected.",
      "Some apps pin their own certificates and will refuse to connect. Those apps keep working only if you turn this off.",
      "You'll be asked for your password during setup.",
    ],
    trustStoreWarning:
      "This changes how every app on this computer verifies secure connections.",
    actionLabel: enabled ? "Turn off" : "Turn on during install",
  };
}

/**
 * What a surface is actually covering right now.
 *
 * Returns the honest sentence rather than a percentage or a tick. "Protected"
 * with the proxy off and "protected" with it on are different claims, and a
 * single green state for both is the flattening this product refuses.
 */
export function coverageSummary(deepInspection: boolean): string {
  return deepInspection
    ? "Your browser and your desktop AI apps."
    : "Your browser. Desktop AI apps like Claude and ChatGPT are not covered.";
}
