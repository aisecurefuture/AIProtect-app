import fs from "node:fs";
import path from "node:path";

/**
 * Pricing, read from shared/tiers.json AT BUILD TIME.
 *
 * Not retyped into this file. A price on a marketing page that disagrees with
 * the entitlement check is a customer billed for one thing and given another,
 * and the marketing copy is the one people screenshot. `output: "export"`
 * means this runs during `next build`, so the numbers are frozen into the HTML
 * from the same file the API reads.
 *
 * If the build fails here, the fix is to build from the repo root, not to
 * hardcode a number.
 */

export interface Tier {
  id: string;
  display_name: string;
  devices: number;
  people: number;
  price_monthly: number;
  price_annual: number;
}

interface TiersFile {
  upgrade_path: string[];
  tiers: Record<string, Omit<Tier, "id">>;
  trial: { days: number; card_required: boolean; reminder_days_before_charge: number };
}

function load(): TiersFile {
  const p = path.join(process.cwd(), "..", "..", "shared", "tiers.json");
  return JSON.parse(fs.readFileSync(p, "utf8")) as TiersFile;
}

export function tiers(): Tier[] {
  const d = load();
  return d.upgrade_path.map((id) => ({ id, ...d.tiers[id] }));
}

export function trial() {
  return load().trial;
}

/** Monthly-equivalent of the annual price, and the saving, both derived. */
export function annualMonthly(t: Tier): { perMonth: string; savePct: number } {
  const perMonth = t.price_annual / 12;
  const savePct = Math.round((1 - t.price_annual / (t.price_monthly * 12)) * 100);
  return { perMonth: perMonth.toFixed(2), savePct };
}
