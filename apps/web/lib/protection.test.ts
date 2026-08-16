/**
 * The UI must not flatten what the services took care to distinguish.
 *
 * Three services carefully separate "checked and fine" from "did not check".
 * Every one of those distinctions dies at a `? "Protected" : "Not protected"`
 * ternary, and the backend cannot defend itself from the frontend. These are
 * the assertions that keep the mapping honest.
 *
 *   node --test --experimental-strip-types lib/*.test.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  statusBanner,
  verdictView,
  privacyView,
  describeDevice,
  capMessage,
  type Entitlement,
} from "./protection.ts";

const ent = (over: Partial<Entitlement> = {}): Entitlement => ({
  state: "active",
  tier: "personal",
  devices_allowed: 3,
  people_allowed: 1,
  protected: true,
  reason: "",
  deadline: null,
  ...over,
});

/* ---------------- subscription status ---------------- */

test("an active subscription reads as protected", () => {
  assert.equal(statusBanner(ent()).tone, "good");
});

test("grace is 'attention', not 'bad' -- the devices ARE protected", () => {
  const b = statusBanner(
    ent({ state: "grace", reason: "There is a problem with your subscription.",
          deadline: "2026-09-01T00:00:00Z" })
  );
  assert.equal(b.tone, "attention");
  assert.match(b.headline, /still protected/i);
  assert.equal(b.deadline, "2026-09-01T00:00:00Z");
});

test("grace never renders as an outage", () => {
  // Frightening someone whose protection is working is its own harm.
  const b = statusBanner(ent({ state: "grace", reason: "Card declined." }));
  assert.notEqual(b.tone, "bad");
  assert.doesNotMatch(b.headline, /not protected/i);
});

test("lapsed says why and what to do", () => {
  const b = statusBanner(
    ent({ state: "lapsed", protected: false, reason: "Your subscription ended." })
  );
  assert.equal(b.tone, "bad");
  assert.ok(b.detail.length > 0, "must say why");
  assert.ok(b.action, "must offer a way back");
});

test("a trial shows its deadline", () => {
  const b = statusBanner(
    ent({ state: "trialing", deadline: "2026-08-30T00:00:00Z" })
  );
  assert.equal(b.tone, "good");
  assert.equal(b.deadline, "2026-08-30T00:00:00Z");
});

/* ---------------- safe links ---------------- */

test("a fetched page and an unfetched one do not read the same", () => {
  // THE CORE PROPERTY. `safe` from reputation alone is a weaker claim than
  // `safe` from a page somebody actually opened, and the headline says so.
  const read = verdictView({
    verdict: "safe", reason: "We checked this page and found nothing harmful.",
    checks_performed: ["reputation_lookup", "page_fetched_and_scanned"],
    page_was_read: true,
  });
  const unread = verdictView({
    verdict: "safe",
    reason: "Nothing is known against this link, but we have not opened it.",
    checks_performed: ["reputation_lookup", "page_not_fetched"],
    page_was_read: false,
  });

  assert.notEqual(read.headline, unread.headline);
  assert.equal(read.qualified, false);
  assert.equal(unread.qualified, true);
});

test("what was actually checked is always rendered", () => {
  const v = verdictView({
    verdict: "safe", reason: "ok",
    checks_performed: ["reputation_lookup", "page_not_fetched"],
    page_was_read: false,
  });
  assert.ok(v.checked.length >= 2);
  assert.ok(v.checked.some((c) => /did not open/i.test(c)));
});

test("blocked and caution keep their severity", () => {
  assert.equal(
    verdictView({ verdict: "blocked", reason: "x", checks_performed: [], page_was_read: true }).tone,
    "bad"
  );
  assert.equal(
    verdictView({ verdict: "caution", reason: "x", checks_performed: [], page_was_read: true }).tone,
    "attention"
  );
});

test("an unknown verdict never renders as safe", () => {
  const v = verdictView({
    verdict: "some_new_state", reason: "", checks_performed: [], page_was_read: false,
  });
  assert.notEqual(v.tone, "good");
  assert.equal(v.qualified, true);
});

/* ---------------- privacy guard ---------------- */

test("an incomplete scan does not claim nothing was found", () => {
  // A scan whose detector never ran is not a scan that found nothing.
  const v = privacyView({ found: [], scan_complete: false, checks_skipped_by_profile: [] });
  assert.notEqual(v.tone, "good");
  assert.ok(v.caveats.length > 0);
  assert.match(v.headline, /incomplete/i);
});

test("a complete scan with no findings is allowed to say so", () => {
  const v = privacyView({ found: [], scan_complete: true, checks_skipped_by_profile: [] });
  assert.equal(v.tone, "good");
  assert.equal(v.caveats.length, 0);
});

test("findings are surfaced with a count", () => {
  const v = privacyView({
    found: [{ type: "pii.email" }, { type: "pii.phone" }],
    scan_complete: true, checks_skipped_by_profile: [],
  });
  assert.equal(v.tone, "attention");
  assert.match(v.headline, /2 things/);
});

/* ---------------- devices ---------------- */

test("a device lists its surfaces, so one laptop is visibly one device", () => {
  const text = describeDevice({
    id: "d", name: "MacBook", platform: "macos",
    surfaces: [
      { kind: "browser-extension", active: true },
      { kind: "desktop-agent", active: true },
    ],
  });
  assert.match(text, /browser extension and desktop app/);
});

test("a revoked surface is not listed as installed", () => {
  const text = describeDevice({
    id: "d", name: "MacBook", platform: "macos",
    surfaces: [
      { kind: "browser-extension", active: false },
      { kind: "desktop-agent", active: true },
    ],
  });
  assert.equal(text, "desktop app");
});

test("at the cap the message offers the upgrade, not an add-on", () => {
  // There is no per-device add-on, so an upgrade is the only route.
  assert.match(capMessage(3, 3, "Pro"), /Upgrade to Pro/);
  assert.match(capMessage(1, 3), /room for 2 more/);
});

test("at the top tier the message offers removal instead", () => {
  assert.match(capMessage(30, 30, null), /Remove one/);
});
