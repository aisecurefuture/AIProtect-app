/**
 * The extension's two failure directions, and the host matching under them.
 *
 *   node --test tests/
 *
 * These are the assertions that keep the extension from being either useless
 * or dangerous. Both failure modes are easy to ship and neither shows up in
 * manual testing, because manual testing happens with the API running.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  detectService,
  isAiApiRequest,
  sitesWeCannotSee,
} from "../src/ai-services.js";
import {
  navigationDecision,
  submissionDecision,
  isDismissible,
  ALLOW,
  WARN,
  BLOCK,
} from "../src/verdict.js";

/* ---------------- host matching ---------------- */

test("known AI hosts are detected", () => {
  assert.equal(detectService("chatgpt.com")?.id, "chatgpt");
  assert.equal(detectService("claude.ai")?.id, "claude");
  assert.equal(detectService("gemini.google.com")?.id, "gemini");
  assert.equal(detectService("www.perplexity.ai")?.id, "perplexity");
});

test("subdomains of a known host count", () => {
  assert.equal(detectService("chat.openai.com")?.id, "chatgpt");
});

test("a lookalike host is NOT treated as the real service", () => {
  // A substring test would match these. That would hand a phishing site
  // impersonating Claude the trusted treatment, which is precisely backwards
  // -- the impersonation is the attack.
  assert.equal(detectService("claude.ai.evil.example"), null);
  assert.equal(detectService("notchatgpt.com.attacker.test"), null);
  assert.equal(detectService("evil-claude.ai.co"), null);
});

test("ordinary sites are not AI services", () => {
  assert.equal(detectService("example.com"), null);
  assert.equal(detectService("bbc.co.uk"), null);
});

test("AI API endpoints are recognised", () => {
  assert.ok(isAiApiRequest("https://api.openai.com/v1/chat/completions"));
  assert.ok(isAiApiRequest("https://claude.ai/api/organizations"));
  assert.equal(isAiApiRequest("https://example.com/api/thing"), false);
});

test("a page whose input we cannot find is reported, not assumed fine", () => {
  // These selectors are private details of somebody else's web app and WILL
  // change. A silently-unattached content script showing a protected badge is
  // the defect this returns a value to prevent.
  const service = detectService("chatgpt.com");
  const emptyDoc = { querySelector: () => null };
  assert.equal(sitesWeCannotSee(emptyDoc, service), "ChatGPT");

  const okDoc = { querySelector: () => ({}) };
  assert.equal(sitesWeCannotSee(okDoc, service), null);
});

/* ---------------- safe links: fail OPEN ---------------- */

test("a dangerous page is blocked", () => {
  const d = navigationDecision(
    { verdict: "blocked", reason: "This page is built to capture passwords." },
    { ok: true }
  );
  assert.equal(d.action, BLOCK);
  assert.match(d.notice, /passwords/);
});

test("an unreachable API does NOT block browsing", () => {
  // A security extension that breaks the web whenever its server hiccups is
  // uninstalled within a day, and an uninstalled extension protects nobody.
  const d = navigationDecision(null, { ok: false });
  assert.equal(d.action, ALLOW);
  assert.equal(d.checked, false);
  assert.match(d.notice, /couldn't check/i);
});

test("failing open still tells the person the check did not happen", () => {
  // Silently allowing would let them believe it was checked.
  const d = navigationDecision(null, { ok: false });
  assert.ok(d.notice.length > 0);
});

test("a safe verdict passes quietly", () => {
  const d = navigationDecision({ verdict: "safe", reason: "" }, { ok: true });
  assert.equal(d.action, ALLOW);
  assert.equal(d.notice, "");
  assert.equal(d.checked, true);
});

test("an unknown verdict warns rather than allowing", () => {
  const d = navigationDecision({ verdict: "brand_new_state" }, { ok: true });
  assert.equal(d.action, WARN);
});

/* ---------------- privacy guard: fail toward warning ---------------- */

test("personal information in a prompt produces a warning", () => {
  const d = submissionDecision(
    { found: [{ type: "pii.email" }], scan_complete: true },
    { ok: true }
  );
  assert.equal(d.action, WARN);
});

test("an unreachable API warns before sending, rather than staying silent", () => {
  // Opposite direction to Safe Links, deliberately: the cost of an
  // unnecessary warning is a click; the cost of silence is a password pasted
  // into a chatbot.
  const d = submissionDecision(null, { ok: false });
  assert.equal(d.action, WARN);
  assert.equal(d.checked, false);
});

test("an incomplete scan is not treated as a clean scan", () => {
  const d = submissionDecision(
    { found: [], scan_complete: false },
    { ok: true }
  );
  assert.equal(d.action, WARN);
  assert.equal(d.checked, false);
  assert.match(d.notice, /didn't finish/i);
});

test("a clean complete scan does not interrupt", () => {
  const d = submissionDecision(
    { found: [], scan_complete: true },
    { ok: true }
  );
  assert.equal(d.action, ALLOW);
  assert.equal(d.notice, "");
});

test("a submission warning is always dismissible", () => {
  // An extension that refuses to let somebody type into ChatGPT is also
  // uninstalled within a day. Warn, never forbid.
  for (const status of [{ ok: true }, { ok: false }]) {
    const d = submissionDecision({ found: [{}], scan_complete: true }, status);
    assert.ok(isDismissible(d), "a prompt submission was made un-dismissible");
  }
});

test("the two features fail in OPPOSITE directions", () => {
  // The single most important property in this file. Same outage, different
  // correct response: browsing keeps working, sending gets a warning.
  const nav = navigationDecision(null, { ok: false });
  const sub = submissionDecision(null, { ok: false });
  assert.equal(nav.action, ALLOW);
  assert.equal(sub.action, WARN);
});

/* ---------------- fail mode: one setting, every path ---------------- */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  failedCheckDecision,
  resolveFailMode,
  DEFAULT_FAIL_MODE,
  FAIL_OPEN,
  FAIL_CLOSED,
} from "../src/verdict.js";

const UNREACHABLE = { ok: false };

test("the consumer default is fail-OPEN, and it is a product decision", () => {
  // CyberArmor.ai defaults to fail-CLOSED (tenant decision 2026-08-06). This
  // product defaults the other way on purpose: a household has no admin to
  // call when the browser stops working, and an uninstalled extension
  // protects nobody. Flipping this is a product call, not a refactor.
  assert.equal(DEFAULT_FAIL_MODE, FAIL_OPEN);
  assert.equal(navigationDecision(null, UNREACHABLE).action, ALLOW);
  assert.equal(submissionDecision(null, UNREACHABLE).action, WARN);
});

test("fail-closed blocks BOTH features, not just one", () => {
  // THE CORE PROPERTY, and the exact shape of the 2026-08-06 defect: one
  // setting honoured by one path and ignored by the other, while every
  // description of the configuration claimed otherwise.
  assert.equal(navigationDecision(null, UNREACHABLE, FAIL_CLOSED).action, BLOCK);
  assert.equal(submissionDecision(null, UNREACHABLE, FAIL_CLOSED).action, BLOCK);
});

test("fail-open allows BOTH features to proceed", () => {
  assert.equal(navigationDecision(null, UNREACHABLE, FAIL_OPEN).action, ALLOW);
  assert.notEqual(submissionDecision(null, UNREACHABLE, FAIL_OPEN).action, BLOCK);
});

test("a partial scan obeys the fail mode too", () => {
  // `scan_complete: false` is a kind of failed check. Leaving it an
  // unconditional WARN would put a hole in fail-closed at precisely the point
  // the detection service went to trouble to report.
  const partial = { found: [], scan_complete: false };
  assert.equal(submissionDecision(partial, { ok: true }, FAIL_CLOSED).action, BLOCK);
  assert.equal(submissionDecision(partial, { ok: true }, FAIL_OPEN).action, WARN);
});

test("an unrecognised fail mode resolves to the default, never to blocking", () => {
  // A typo, a null, or a value from a newer portal than this install knows
  // must not silently brick somebody's browsing.
  for (const bad of [undefined, null, "", "closd", "CLOSED", 0, {}, "true"]) {
    assert.equal(resolveFailMode(bad), DEFAULT_FAIL_MODE, `resolved ${JSON.stringify(bad)}`);
    assert.notEqual(navigationDecision(null, UNREACHABLE, bad).action, BLOCK);
  }
});

test("a fail-closed block says it was US and that it is not the site's fault", () => {
  // The uninstall path: a block that does not identify itself is
  // indistinguishable from the destination being broken, and the rational
  // response to "ChatGPT is broken" is to remove what you installed last.
  for (const what of ["navigation", "submission"]) {
    const d = failedCheckDecision(what, FAIL_CLOSED);
    assert.match(d.notice, /AIProtect/, `${what} must name us`);
    assert.match(d.notice, /couldn't/i, `${what} must say we could not check`);
    assert.match(d.notice, /temporary|doesn't mean/i, `${what} must not imply the site is unsafe`);
  }
});

test("a failed check never reports itself as checked", () => {
  for (const mode of [FAIL_OPEN, FAIL_CLOSED]) {
    assert.equal(navigationDecision(null, UNREACHABLE, mode).checked, false);
    assert.equal(submissionDecision(null, UNREACHABLE, mode).checked, false);
  }
});

test("fail-closed makes a submission non-dismissible; fail-open does not", () => {
  assert.equal(isDismissible(submissionDecision(null, UNREACHABLE, FAIL_CLOSED)), false);
  assert.equal(isDismissible(submissionDecision(null, UNREACHABLE, FAIL_OPEN)), true);
});

test("no decision path branches on fail mode on its own", () => {
  // STRUCTURAL, not behavioural. The 2026-08-06 defect was not a wrong
  // branch -- it was a SECOND branch. Behavioural tests above pass just as
  // happily with the logic duplicated in two places, right up until the two
  // copies drift. So: the fail-mode constants may only be compared inside the
  // single resolution point.
  const src = readFileSync(
    fileURLToPath(new URL("../src/verdict.js", import.meta.url)),
    "utf8"
  );
  // Strip block comments -- the header discusses these names at length.
  const code = src.replace(/\/\*[\s\S]*?\*\//g, "");
  const comparisons = code.match(/===\s*FAIL_(OPEN|CLOSED)|FAIL_(OPEN|CLOSED)\s*===/g) ?? [];
  assert.ok(
    comparisons.length <= 3,
    `fail-mode is compared ${comparisons.length} times. It belongs in ` +
      `resolveFailMode() and the two mode checks that consume it -- a new ` +
      `comparison is a second code path reading one setting, which is the ` +
      `defect this file is shaped to prevent.`
  );
});
