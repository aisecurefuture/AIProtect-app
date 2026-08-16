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
