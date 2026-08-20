/**
 * The settings that can make a computer behave worse must say so.
 *
 * Both of these are opt-in choices with real costs -- one blocks traffic when
 * our service is down, the other installs a root certificate. A UI that
 * presents either as a plain benefit is how somebody enables it, hits the
 * consequence, and uninstalls the product rather than changing the setting
 * back. That happened on the B2B side with fail-closed.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  FAIL_MODE_OPTIONS,
  failModeOption,
  deepInspectionCopy,
  coverageSummary,
} from "./coverage.ts";

test("both fail modes are offered, never one as a checkbox", () => {
  // A checkbox has an unstated default and a name that flatters one side.
  assert.equal(FAIL_MODE_OPTIONS.length, 2);
  assert.deepEqual(FAIL_MODE_OPTIONS.map((o) => o.value), ["open", "closed"]);
});

test("the safer option states what it breaks", () => {
  // THE CORE PROPERTY. Offering fail-closed without its cost is the setup for
  // an uninstall.
  const closed = failModeOption("closed");
  assert.ok(closed.consequence);
  assert.match(closed.consequence, /stop working/i);
});

test("the permissive option states what it gives up", () => {
  // Symmetry: the recommended option does not get to look free either.
  const open = failModeOption("open");
  assert.ok(open.consequence);
  assert.match(open.consequence, /isn't a checked one/i);
});

test("exactly one option is recommended, and it is the one that doesn't break things", () => {
  const recommended = FAIL_MODE_OPTIONS.filter((o) => o.recommended);
  assert.equal(recommended.length, 1);
  assert.equal(recommended[0].value, "open");
});

test("an unknown mode falls back to the permissive option, never to blocking", () => {
  for (const bad of ["", "closd", "CLOSED", "nonsense"]) {
    assert.equal(failModeOption(bad).value, "open", `fell back wrong for ${bad}`);
  }
});

test("deep inspection names the certificate, the antivirus flag, and the password", () => {
  // A person agreeing to a root certificate on their own machine gets the
  // whole list, not a "learn more".
  const copy = deepInspectionCopy(false);
  const all = copy.consequences.join(" ").toLowerCase();
  assert.match(all, /certificate/);
  assert.match(all, /antivirus/);
  assert.match(all, /password/);
  assert.match(copy.trustStoreWarning.toLowerCase(), /every app/);
});

test("deep inspection says what it costs as well as what it buys", () => {
  const copy = deepInspectionCopy(false);
  assert.ok(copy.benefit.length > 0);
  assert.ok(copy.consequences.length >= 3, "consequences must not be summarised away");
});

test("deep inspection says the certificate persists", () => {
  // The irreversible-ish part. "Until you remove it" is the honest framing.
  const all = deepInspectionCopy(false).consequences.join(" ");
  assert.match(all, /stays until|until you remove/i);
});

test("coverage is described differently with and without the proxy", () => {
  // "Protected" with the proxy off and "protected" with it on are different
  // claims. One green state for both is exactly the flattening this product
  // refuses everywhere else.
  const off = coverageSummary(false);
  const on = coverageSummary(true);
  assert.notEqual(off, on);
  assert.match(off, /not covered/i);
  assert.match(on, /desktop/i);
});
