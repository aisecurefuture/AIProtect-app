/**
 * What the extension does with an answer -- including a non-answer.
 *
 * THE FAIL DIRECTION IS THE WHOLE DESIGN, and it is different for the two
 * features. Getting it backwards either bricks somebody's browser or lets
 * their password through while showing a green tick.
 *
 *   SAFE LINKS   fail OPEN. If the API is unreachable we do not block
 *                navigation. A security extension that stops the web working
 *                whenever its server hiccups is uninstalled within a day, and
 *                an uninstalled extension protects nobody. We say we could
 *                not check, and let the person through.
 *
 *   PRIVACY GUARD fail CLOSED-ish. If we cannot check the text, we WARN before
 *                it is sent. The cost of an unnecessary warning is a click;
 *                the cost of silence is a password pasted into a chatbot. But
 *                we never hard-block: the person can always proceed, because
 *                an extension that refuses to let someone type into ChatGPT is
 *                also uninstalled within a day.
 *
 * The asymmetry is deliberate. Blocking browsing is disproportionate; a
 * dismissible warning is not.
 *
 * ...UNLESS THE PERSON ASKED FOR THE OTHER THING.
 * ===============================================
 * Everything above is the DEFAULT. A customer can set fail mode to `closed`
 * in the portal, and then both features block instead. The default protects
 * someone who never opened the setting; the setting belongs to someone who
 * did, and it must be obeyed by BOTH features or it is a lie.
 *
 * THE DEFECT THIS FILE IS SHAPED TO PREVENT (CyberArmor.ai, 2026-08-06):
 * `transparent_proxy` had one FAIL_OPEN flag. The policy path honoured it;
 * the redact path ignored it and blocked unconditionally. So an endpoint
 * configured fail-open still had its AI traffic blocked, while every
 * description of its configuration said the opposite. It surfaced as
 * "API Error: 403" in Claude Code, the user concluded their Anthropic account
 * was blocked, and uninstalled the agent to get working again.
 *
 * The lesson is structural, not a bug fix: TWO CODE PATHS READING ONE SETTING
 * WILL EVENTUALLY DISAGREE. So neither function below branches on fail mode
 * itself. Both call `failedCheckDecision`, which is the only place in this
 * product that decides what "we could not check" means, and
 * tests/behaviour.test.mjs asserts that no path escapes it.
 */

export const ALLOW = "allow";
export const WARN = "warn";
export const BLOCK = "block";

export const FAIL_OPEN = "open";
export const FAIL_CLOSED = "closed";

/**
 * The B2C default, and it deliberately DIFFERS from CyberArmor.ai's.
 *
 * The B2B default is fail-CLOSED (tenant decision 2026-08-06: block when we
 * cannot check, because it leads customers toward security over convenience).
 * That reasoning depends on there being an administrator who chose it, an IT
 * function to call when the web stops working, and a contract that survives a
 * bad afternoon.
 *
 * A household has none of those. For a consumer, fail-closed means the
 * browser breaks and the product gets uninstalled -- which is not a
 * hypothetical: that is exactly what a *technical* user did on the B2B side
 * within a day. An uninstalled extension protects nobody.
 *
 * So the consumer default is OPEN and the choice is offered in the portal
 * with its consequences spelled out. Changing this constant is a product
 * decision, not a refactor.
 */
export const DEFAULT_FAIL_MODE = FAIL_OPEN;

/**
 * The ONLY place a fail-mode value is interpreted.
 *
 * Anything unrecognised -- undefined, null, a typo, a value from a newer
 * portal this install has not been updated for -- resolves to the default
 * rather than being treated as `closed`. A typo must not silently brick
 * somebody's browsing.
 */
export function resolveFailMode(setting) {
  return setting === FAIL_CLOSED || setting === FAIL_OPEN
    ? setting
    : DEFAULT_FAIL_MODE;
}

/**
 * What "we could not check" means. One decision, both features.
 *
 * `what` is "navigation" or "submission" -- it changes the WORDING, never the
 * action. If it changed the action, this would be two code paths again.
 *
 * The wording is load-bearing. A blocked request that does not identify
 * itself as ours is indistinguishable from the destination being broken, and
 * the customer's rational response to "ChatGPT is broken" is to remove the
 * thing they installed most recently. So every message below says, in its
 * first clause, that this was us and that it was because we could not check
 * -- not because the thing was unsafe.
 */
export function failedCheckDecision(what, failMode, { partial = false, found = 0 } = {}) {
  const mode = resolveFailMode(failMode);
  const submission = what === "submission";

  // WHAT went wrong -- wording only. Never the action.
  const because = partial
    ? found
      ? `found ${found} thing(s) but didn't finish checking`
      : "didn't finish checking"
    : submission
      ? "couldn't check this text"
      : "couldn't check this link";

  if (mode === FAIL_CLOSED) {
    return {
      action: BLOCK,
      notice:
        `AIProtect ${because}, and your settings say to block when that ` +
        `happens. This is usually temporary — it doesn't mean anything is ` +
        `wrong with the site.`,
      checked: false,
      failMode: mode,
    };
  }

  return {
    action: submission ? WARN : ALLOW,
    notice: submission
      ? `We ${because} for personal information. Send it anyway?`
      : `We ${because}, so we haven't blocked it.`,
    checked: false,
    failMode: mode,
  };
}

/**
 * Navigation decision from a trust-gate consumer verdict.
 *
 * @param {{verdict?: string, reason?: string, page_was_read?: boolean}|null} consumer
 * @param {{ok: boolean}} status  whether we got an answer at all
 */
export function navigationDecision(consumer, status = { ok: true }, failMode) {
  if (!status.ok) {
    // NOT decided here -- see failedCheckDecision. Two paths reading one
    // setting is the 2026-08-06 defect; there is one path.
    return failedCheckDecision("navigation", failMode);
  }
  const verdict = consumer?.verdict;
  if (verdict === "blocked") {
    return {
      action: BLOCK,
      notice: consumer.reason || "This site looks dangerous.",
      checked: true,
    };
  }
  if (verdict === "caution") {
    return {
      action: WARN,
      notice: consumer.reason || "Something about this page looks risky.",
      checked: true,
    };
  }
  if (verdict === "safe") {
    return { action: ALLOW, notice: "", checked: true };
  }
  // Unknown verdict: not good news, but not worth blocking on either.
  return {
    action: WARN,
    notice: "We couldn't reach a clear verdict on this page.",
    checked: true,
  };
}

/**
 * Whether to interrupt a submission to an AI assistant.
 *
 * @param {{found?: unknown[], scan_complete?: boolean}|null} result
 * @param {{ok: boolean}} status
 */
export function submissionDecision(result, status = { ok: true }, failMode) {
  if (!status.ok) {
    return failedCheckDecision("submission", failMode);
  }

  const found = result?.found ?? [];

  // An incomplete scan is NOT a clean scan. Saying nothing here would be the
  // detection service's `scan_complete` flag being thrown away at the last
  // possible moment -- by the surface the person is actually looking at.
  if (result?.scan_complete === false) {
    // A PARTIAL check is a kind of failed check, so it goes through the SAME
    // decision rather than branching on the mode again. Leaving it an
    // unconditional WARN would put a hole in fail-closed at exactly the point
    // the detection service went to trouble to tell us it had not finished.
    return failedCheckDecision("submission", failMode, {
      partial: true,
      found: found.length,
    });
  }

  if (found.length) {
    return {
      action: WARN,
      notice: `This looks like it contains ${found.length} piece(s) of personal information.`,
      checked: true,
    };
  }

  return { action: ALLOW, notice: "", checked: true };
}

/**
 * Whether the person can click through.
 *
 * Under the default (fail-open) a submission is never hard-blocked, so this
 * is always true for Privacy Guard. Under fail-CLOSED it is false -- which is
 * the entire point of having chosen it. The asymmetry in the header describes
 * the default, not a guarantee that overrides the customer's own setting.
 */
export function isDismissible(decision) {
  return decision.action !== BLOCK;
}
