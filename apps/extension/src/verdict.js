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
 */

export const ALLOW = "allow";
export const WARN = "warn";
export const BLOCK = "block";

/**
 * Navigation decision from a trust-gate consumer verdict.
 *
 * @param {{verdict?: string, reason?: string, page_was_read?: boolean}|null} consumer
 * @param {{ok: boolean}} status  whether we got an answer at all
 */
export function navigationDecision(consumer, status = { ok: true }) {
  if (!status.ok) {
    // Fail open, and SAY so. Silently allowing would let a person believe the
    // check happened; blocking would break the web on a server blip.
    return {
      action: ALLOW,
      notice: "We couldn't check this link, so we haven't blocked it.",
      checked: false,
    };
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
export function submissionDecision(result, status = { ok: true }) {
  if (!status.ok) {
    return {
      action: WARN,
      notice:
        "We couldn't check this text for personal information. Send it anyway?",
      checked: false,
    };
  }

  const found = result?.found ?? [];

  // An incomplete scan is NOT a clean scan. Saying nothing here would be the
  // detection service's `scan_complete` flag being thrown away at the last
  // possible moment -- by the surface the person is actually looking at.
  if (result?.scan_complete === false) {
    return {
      action: WARN,
      notice: found.length
        ? `We found ${found.length} thing(s), and some checks didn't finish.`
        : "Some checks didn't finish, so we may have missed something.",
      checked: false,
    };
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

/** Never hard-blocks a submission. See the header. */
export function isDismissible(decision) {
  return decision.action !== BLOCK;
}
