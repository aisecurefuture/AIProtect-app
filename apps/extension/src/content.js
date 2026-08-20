/**
 * Privacy Guard, on AI assistant pages only.
 *
 * WHAT THIS SCRIPT CAN SEE, said plainly because it matters: on the handful
 * of AI sites in the manifest, it reads the text in the prompt box at the
 * moment you try to send it. It reads nothing on any other site -- the
 * extension holds no host permissions for the rest of the web.
 *
 * The text goes to our scanner and is not stored. It is never written to
 * storage, never logged, and never sent anywhere else.
 */
import { detectService, sitesWeCannotSee } from "./ai-services.js";
import { checkText, isEnrolled } from "./api.js";
import { submissionDecision, ALLOW } from "./verdict.js";

const service = detectService(location.hostname);
if (service) init();

async function init() {
  if (!(await isEnrolled())) return;

  const missing = sitesWeCannotSee(document, service);
  if (missing) {
    // The selectors are private details of somebody else's app and they move.
    // Report it rather than sitting attached to nothing behind a green badge.
    chrome.runtime.sendMessage({ type: "selectorsStale", service: missing });
    return;
  }

  const input = document.querySelector(service.inputSelector);
  if (!input) return;

  let cleared = false;   // set once the person has chosen to send anyway

  async function gate(event) {
    if (cleared) { cleared = false; return; }
    const text = (input.value ?? input.textContent ?? "").trim();
    if (text.length < 12) return;      // too short to hold anything meaningful

    event.preventDefault();
    event.stopPropagation();

    const { ok, result, failMode } = await checkText(text);
    const decision = submissionDecision(result, { ok }, failMode);

    if (decision.action === ALLOW) { cleared = true; resend(event); return; }

    // Always dismissible. An extension that refuses to let somebody type into
    // ChatGPT gets uninstalled, and an uninstalled extension protects nobody.
    if (window.confirm(`AIProtect\n\n${decision.notice}\n\nSend anyway?`)) {
      cleared = true;
      resend(event);
    }
  }

  function resend(event) {
    if (event.type === "keydown") {
      input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    } else {
      event.target?.click?.();
    }
  }

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) gate(e);
  }, true);

  const submit = document.querySelector(service.submitSelector);
  submit?.addEventListener("click", gate, true);
}
