import { isEnrolled } from "./src/api.js";

const state = document.getElementById("state");

const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

if (!(await isEnrolled())) {
  // Not enrolled means NOT PROTECTED, and it says so. A popup that showed a
  // neutral "AIProtect" while doing nothing at all is how somebody believes
  // they are covered when they are not.
  state.className = "card bad";
  state.textContent = "This browser isn't set up yet, so nothing is being checked.";
} else {
  const decision = await chrome.runtime.sendMessage({
    type: "lastDecision", url: tab?.url,
  }).catch(() => null);

  if (!decision) {
    state.className = "card good";
    state.textContent = "Protection is on. Nothing to report on this page.";
  } else if (!decision.checked) {
    // The honest middle state: we are on, but this page was not checked.
    state.className = "card warn";
    state.textContent = decision.notice;
  } else if (decision.action === "allow") {
    state.className = "card good";
    state.textContent = "This page looked fine.";
  } else {
    state.className = decision.action === "block" ? "card bad" : "card warn";
    state.textContent = decision.notice;
  }
}

document.getElementById("setup").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});
