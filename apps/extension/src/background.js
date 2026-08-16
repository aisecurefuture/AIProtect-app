/**
 * Service worker: Safe Links.
 *
 * Checks a URL BEFORE the page loads, using webNavigation. The extension
 * never reads page content to do this -- the URL is enough, which is why it
 * asks for no host permissions beyond our own API.
 */
import { checkLink, isEnrolled } from "./api.js";
import { navigationDecision, BLOCK, WARN } from "./verdict.js";

// Only top-level navigations a person actually initiated. Checking every
// subframe would multiply requests by the ad count on a page.
const recent = new Map();          // url -> {decision, at}
const RECENT_TTL_MS = 60_000;

function remember(url, decision) {
  recent.set(url, { decision, at: Date.now() });
  if (recent.size > 200) recent.delete(recent.keys().next().value);
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (!/^https?:/.test(url)) return;
  if (!(await isEnrolled())) return;   // not signed in: do nothing, quietly

  const cached = recent.get(url);
  if (cached && Date.now() - cached.at < RECENT_TTL_MS) return;

  const { ok, consumer } = await checkLink(url);
  const decision = navigationDecision(consumer, { ok });
  remember(url, decision);

  if (decision.action === BLOCK) {
    // Replace the tab rather than closing it: a tab that vanishes looks like
    // a crash, and the person needs to be told what happened and be able to
    // go anyway if they judge it a false positive.
    const target = chrome.runtime.getURL(
      `blocked.html?url=${encodeURIComponent(url)}&reason=${encodeURIComponent(decision.notice)}`
    );
    chrome.tabs.update(details.tabId, { url: target });
    chrome.notifications?.create({
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title: "AIProtect blocked a page",
      message: decision.notice,
    });
    return;
  }

  if (decision.action === WARN && decision.checked) {
    chrome.action.setBadgeText({ tabId: details.tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: "#d97706" });
  }
});

// The popup asks for the last decision on the tab it is opened over.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "lastDecision") {
    const entry = recent.get(msg.url);
    sendResponse(entry?.decision ?? null);
  }
  return true;
});
