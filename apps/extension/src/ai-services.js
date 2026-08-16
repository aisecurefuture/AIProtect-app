/**
 * Which sites are AI assistants, and where their input boxes are.
 *
 * PROVENANCE: the selectors below are lifted from
 * `extensions/chromium-shared/ai_monitor.js` in CyberArmor.ai (fork point
 * 29b6bf21). They are the one genuinely hard-won asset in that extension --
 * somebody sat with each product's DOM and found the input and submit
 * elements. Recreating them is slow and the result is worse; the rest of that
 * 8,684-line extension is enterprise scaffolding this product does not want.
 *
 * THEY WILL ROT. Every one of these is a private implementation detail of
 * somebody else's web app, and they change without notice. That is why
 * `detectService()` falls back to `generic`, and why a site we cannot find an
 * input on degrades to "we are not watching this page" rather than to silence.
 * See `sitesWeCannotSee()`.
 */

export const SERVICE_SELECTORS = {
  chatgpt: {
    name: "ChatGPT",
    hosts: ["chatgpt.com", "chat.openai.com", "openai.com"],
    inputSelector:
      '#prompt-textarea, textarea[data-id="root"], textarea.prompt-textarea',
    submitSelector:
      'button[data-testid="send-button"], button[data-testid="fruitjuice-send-button"]',
  },
  claude: {
    name: "Claude",
    hosts: ["claude.ai"],
    inputSelector:
      'div[contenteditable="true"].ProseMirror, div[contenteditable="true"]',
    submitSelector:
      'button[aria-label="Send Message"], button[type="submit"]',
  },
  gemini: {
    name: "Gemini",
    hosts: ["gemini.google.com", "bard.google.com"],
    inputSelector:
      '.ql-editor, rich-textarea .textarea, textarea[placeholder*="Enter"]',
    submitSelector: 'button.send-button, button[aria-label="Send message"]',
  },
  copilot: {
    name: "Copilot",
    hosts: ["copilot.microsoft.com", "bing.com"],
    inputSelector:
      '#searchbox, textarea[name="searchbox"], .cib-serp-main textarea',
    submitSelector: 'button[aria-label="Submit"]',
  },
  grok: {
    name: "Grok",
    hosts: ["grok.com", "x.ai"],
    inputSelector:
      'textarea[aria-label*="Ask Grok" i], textarea[aria-label*="Grok" i]',
    submitSelector: 'button[data-testid="chat-submit"], button[type="submit"]',
  },
  perplexity: {
    name: "Perplexity",
    hosts: ["perplexity.ai"],
    inputSelector: 'textarea[placeholder*="Ask" i], div[contenteditable="true"]',
    submitSelector: 'button[aria-label*="Submit" i], button[type="submit"]',
  },
  generic: {
    name: "an AI assistant",
    hosts: [],
    inputSelector:
      'textarea[placeholder*="message" i], textarea[placeholder*="Ask" i], div[contenteditable="true"]',
    submitSelector: 'button[type="submit"]',
  },
};

/** Direct API endpoints. Not user-facing pages -- used to spot AI traffic. */
export const AI_API_PATTERNS = [
  /api\.openai\.com/i,
  /api\.anthropic\.com/i,
  /generativelanguage\.googleapis\.com/i,
  /api\.mistral\.ai/i,
  /api\.cohere\.ai/i,
  /api\.perplexity\.ai/i,
  /api\.together\.xyz/i,
  /api\.groq\.com/i,
  /chatgpt\.com\/backend-api/i,
  /claude\.ai\/api/i,
];

function hostMatches(hostname, host) {
  return hostname === host || hostname.endsWith(`.${host}`);
}

/**
 * Which AI service a hostname belongs to, or null.
 *
 * Suffix-anchored on purpose. A substring test would match
 * `claude.ai.evil.example` -- a phishing host impersonating the very service
 * we are trying to protect, handed the trusted treatment for free.
 */
export function detectService(hostname) {
  const host = (hostname || "").toLowerCase().replace(/^www\./, "");
  for (const [id, spec] of Object.entries(SERVICE_SELECTORS)) {
    if (id === "generic") continue;
    if (spec.hosts.some((h) => hostMatches(host, h))) return { id, ...spec };
  }
  return null;
}

export function isAiApiRequest(url) {
  return AI_API_PATTERNS.some((p) => p.test(url || ""));
}

/**
 * Services whose selectors we could not find on the page.
 *
 * Returned so the UI can say "we are not watching this page" instead of
 * showing a protected badge over a page where the input box moved and the
 * content script is attached to nothing. A selector that silently stopped
 * matching is this codebase's recurring defect wearing a stylesheet.
 */
export function sitesWeCannotSee(doc, service) {
  if (!service) return null;
  const input = doc.querySelector(service.inputSelector);
  return input ? null : service.name;
}
