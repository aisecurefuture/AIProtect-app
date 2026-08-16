# aiprotect/extension — consumer browser extension

**Status:** not built. Built by Prompt 5.

Manifest V3. Chrome/Edge builds plus Firefox and Safari wrappers, following the
existing per-browser pattern in `extensions/`. **The Safari build is reused by
mobile v1**, so it is on the critical path for iOS.

## Reuse
`extensions/chromium-shared/` — `ai_monitor.js` and `background.js` contain the
real protection logic (PII protection, phishing defense, AI-service monitoring,
prompt-injection detection). Keep the logic; replace the enterprise UX and
tenant enrollment with consumer account sign-in.

## Features
Safe Links (intercept risky navigation via the trust-gate fast path) · Privacy
Guard (warn before pasting secrets/PII into AI chat sites) · AI Safety (flag
prompt-injection and scam AI responses).

## Rules
Heavy detection stays server-side; the extension is a thin, privacy-respecting
sensor plus UI. Document exactly what data leaves the browser — this is the
highest-scrutiny surface for a consumer security product.

Highest daily-value consumer surface and the cheapest to ship. Build it in
parallel with `web/`.
