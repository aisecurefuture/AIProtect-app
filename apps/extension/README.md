# aiprotect/extension — consumer browser extension

Manifest V3. Chrome/Edge today; Firefox and Safari wrappers to follow (the
Safari build is what mobile v1 depends on).

```bash
node --test tests/*.test.mjs     # or: make test-extension
# Load unpacked: chrome://extensions → Developer mode → Load unpacked → this dir
```

## What it does

- **Safe Links** — checks a URL against the trust gate *before* the page loads.
- **Privacy Guard** — on AI assistant sites only, warns before you send text
  that contains personal information.

## What it can see, plainly

This is the section to keep honest, because it is the thing a reviewer and a
customer will both ask about.

- It requests **no host permissions for the web at large**. Safe Links works
  from the navigation URL alone; the extension never reads the contents of an
  arbitrary page.
- The content script runs on **seven AI assistant domains only** (listed in the
  manifest). On every other site it cannot read anything.
- On those sites it reads the prompt box **at the moment you press send**, and
  sends that text to our scanner. It is not stored, not logged, and not written
  to extension storage.
- Storage holds a device credential and your settings. Nothing else.

For contrast, the B2B extension this was forked from requests eleven
permissions including `clipboardRead`, `webRequest` and `declarativeNetRequest`,
plus `http://*/*`. None of those are needed to warn somebody.

## The two failure directions are opposite, on purpose

Pinned by `tests/behaviour.test.mjs`, and the single most important property
here:

| | API unreachable |
|---|---|
| **Safe Links** | **fails OPEN** — navigation is allowed, with a note that we couldn't check |
| **Privacy Guard** | **fails toward WARNING** — asks before sending |

An extension that breaks the web whenever its server hiccups is uninstalled
within a day, and an uninstalled extension protects nobody. But the cost of an
unnecessary "are you sure?" is a click, while the cost of silence is a password
pasted into a chatbot.

Neither feature ever *forbids*. The block page has an "Open it anyway" button,
and a prompt warning is always dismissible — we are sometimes wrong, and a wall
with no door gets the extension removed rather than the page avoided.

## One device, many surfaces

**This extension is a surface, not a device.** A laptop running it and the
desktop app is one device with two installs — one subscription slot, one
rate-limit bucket, two separately revocable credentials.

So setup offers two paths (`enroll.html`):

1. **Join an existing device** with a six-character code from the other
   install. Uses no additional device slot.
2. **Enrol as a new device**, if this is the first place you're installing it.

Every request sends the **device** id as `x-device-id`, never a per-install id.
Sending a per-install id would quietly give a three-surface laptop 3× its rate
limit, with no second ceiling underneath to catch it.

## Reuse and provenance

`src/ai-services.js` lifts `SERVICE_SELECTORS` and the API endpoint patterns
from `extensions/chromium-shared/ai_monitor.js` (fork point `29b6bf21`). Those
selectors are the one genuinely hard-won asset in that extension — somebody sat
with each product's DOM to find them.

**They will rot.** Each is a private implementation detail of somebody else's
web app. `sitesWeCannotSee()` exists so that a moved input box surfaces as "we
are not watching this page" rather than as a content script attached to nothing
behind a green badge.

The rest of that extension — PQC auth, the in-browser policy engine, the
enterprise options page, the upload interceptor — is deliberately not here.

## Not built yet

Firefox and Safari wrappers, icons (placeholders), a real popup activity list,
and the onboarding link from the web portal.
