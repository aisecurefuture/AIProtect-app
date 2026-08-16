# aiprotect/agent — consumer desktop app

**Status:** not built. Built by Prompt 6 in the strategy doc's ordering — and
deliberately last. Do not start before web + extension + mobile v1 ship.

## Reuse
`agents/endpoint-agent/` — Python, cross-platform (macOS/Windows/Linux). Take
AI-traffic coverage, the clipboard/DLP helper, and the captive-portal watchdog.

## Rework
Strip enterprise policy-server enrollment; enroll against the consumer account
with a per-device credential and settings from `aiprotect/api`. Present as a
menu-bar / tray app with a simple status UI — not a daemon that logs.

## Why last
Heaviest lift, lowest consumer expectation. Signed installers per OS plus
auto-update is a large ongoing cost. Be conservative and explicit about what is
inspected locally versus sent to the API.
