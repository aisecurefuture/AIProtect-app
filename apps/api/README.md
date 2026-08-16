# aiprotect/api — consumer API (`api.aiprotect.app`)

**Status:** not built. Built by Prompt 3.

Python + FastAPI + SQLAlchemy + Pydantic, matching the `services/` house style.

## Scope
Owns **identity, accounts, devices, settings, billing** — and nothing else. All
ML and URL analysis is delegated over HTTP to consumer-dedicated deployments of
`services/detection` and `services/url-trust-gate`. Keep this service thin.

## Reuse
- `libs/cyberarmor-core` — audit, evidence, health. Use unmodified.
- `services/policy/policy_engine.py` — imported **as a library** for the
  Standard / Strict / Kids presets. Requires `services/policy` on `sys.path`
  and `OPA_ENABLED=false`. See `../spikes/README.md`.
- `cyberarmor_core.crypto` (incl. `totp.py`) — the only piece of
  `services/dashboard-auth` worth taking.

## Do NOT reuse
`services/dashboard-auth` wholesale. It is **operator-coupled**, not
tenant-coupled: an email allowlist with no registration path plus a 16-target
admin reverse proxy. ~100–150 of its 1,245 lines survive a consumer rewrite.
Write auth fresh.

## Multi-device is the shape of this API

One subscription covers many devices. That drives the account/subscription/
member/device model, enrollment, per-device credentials, and entitlement caps.
**Read [`docs/MULTI-DEVICE.md`](../../docs/MULTI-DEVICE.md) before building
anything here** — it carries the rules, including the ones that are easy to get
backwards:

- At the device cap, **refuse the new device; never silently evict an old one.**
- A wiped or reinstalled device must not consume a second slot.
- A downgrade must not deactivate devices in the background.
- Removing a device revokes its credential, not just its row.

This API is what supplies `x-account-id` and `x-client-id` (the device) on every
call it makes to detection, which is how the two-level rate limit works.

## Hard rules
- **No `tenant_id`.** Anywhere. Ever. Enforced by `make verify-consumer-scope`.
- `agent_id` = enrolled device id, else `aiprotect-web` / `aiprotect-api`.
- Every response must serve both the web SPA and the React Native app.
- Entitlement checks are FastAPI dependencies, stubbed here and filled by
  the billing phase.
