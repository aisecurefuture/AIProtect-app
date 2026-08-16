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

## Hard rules
- **No `tenant_id`.** Anywhere. Ever.
- `agent_id` = enrolled device id, else `aiprotect-web` / `aiprotect-api`.
- Every response must serve both the web SPA and the React Native app.
- Entitlement checks are FastAPI dependencies, stubbed here and filled by
  Prompt 8.
