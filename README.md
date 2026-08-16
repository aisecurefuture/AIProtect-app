# AIProtect.app

Consumer (B2C) AI security. Protection for a person's own devices — the same
detection engine that CyberArmor.ai sells to businesses, rebuilt around one
individual and their family instead of a tenant.

| Property | Surface | Directory |
|---|---|---|
| `aiprotect.app` | Marketing site | `sites/marketing/` |
| `app.aiprotect.app` | Responsive consumer portal | `apps/web/` |
| `api.aiprotect.app` | Consumer API | `apps/api/` |
| `docs.aiprotect.app` | Help & docs | `sites/docs/` |
| `support.aiprotect.app` | Support portal | *(not started)* |
| iOS / Android | Phone + tablet apps | `apps/mobile/` |
| Chrome/Edge/Firefox/Safari | Browser extension | `apps/extension/` |
| macOS/Windows/Linux | Desktop agent | `apps/agent/` |

## Layout

```
apps/          the consumer product surfaces
sites/         public web properties
services/      the engines: detection (ML) + url-trust-gate (safe links)
libs/          cyberarmor-core (audit/evidence/health) + policy-engine
shared/        policy-fields.json — read at import by the policy engine
infra/         docker compose deployment
spikes/        seam proofs, kept runnable as regression tests
scripts/       CI guards, diagnostics, deployment
docs/          strategy and the phased build plan
```

## Status

Engines forked and working. Product surfaces are scaffolding.

- ✅ `services/detection` — 201 tests green. Consumer serving profile, content-hash
  result cache, per-client rate limiting, saturation shed on all 7 scan endpoints.
- ✅ `services/url-trust-gate` — forked; consumer verdict mapping not yet done.
- ✅ `libs/` — both seams proven runnable (`make verify-seams`).
- 🔲 `apps/*`, `sites/*` — README stubs. See `docs/STRATEGY-AND-PROMPTS.md`
  for the phased build plan and the copy-pasteable prompt for each.

## Quick start

```bash
make verify-seams            # prove the two library seams still hold
make test                    # detection test suite
make verify-consumer-scope   # no tenant_id creeping into apps/
python3 scripts/diagnostics/what_the_consumer_profile_saves.py
```

Deploy:
```bash
AIPROTECT_DETECTION_API_SECRET=... docker compose -f infra/docker-compose.yml up -d
```

## Two rules

**1. No `tenant_id`, ever, in `apps/`.** This product has accounts and devices,
not tenants. The audit service defaults `tenant_id` so the hash chain collapses
to a single chain — correct for one user. `agent_id` carries the **enrolled
device id** instead, which is also what lets the Activity feed say "blocked on
your iPhone". Enforced by `make verify-consumer-scope`.

**2. Say what you did not check.** The detection service distinguishes three
states — ran / failed / not configured — and every scan response names the
checks the profile skipped. Do not collapse them. A check that did not run must
never render as a check that ran and found nothing. This is the defect class
this codebase has paid for repeatedly; see `services/detection/tests/` for the
tests that hold the line.

## Relationship to CyberArmor.ai

Independent. Separate repository, separate deployment, separate infrastructure.
Nothing here shares a container, volume, or model cache with the B2B product.

The engines were forked from it — see [`FORK-PROVENANCE.md`](FORK-PROVENANCE.md)
for exactly what was copied, from which commit, and what was deliberately left
behind. There is no sync process by design: the two products have already
diverged (no tenants, different auth, a narrower detector set), and a fix worth
having in both gets applied twice, on purpose.
