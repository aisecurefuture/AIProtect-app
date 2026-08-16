# Fork provenance

This repository was forked from **CyberArmor.ai** (`aisecurefuture/CyberArmorAi`)
on **2026-08-16**, at commit **`29b6bf21f037748b86e981727b72c150c8a18cb9`**
(branch `feat/aiprotect-b2c`).

**There is no sync process, deliberately.** The two products diverged on day
one — no tenants, different auth, a narrower detector set — so an automated
merge would fight that divergence every time. A fix worth having in both is
applied twice, by hand, on purpose. This file exists so that when it happens,
whoever does it knows what the starting point was.

## What was copied

| Path here | Came from | Notes |
|---|---|---|
| `services/detection/` | `services/detection/` | Includes the consumer profile, result cache, and rate limiting added just before the fork |
| `services/url-trust-gate/` | `services/url-trust-gate/` | Unmodified so far |
| `libs/cyberarmor-core/` | `libs/cyberarmor-core/` | Unmodified. Name kept |
| `libs/policy-engine/` | `services/policy/{policy_engine,conditions_guard,policy_fields,opa_client}.py` | Just the 4 modules the engine needs as a library — **not** the 2,733-line FastAPI service |
| `shared/policy-fields.json` | `shared/policy-fields.json` | Read off disk at import by `policy_fields.py` |
| `scripts/deployment/seed_hf_models.sh` | same | A fresh deploy cannot populate the model cache without it |
| `spikes/`, `docs/STRATEGY-AND-PROMPTS.md` | `aiprotect/` | The B2C planning work |

## What was deliberately NOT copied

- **`services/policy/main.py`** (2,733 lines) — every read path is
  `_load_active_policies_for_tenant`. Consumer presets are hardcoded
  `List[dict]` fed to the engine; there is no policy CRUD service here.
- **`services/dashboard-auth/`** — operator-coupled (email allowlist, no
  registration path, a 16-target admin reverse proxy). Consumer auth is
  written fresh; only `cyberarmor_core.crypto` carries over.
- **`customer-portal/`, `admin-dashboard/`, `msp-console/`,
  `services/control-plane/`** — the B2B product.
- **`mobile/`** — a read-only B2B SOC dashboard that cannot build (no Xcode
  project, no `AndroidManifest.xml`, no entry point) and calls `/api/v1` routes
  that were never implemented. `apps/mobile/` is a new app, not a fork of it.
- The other ~30 services in the B2B compose stack.

## Changes made during the fork

1. **`libs/policy-engine/`** — the engine moved out of `services/policy/`. It
   still uses flat imports (`import opa_client`), so that directory must be on
   `sys.path`; it is not a package. `OPA_ENABLED=false` is required or every
   evaluation pays a urllib timeout against an OPA sidecar this product does
   not run.
2. **`infra/docker-compose.yml`** — one `detection` service (the `-consumer`
   suffix was redundant once the repo is consumer-only), its own `hf_models`
   volume, profile `consumer`, cache on, rate limit 60 rpm.
3. **`test_every_model_is_declared_and_seeded.py`** — made profile-aware. It
   compared compose against *this process's* `MODEL_IDS`, which is a different
   profile than the deployment's, and called the difference a drift. It now
   reads `CYBERARMOR_DETECTION_PROFILE` from compose and checks against that
   set; accessor coverage checks `ALL_MODEL_IDS`, so narrowing a profile does
   not make an accessor look like dead code.
4. **`detection_profile.models_for_profile()`** — added for the above.

## Port-back list

Things removed or deferred here that should return when the matching component
is built. Nothing on this list is a decision to go without.

- [ ] **`test_a_chain_corroborates_it_does_not_convict.py`** — deleted during
  the fork. It is a cross-surface test importing
  `agents/endpoint-agent/local_proxy/transparent_proxy.py`, which has no
  equivalent here yet. **Port it back when `apps/agent/` exists.** The property
  it pins — a promptware chain corroborates, it does not convict — is not
  B2B-specific and matters just as much for a consumer.
- [ ] **Strip PHI and zero-shot code entirely.** The consumer profile disables
  them, but `obi/deid_roberta_i2b2` (HIPAA Safe Harbor de-identification) has
  no consumer use case at all and the code is still woven through
  `_scan_sensitive_data` and `_redact_text`. Removing it needs a machine that
  can actually run the models; it was not attempted blind.
- [ ] **Batch `/scan/redact`'s NER windows** — up to 24 windows × 2 models on
  one text, currently one forward pass per window. Real win, needs
  `torch`/`transformers` installed to test, and it is the fail-closed path.
- [x] ~~**Strip `tenant_lists.py` from url-trust-gate** and default
  `tenant_id`.~~ Done 2026-08-16. Also removed `test_tenant_lists.py`.
- [ ] **Per-ACCOUNT allow/block lists.** Removing `tenant_lists.py` removed the
  only allow/block path. It could never have fired here (no policy service to
  query), so nothing was lost operationally — but "always allow this site" and
  "never open this site" are good consumer features and they need to come back
  scoped to the **account**, evaluated across its enrolled devices. Blocked on
  the consumer API existing.
- [x] ~~**`services/audit` was missed in the initial fork**~~ — added the same
  day, along with three other things the first pass dropped. All four were the
  same class of mistake: **copying a component without the things it is only
  transitively coupled to.** Each one was found by a test refusing to collect,
  not by review.
  - `services/audit/` — the writer library was copied, the service it writes
    to was not. The Activity feed depends on it.
  - `conftest.py` — repo-root test bootstrap. Without it every service's
    `main`/`models` collide in a combined run and one suite silently asserts
    against another service's module. Adapted: source roots are now
    `libs/cyberarmor-core` and `libs/policy-engine`, no `sdks/python`.
  - `pytest.ini` — `--import-mode=importlib`, which is what makes duplicate
    test basenames across suites legal.
  - `scripts/security/rotate_audit_signing_key.py` — the audit key rotation
    tests execute it as a subprocess.
- [ ] **Make `libs/cyberarmor-core` an installable package** — it has no
  `pyproject.toml`, no `setup.py`, and no `__init__.py`. It works only because
  every Dockerfile does `COPY` + `PYTHONPATH`. Worth fixing here regardless of
  the B2B repo.

## Known-inherited issues

Carried over from the fork point, not introduced here:

- `services/detection` `/scan/redact` holds user plaintext in memory during
  redaction (not cached — see `scan_cache.py` — but worth an audit for B2C).
- The `tenant_id` field still exists cosmetically in detection request models.
  It is echoed and never authorised against. Harmless, but it should go.
