# AIProtect.app — B2C Strategy, Repo Architecture & Build Prompts

> Consumer (B2C) sibling of CyberArmor.ai (B2B). Marketing at **aiprotect.app**,
> API at **api.aiprotect.app**, docs at **docs.aiprotect.app**, support at
> **support.aiprotect.app**. Consumer portal = responsive web app + iOS/Android
> phone & tablet apps.
>
> Branch: `feat/aiprotect-b2c`. Status: planning doc — nothing built yet.
> **Revision 2** — rewritten after a code-level audit of the reuse assumptions.

---

## 0. What the audit changed (read this first)

Revision 1 of this document was written from directory structure and
`package.json` files. A code-level audit of the three load-bearing assumptions
found one of them badly wrong:

| Rev-1 claim | Reality | Impact |
|---|---|---|
| "`mobile/` is already a React Native app — fork it for B2C" | It's a **read-only B2B SOC dashboard**, 2,444 lines, and **not buildable** — no Xcode project, no `AndroidManifest.xml`, no `index.js`. It calls `/api/v1/*` endpoints that **don't exist server-side**. Zero on-device protection. | **Mobile plan rewritten.** Protection on mobile is net-new native work gated on an Apple entitlement. |
| "Proxy the consumer API to the shared `services/detection`" | Detection is **5.24 GiB RSS, CPU-only, ~3.6 s/scan, no caching, no batching, no rate limiting**, with 5 of 7 endpoints unbounded. ≈14 core-seconds per scan. | **Cannot serve a free tier, and must not share a deployment with the paying B2B pilot.** A cost-reduced consumer tier is now a prerequisite phase. |
| "Model consumer auth on `services/dashboard-auth`, strip tenants" | It's **operator-coupled, not tenant-coupled** — an email allowlist with no registration path, plus a 16-target admin reverse proxy. ~100–150 of 1,245 lines survive. | **Write consumer auth fresh**; reuse only `cyberarmor_core.crypto`. |

What *did* hold up: **the shared-core seam is real**, and the repo organization
recommendation is unchanged and strengthened.

Also confirmed: `AI_Protect_V3-*.sln` at the repo root is **not** prior art for
this product — it's a Visual Studio solution for the `rasp/dotnet` and
`extensions/visual-studio` C# projects, misleadingly named. No name collision,
no existing AIProtect code in the repo.

Per decision on 2026-08-16, **`cyberarmor-core` keeps its name** — no rename.
It's an internal package name, never user-visible; not worth the churn.

---

## 1. The decision: how to organize the two products

**Recommendation (unchanged): keep AIProtect in this monorepo now, behind the
shared-core seam, and defer the physical repo split until AIProtect has traction
or its own team.** One repo, hard directory boundaries, separate deploy
pipelines, and a shared core both products import.

### The seam, now verified line-by-line

| Piece | Verdict | Reusable |
|---|---|---|
| `libs/cyberarmor-core/` — `audit_writer`, `evidence`, `health_record`, `event_taxonomy`, `crypto` | **REUSE AS-IS** | ~2,200 lines, **zero changes** |
| `services/policy/policy_engine.py` + `conditions_guard.py`, imported **as a library** | **REUSE AS-IS** | ~1,700 lines, zero changes — but see caveat |
| `services/url-trust-gate/` detection core | **REUSE WITH ADAPTER** | ~1,900 lines, ~1 day of adapter |
| `services/detection/` | **REUSE, SEPARATE DEPLOYMENT** | Same code, cheap config (§3) |
| `extensions/chromium-shared/` | **REUSE WITH RESKIN** | Real protection logic |
| `services/policy/main.py`, `services/dashboard-auth/` | **REWRITE** | ~0 |
| `mobile/` | **DO NOT FORK** | See §4 |

The encouraging signal: tenant-coupling was already deliberately pushed *out* of
the pure layers. `EvaluationContext` has no tenant field. `AuditWriter.enqueue`
takes an opaque dict. `HealthRecord` and `EvidenceItem` have no tenant. Someone
drew this line on purpose — it just stops at the FastAPI boundary in each service.

Two specific gifts for B2C:
- **`url-trust-gate` already degrades to a standalone, score-based verdict engine
  when the policy service is unreachable** (`main.py:1201-1204` →
  `_fallback_decision`). That is the B2C mode, already written, by accident.
- **The reputation cache is not tenant-keyed** — `reputation.py:35` keys on
  canonical-URL fingerprint alone. Already a consumer-grade shared cache.

**Both seams are now proven** (Prompt 0, 2026-08-16). Runnable regression tests
live in `aiprotect/spikes/`; `make verify-aiprotect-seams` runs both.

- `spike_policy_engine.py` — **12/12 PASS**. The engine evaluates a three-rule
  consumer preset against a tenant-free context with no FastAPI, DB, or network.
  Two required accommodations: **`services/policy/` must be on `sys.path`**
  (flat imports — `import opa_client`, so `from services.policy import ...`
  does not work), and **`OPA_ENABLED=false` must be set explicitly** or every
  evaluation pays a urllib timeout against an OPA sidecar B2C does not run.
- `spike_core_tenant_free.py` — **21/21 PASS**. `cyberarmor_core` is usable
  unmodified. `AuditWriter` enqueues tenant-free events and spools overflow to
  disk with no audit service running.

**Two gaps the spikes exposed:**

1. **`libs/cyberarmor-core` is not an installable package** — no
   `pyproject.toml`, no `setup.py`, and **no `__init__.py`**. It is an implicit
   namespace package that works only via `COPY` + `PYTHONPATH` replicated across
   ~10 service Dockerfiles. So the "versioned shared contract" this document
   describes **does not exist as packaging yet**. Closing that is precisely what
   makes the eventual repo split a weekend rather than a rewrite — do it before
   the split, not during.
2. **The policy engine does not validate field names.** It resolves
   `content.foo` from whatever dict the caller passed and never checks
   `shared/policy-fields.json` (that registry drives the builder UI, not
   enforcement). Consequences both ways: the consumer product can define its own
   vocabulary (`content.kid_unsafe`) for free — *and* **a typo'd field on a
   `block` rule silently never fires, raises nothing, and reports nothing in
   `problems`.** That is the dishonest-health defect class in a new costume.
   **Every consumer preset rule needs a known-positive fixture test.**

### Why not a separate repo today
The verified reuse above is code you'd otherwise maintain twice. Every detection
improvement and trust-gate fix would be done in two places. That's the
duplication to avoid.

### Why not fully merged either
"Don't let them hurt each other" is a **deploy-time and runtime-blast-radius**
concern, not a source-control one — and the detection findings make it concrete:
consumer free-tier traffic pointed at the B2B detection instances is a live
availability *and* cost risk to the paying pilot. You get isolation from
directory boundaries + independent CI/CD + **separate service deployments** —
not from a second repo.

### Proposed layout
```
/libs/cyberarmor-core/     # shared kernel — versioned contract, name unchanged
/services/                 # shared backend services (source shared, deployed separately)
/aiprotect/                # ← NEW: everything B2C-specific
  api/                     # consumer API (api.aiprotect.app) — auth, billing, devices
  web/                     # responsive consumer portal (Next.js, reuse marketing/ stack)
  mobile/                  # NEW RN app — not a fork of /mobile
    ios-native/            # Swift Network Extension (v2)
    android-native/        # Kotlin VpnService (v2)
  extension/               # consumer browser build (wraps extensions/chromium-shared)
  agent/                   # consumer desktop build (wraps agents/endpoint-agent)
  marketing/               # aiprotect.app public site (fork of /marketing Next.js)
  docs/                    # docs.aiprotect.app (fork of /docs-site MkDocs)
  infra/                   # aiprotect compose + deploy, separate from B2B infra
/customer-portal/          # unchanged B2B tenant portal (app.CyberArmor.ai)
```

### Guardrails
1. **No imports across product trees.** `aiprotect/**` may import
   `libs/cyberarmor-core` and the policy engine as a library — never
   portal/control-plane code. Enforce in CI.
2. **Single-tenant by construction.** The B2C API never carries `tenant_id`.
3. **Separate deployments, always.** Consumer detection and trust-gate run on
   their own instances. A B2C traffic spike must not touch the B2B pilot.
4. **Shared-core changes reviewed as contract changes** (semver + changelog).

### When to actually split the repo
When AIProtect gets dedicated engineers, when release cadence diverges hard, or
when you need a separate compliance/App-Store entity. **Signal to watch:** when
"I had to touch the other product to ship this one" stops happening.

---

## 2. Hard constraints that shape everything

These are external or economic, not code, and they drive sequencing.

**A. The Apple Network Extension entitlement is the long pole.** Real on-device
AI-traffic protection on iOS requires `NEPacketTunnelProvider` (consumer path)
under `com.apple.developer.networking.networkextension` — an entitlement you
must *apply* to Apple for, with review. The repo's own design brief
(`docs/specs/mobile-endpoint-security.md`) already calls this "the longest
external dependency." **Apply on day 0, in parallel with all build work.**
Everything mobile-native is gated behind it.

**B. Free-tier unit economics.** At ~14 core-seconds and ~3.6 s per scan with
zero caching, a free consumer tier on the current detection config is
financially unviable and trivially DoS-able (no rate limiting; 5 of 7 scan
endpoints have unbounded concurrency). The cost-reduced tier in §3 is a
**prerequisite**, not an optimization.

**C. React Native cannot host the protection layer.** The packet tunnel (Swift)
and `VpnService` (Kotlin) must be native. RN is the dashboard shell only.

**D. Consumer privacy is a product constraint, not a legal afterthought.** B2B
sells "inspect your employees' AI traffic." Consumers are buying protection *for
themselves* — a VPN-based inspection app faces hard App Store review and a
skeptical user. The privacy story must be designed in, and must match what the
code actually does.

---

## 3. Product shape for a consumer

| B2B concept | B2C consumer framing |
|---|---|
| Tenant / org | One person or a **Family plan** (up to N devices/members) |
| Agent enrollment | "Add this device" — QR / deep link, 60-second setup |
| Policy engine | 3 presets: **Standard / Strict / Kids**, plus a few toggles |
| url-trust-gate | **Safe Links** — "Is this link safe?" in browser + share sheet |
| Detection DLP | **Privacy Guard** — warns before you paste secrets into AI chatbots |
| AI-traffic inspection | **AI Safety** — flags prompt-injection & scam AI responses |
| Audit log | **Activity** — a personal, plain-language protection timeline |
| SIEM/SSO | (hidden — not a consumer surface) |
| Billing | Apple/Google IAP + Stripe (web); Free + Pro + Family |

**Consumer detection tier** (from the audit — the config that makes free viable):
drop `bart-large-mnli` (−2.72 s, −1.6 GB), drop `obi/deid_roberta_i2b2`
(−1.4 GB), `OLLAMA_ENABLED=false`, `CYBERARMOR_PROMPTWARE_SESSION_ENABLED=false`
(it has a documented cross-user blocking incident and consumer traffic collapses
into shared session buckets).

**Corrected figures (2026-08-16).** An earlier draft of this document claimed
"~1.2 GiB and ~0.5 s/scan". That was wrong: it quietly dropped
`_scan_sensitive_data`, which *is* the Privacy Guard feature and cannot be
dropped. Derived from the measured per-detector medians in
`docs/specs/pilot-capacity-model.md`, the honest projection is **~2.2 GiB and
~0.89 s/scan** — a **2.3× memory and 4.1× latency** improvement, not 4×/7×.
Run `scripts/diagnostics/what_the_consumer_profile_saves.py` to reproduce the
arithmetic; it labels every figure `[MEASURED]` or `[PROJECTED]`.

Then add content-hash result caching — for consumer traffic this is the larger
half of the win, since scans are pure functions of their text and consumer
workloads repeat heavily across users.

---

## 4. Mobile: the honest plan

`mobile/` is a scaffold that was never wired to a real API and cannot build.
Salvage the *patterns* (API client shape, offline queue, WebSocket reconnect,
biometric gate, notification setup) — but **do not fork it**, and do not carry
over its security bugs (API key in AsyncStorage plaintext, key in the WebSocket
query string, and a biometric gate bypassable via its own `onSkip` prop).

Ship mobile in two stages:

- **v1 — shippable without any Apple entitlement.** Consumer account +
  dashboard, Safe Links via **iOS Share Extension / Android share intent**,
  a **Safari Web Extension** on iOS and the Chromium extension on Android,
  Privacy Guard as an in-app paste-check, push notifications. This is a real,
  useful product and it de-risks the whole thing.
- **v2 — full on-device protection, gated on the entitlement.** Swift
  `NEPacketTunnelProvider` and Kotlin `VpnService`, both net-new native.

---

## 5. Build prompt series

Feed these to Claude Code **in order**, reviewing between phases.

> **Day 0, in parallel and not a code task:** start the Apple Network Extension
> entitlement application, and register the `aiprotect.app` App Store /
> Play Console identities. These have lead times that gate Prompt 8.

### ~~Prompt 0~~ — DONE 2026-08-16 ✅

Delivered: `aiprotect/` tree with per-surface READMEs; two seam spikes in
`aiprotect/spikes/` (12/12 and 21/21 PASS); the boundary guard at
`scripts/ci/check_aiprotect_boundaries.py` with a 7/7 self-test; three Makefile
targets (`verify-aiprotect-boundaries`, `-selftest`, `verify-aiprotect-seams`).
Conventions settled: `agent_id` = enrolled device id (else `aiprotect-web` /
`aiprotect-api`), `tenant_id` never set. Findings folded into §1 above.

<details><summary>Original Prompt 0 text</summary>
```
On branch feat/aiprotect-b2c, set up the AIProtect B2C workspace without
disturbing the B2B product.

1. Create the /aiprotect tree: api/ web/ mobile/ extension/ agent/ marketing/
   docs/ infra/ , each with a stub README stating its purpose and its B2B
   reuse source.
2. PROVE THE SEAM (this is the real goal): write a standalone spike that imports
   services/policy/policy_engine.py and conditions_guard.py AS A LIBRARY —
   no FastAPI, no DB, no tenant — and evaluates a hardcoded "Standard" consumer
   preset (a List[dict] of policy rows) against a sample EvaluationContext.
   Nothing in this repo currently imports the engine as a library, so this path
   is untested. Report exactly what breaks and what the real import surface is.
3. Do the same for libs/cyberarmor-core: a spike that writes an audit event and
   an evidence record with NO tenant_id. Note that services/audit requires
   agent_id with no default — decide and document the consumer convention for
   that field (url-trust-gate papers over it with a literal; pick deliberately).
4. Add a CI guard that fails if anything under aiprotect/** imports from
   customer-portal/, admin-dashboard/, msp-console/, or services/control-plane.
   Wire it into the existing Makefile/CI.
5. Write /aiprotect/README.md: architecture, the no-cross-import rule, and the
   separate-deployment rule for shared services.

Do NOT rename cyberarmor-core. Do NOT fork any service yet. Report the two spike
results before making further structural changes.
```
</details>

### ~~Prompt 1~~ — DONE 2026-08-16 ✅

Delivered, all defaulting to existing B2B behaviour so the pilot is untouched:
`services/detection/detection_profile.py` (profile as a **third state** —
*not configured* ≠ *failed*), `scan_cache.py` (content-hash cache that refuses
incomplete scans), `rate_limit.py` (per-client token bucket); the saturation
shed extended from 2 of 7 to **all 7** scan endpoints; `/ready` now separates
`degraded_models` (a fault) from `models_disabled_by_profile` (a choice);
consumer deployment at `aiprotect/infra/docker-compose.consumer.yml`.
31 new tests, 218 detection tests green. Figures corrected above.

**NOT done, deliberately: batching.** Two reasons, and they point at a
different change than the prompt assumed. (1) Each request carries one text, so
batching would have to happen *across* requests — micro-batching behind a queue,
which *adds* latency to every request to save aggregate CPU. That is the wrong
trade against a 5.0 s fail-closed inspection budget. (2) The one place
in-request batching genuinely applies is `/scan/redact`, which runs up to
24 NER windows × 2 models on a single text — those windows could become one
batched pipeline call with no added latency. That is the real opportunity, and
it was **not** attempted here because `transformers`/`torch` are not installed
in this environment, so it could not be tested — and `/scan/redact` is the
fail-closed path where a bug means either leaked PII or blocked traffic. Do it
on a machine that can run the models, behind the existing redaction tests.

<details><summary>Original Prompt 1 text</summary>
```
Make services/detection economically viable for a B2C consumer tier, WITHOUT
changing the B2B deployment's behavior.

Audit findings to act on: 5.24 GiB RSS, CPU-only, ~3.58s per /scan, no result
caching, no batching, no rate limiting, and 5 of 7 scan endpoints not covered by
the @_sheds_when_saturated semaphore.

1. Add a content-hash result cache (scans are pure functions of the input text).
   This is the highest-leverage change. Make TTL and backend configurable;
   ensure it cannot leak results across accounts.
2. Add batching at the pipeline call sites — every call currently passes a
   single string.
3. Add rate limiting, and extend the saturation shed to ALL scan endpoints.
4. Add a "consumer profile" env configuration that drops bart-large-mnli and
   obi/deid_roberta_i2b2, sets OLLAMA_ENABLED=false and
   CYBERARMOR_PROMPTWARE_SESSION_ENABLED=false. Target ~1.2 GiB and ~0.5s/scan.
5. Verify every dropped model degrades to its documented heuristic fallback and
   that /ready honestly reports "degraded" — do NOT let it report healthy for a
   check that didn't run.
6. Produce a measured before/after benchmark, and a separate consumer compose
   deployment in aiprotect/infra so consumer traffic NEVER shares instances with
   the B2B pilot.

Also flag (do not fix here): infra/helm/cyberarmor/values.yaml limits detection
memory to 2Gi against a measured 5.24 GiB — that's a guaranteed OOM crash-loop.
```
</details>

### Prompt 2 — url-trust-gate consumer adapter
```
Make services/url-trust-gate serve consumer callers with no tenant, without
breaking its B2B callers.

The audit found tenant_id is required at the API boundary but load-bearing in
exactly one place (_tenant_listed_decision); crawler.py accepts it and never
reads it; and the gate ALREADY falls back to a standalone score-based verdict
(_fallback_decision) when the policy service is unavailable. Consumer mode is
mostly latent in the code already.

1. Make tenant_id optional/defaulted; drop it from the consumer response shape.
2. Add a consumer verdict mapping: safe / caution / blocked + ONE plain-language
   reason a non-technical person understands. Map REQUIRE_APPROVAL -> block
   (the gate already does this).
3. Expose the existing "fast" (~10ms cached) depth for browser and share-sheet
   click interception, and a "deep" depth for on-demand checks.
4. Confirm the reputation cache (keyed on URL fingerprint, not tenant) is safe to
   share across consumer users, and document why.
5. Contract tests so B2C changes can't break B2B and vice versa.
```

### Prompt 3 — Consumer API (api.aiprotect.app)
```
Build the AIProtect consumer API in /aiprotect/api — Python + FastAPI +
SQLAlchemy + Pydantic, reusing libs/cyberarmor-core for audit/evidence and
importing policy_engine as a library (per the Prompt 0 spike).

WRITE AUTH FRESH. Do not fork services/dashboard-auth — the audit found it is
operator-coupled (email allowlist, no registration path, 16-target admin proxy);
only ~100-150 of its 1,245 lines survive. Reuse cyberarmor_core.crypto (incl.
totp.py) and nothing else.

Single-user B2C — NO tenant_id anywhere:
- Auth: email + passwordless code, Sign in with Apple, Sign in with Google,
  optional TOTP. Sessions + refresh tokens suitable for mobile. Secure token
  storage guidance for clients (Keychain/Keystore — NOT plaintext).
- Accounts: individual + Family (owner invites N members, per-member device caps,
  parental Kids controls). Account deletion and data export (GDPR/CCPA).
- Devices: enroll/list/rename/remove; per-device credential; QR/deep-link flow.
- Protection settings: presets Standard/Strict/Kids as hardcoded policy row sets
  fed to the imported policy engine, + a few toggles, pushed to devices.
- Thin proxies to the CONSUMER deployments (Prompts 1-2): POST /safe-links and
  POST /privacy-check. The API owns identity/billing/devices; ML stays in the
  services.
- Activity feed from cyberarmor-core audit/evidence, in plain language.
- Billing entitlement stubs enforced as FastAPI dependencies (filled in Prompt 7).

Deliver OpenAPI docs, a docker service, and integration tests. Every response
must serve BOTH a web SPA and a React Native app.
```

### Prompt 4 — Responsive consumer web portal
```
Build the AIProtect consumer web portal in /aiprotect/web as a responsive
Next.js app (reuse the stack and component conventions from /marketing; do NOT
reuse the vanilla-JS customer-portal SPA).

Screens (mobile-first: phone -> tablet -> desktop):
- Onboarding: sign up, pick a plan, add first device via QR — target under 60s.
- Home: one "You're protected" status, recent Activity, quick actions. No jargon.
- Safe Links: check a URL, see the consumer verdict.
- Privacy Guard: paste text, see what sensitive data it contains before sharing
  it with an AI.
- Devices: list/add/remove, per-device status.
- Family: invite members, Kids preset, privacy-aware family activity.
- Settings: presets, subscription, privacy controls, account deletion.

Auth against api.aiprotect.app. Accessibility AA, dark mode, and an honest,
prominent "what we can and cannot see" explainer. Component tests.
```

### Prompt 5 — Consumer browser extension
```
Build a consumer AIProtect browser extension in /aiprotect/extension by wrapping
the shared core in extensions/chromium-shared (ai_monitor.js, background.js) —
reuse the detection/monitoring logic, replace the enterprise UX and enrollment.

- Sign in with the AIProtect account; no tenant concept.
- Features: Safe Links (intercept risky navigations via the fast path), Privacy
  Guard (warn before pasting secrets/PII into AI chat sites), AI Safety (flag
  prompt-injection / scam AI responses).
- Manifest V3; Chrome/Edge builds, plus Firefox and Safari wrappers following the
  existing per-browser pattern. The Safari build is reused by mobile v1.
- Friendly popup: protection status + recent blocks.

Heavy detection stays server-side. Document exactly what data leaves the browser.
```

### Prompt 6 — Mobile v1 (ships without the Apple entitlement)
```
Build the AIProtect mobile app in /aiprotect/mobile as a NEW React Native app.

Do NOT fork /mobile — the audit found it is a read-only B2B SOC dashboard that
cannot build (no Xcode project, no AndroidManifest, no index.js) and calls
/api/v1/* endpoints that don't exist. Salvage PATTERNS only: the API client
shape, offline queue, WebSocket reconnect, biometric gate, notification setup.

Explicitly do NOT carry over its security bugs: API key in AsyncStorage
plaintext, credential in the WebSocket query string, and a biometric gate that
its own onSkip prop bypasses. Use Keychain/Keystore and real session tokens.

v1 scope — no Network Extension required:
- Onboarding, Home status, Devices, Family, Settings, Activity (parity with web).
- Safe Links via iOS Share Extension and Android share intent.
- Safari Web Extension on iOS + the Chromium extension on Android (from Prompt 5).
- Privacy Guard as an in-app paste-check.
- Sign in with Apple (required if you offer Google), Google, biometric unlock.
- Tablet layouts for iPad and Android tablets: master/detail, not stretched phone.
- Push notifications actually registered server-side.

Deliver complete, buildable iOS and Android native scaffolds (Xcode project,
AndroidManifest, gradle wrapper, entry point, babel/metro config) — the missing
pieces that make /mobile unbuildable. Plus a store-submission checklist:
privacy nutrition label and data-safety form filled from REAL data flows.
```

### Prompt 7 — Mobile v2: native on-device protection (gated on Apple entitlement)
```
Add real on-device AI-traffic protection to /aiprotect/mobile. Prerequisite: the
Apple Network Extension entitlement must be APPROVED before starting iOS work.
Read docs/specs/mobile-endpoint-security.md first — it already analyzes this.

- iOS: Swift NEPacketTunnelProvider (consumer path), app group, entitlements,
  extension target. RN cannot host this — it is native.
- Android: Kotlin VpnService + foreground service. Note the design brief rules
  out the Accessibility-service route on Play-policy grounds.
- On-device verdict cache + evidence write path, so the tunnel is not making a
  network round-trip per flow.
- Battery, and fail-open vs fail-closed behavior when the API is unreachable —
  a consumer security app that silently kills connectivity will be uninstalled.
- Be conservative and explicit about what is inspected on-device vs sent to the
  API, and make the app's own UI say so.
```

### Prompt 8 — Billing, subscriptions & entitlements
```
Implement AIProtect billing end to end across the consumer API, web, and mobile.

- Tiers: Free (basic Safe Links + limited Privacy Guard), Pro (full, 1 user),
  Family (N members/devices + Kids controls).
- Web: Stripe subscriptions + customer portal.
- iOS: StoreKit IAP. Android: Google Play Billing.
- ONE entitlement service in the consumer API reconciling all three sources into
  a single source of truth, enforced via the FastAPI dependencies stubbed in
  Prompt 3. Handle grace periods, refunds, family sharing, and cross-platform
  ("bought on iOS, now on web").
- Free-tier abuse controls tied to the Prompt 1 rate limiting — the detection
  tier is CPU-bound and a free tier is the obvious attack surface.
- Never let a lapsed subscription silently leave a user unprotected: warn clearly.

Deliver webhooks, reconciliation jobs, and tests for chargebacks, expired
receipts, and mid-cycle plan changes.
```

### Prompt 9 — Marketing, docs, support sites
```
Stand up the three public AIProtect web properties, reusing existing stacks.

- /aiprotect/marketing (aiprotect.app): fork /marketing (Next.js). Consumer
  positioning: "AI security for your everyday devices." Value, pricing, privacy
  promise, sign-up + app store badges. Be honest about what it does and does not
  do — no capabilities the code doesn't have.
- /aiprotect/docs (docs.aiprotect.app): fork /docs-site (MkDocs). Setup per
  device, what each feature protects against, privacy FAQ.
- support.aiprotect.app: recommend the lightest option that fits (static help
  center + hosted helpdesk vs a small app), then implement the chosen one.

Match branding across all three. Wire analytics + consent.
```

### Prompt 10 — Trust, privacy & launch hardening
```
Do a consumer-launch readiness pass on AIProtect.

- Privacy: a plain-language privacy policy and in-app "what we see" explainer
  that MATCH the actual data flows — audit the code to confirm, and fix any claim
  the implementation can't back. Apple Privacy Nutrition Label + Google Data
  Safety form from real flows.
- Security review of the consumer API and auth (/security-review), focused on
  account takeover, family-permission escalation, and device-credential theft.
- The dishonest-health check: verify NO screen reports "protected" when the
  underlying check never ran. This is a known recurring defect class in this
  codebase — hunt it specifically before launch.
- Capability honesty: this platform inspects AI traffic; it does NOT parse
  PDF/DOCX/XLSX. Make sure no consumer-facing copy implies document scanning.
- Abuse/safety: rate limits, Kids controls, and a clear incident path.

Deliver a go/no-go launch checklist.
```

---

## 6. Sequencing

**Day 0 (parallel, non-code):** Apple Network Extension entitlement application;
App Store / Play Console registration for aiprotect.app.

1. **Prompt 0** — prove the seam. If the policy-engine-as-library spike fails
   badly, that changes the architecture, so do it first and cheaply.
2. **Prompts 1–2** — consumer detection tier + trust-gate adapter. These are
   prerequisites: without them there is no viable free tier and no isolation
   from the paying B2B pilot.
3. **Prompt 3** — consumer API.
4. **Prompts 4 + 5 in parallel** — web portal and browser extension. The
   extension is the highest daily-value consumer surface and the cheapest to
   ship; the Safari build feeds mobile v1.
5. **Ship a private beta on web + extension.** This validates the consumer
   product before paying the app-store tax.
6. **Prompt 6** — mobile v1, reusing proven web flows.
7. **Prompt 8** — billing, once there's something worth charging for.
8. **Prompt 9** — public sites, ahead of public beta.
9. **Prompt 7** — mobile v2 native protection, when the entitlement lands.
10. **Prompt 10** — launch hardening.

---

## Appendix — incidental B2B findings

Surfaced during this audit; they affect the product you're actively piloting, so
they're recorded here rather than lost:

1. **`infra/helm/cyberarmor/values.yaml:98-104`** limits detection memory to
   **2Gi against a measured 5.24 GiB** footprint — a guaranteed OOM crash-loop
   on any Kubernetes deploy, each restart reloading ~5 GiB of weights. (Helm is
   currently out of scope per the compose-only decision, but the file is wrong.)
2. **`services/detection` has no rate limiting**, and `/scan/prompt-injection`,
   `/scan/sensitive-data`, `/scan/output-safety`, `/scan/toxicity`, and
   `/scan/redact` are **not** covered by the saturation shed — unbounded
   concurrent transformer inference. `/scan/output-safety` is ~2.72 s of CPU per
   call, so a single client can peg every core.
3. **`mobile/` security bugs**, if that code is ever revived: API key persisted
   in AsyncStorage plaintext (`src/services/auth.ts:5,71`), credential passed in
   the WebSocket query string where it lands in logs (`src/services/websocket.ts:33`),
   and a biometric gate defeated by its own skip handler (`App.tsx:67`).
4. **`mobile/` targets an API contract that was never built** — no `/api/v1`
   routes exist in `services/control-plane`, and the Helm ingress forwards
   `/api/v1/*` without a rewrite annotation to services that serve unprefixed
   paths.
