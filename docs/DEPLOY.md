# Deploying AIProtect

**Nothing here has ever been run.** Every test in this repo is a unit or
integration test against SQLite and mocks. No container has been started, the
API has never spoken to a real detection service, and the Stripe webhook has
never seen a real Stripe event. Treat the first deploy as a first deploy.

---

## The decision to make before any of this: which box

`aiprotect.app` DNS is at **GoDaddy** (`ns23/ns24.domaincontrol.com`). The
CyberArmor.ai production host is **`178.156.228.46`**.

Pointing AIProtect at that host is possible, and it is what the architecture in
this repository is built to avoid.

**What separation was supposed to buy.** Separate repository, separate
deployment, separate volumes, separate model cache — all so a consumer traffic
spike or a free-tier abuser cannot affect an ~800-seat regulated customer. A
shared box gives back CPU, RAM, disk, the network, and the reverse proxy.

**The numbers.** That host is 16 GiB with **swap disabled**, running ~30
containers, and B2B detection alone holds **5.24 GiB RSS** (measured
2026-08-07). AIProtect adds detection (~2.2 GiB projected), url-trust-gate,
audit, the API and the portal — call it 3–4 GiB. That is plausibly over the
line, and the documented failure mode is the kernel OOM killer choosing by
badness score **with no guarantee it picks detection rather than Postgres**.
There is already shared fate on ingress: a sealed OpenBao takes 80/443 down
with it.

**Recommendation:** a separate host. A small Hetzner instance is a few euros a
month and keeps the promise the whole design rests on.

**Middle path if you want a presence today:** point `aiprotect.app`, `www` and
`docs` at the existing host — static holding pages, negligible load — and give
`api.aiprotect.app` its own box, since that is where detection lives.

---

## DNS

Lower the TTL first so a mistake is minutes rather than hours.

| Type | Name | Value | TTL |
|---|---|---|---|
| A | `@` | `178.156.228.46` | 600 |
| A | `www` | `178.156.228.46` | 600 |
| A | `app` | `178.156.228.46` | 600 |
| A | `api` | `178.156.228.46` | 600 |
| A | `docs` | `178.156.228.46` | 600 |
| A | `support` | `178.156.228.46` | 600 |

**Delete first:** the apex A records `15.197.142.173` and `3.33.152.147` —
GoDaddy parking. **Turn Domain Forwarding off**, or GoDaddy re-adds them.
`www` currently carries a CNAME *and* two A records, which is invalid; make it
one or the other.

### DNS alone will not work — verified 2026-08-16

Three things checked against the live host:

1. **Caddy there issues per-host certificates.** `cyberarmor.ai` and
   `app.cyberarmor.ai` each present their own single-name cert.
2. **An `aiprotect.app` SNI returns no certificate at all.** Point DNS at that
   host without adding the hostnames and a visitor gets a browser security
   warning — on a security product's domain, which is the worst possible first
   impression.
3. **This stack has no public ingress.** Every service in
   `infra/docker-compose.yml` binds `127.0.0.1` only.

DNS is the last step, not the first.

---

## Two ingress shapes. Pick by whether AIProtect owns 80/443.

### A. Dedicated host — AIProtect owns the ports

```bash
docker compose -f infra/docker-compose.yml -f infra/docker-compose.ingress.yml up -d
```

Brings up Caddy with `infra/Caddyfile`, which obtains certificates for all six
hostnames and serves `infra/holding/` for the ones not built yet.

### B. Shared host — something else already owns the ports

**Do not bring up the ingress overlay.** Two Caddy instances cannot both bind
80/443; the second fails to start, and on the CyberArmor host that is an
outage for a paying customer.

Instead:

```bash
docker compose -f infra/docker-compose.yml up -d      # loopback ports only
```

then append `infra/caddy-snippets/aiprotect.caddy` to that host's existing
Caddyfile and reload it. The snippets proxy to `127.0.0.1:3000` and
`127.0.0.1:8100` and expect the holding page at `/opt/aiprotect/holding`.
Nothing about the existing CyberArmor site blocks changes.

---

## Environment

Every one of these is `:?` in compose — the stack refuses to start without
them rather than falling back to a default secret.

```bash
AIPROTECT_DETECTION_API_SECRET=   # openssl rand -hex 32
AIPROTECT_TRUST_GATE_API_SECRET=
AIPROTECT_AUDIT_API_SECRET=
AIPROTECT_AUTH_PEPPER=            # peppers login-code and refresh-token hashes
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=            # unset => the webhook refuses EVERY event
```

`STRIPE_WEBHOOK_SECRET` being unset is deliberately fatal to the webhook. A
misconfiguration must not become an open endpoint anyone can use to cancel
subscriptions.

---

## Order of operations

1. **Seed the models before starting detection.** `TRANSFORMERS_OFFLINE=1`
   against an empty `hf_models` volume gives five failed models while every
   health signal stays green — this has happened twice on the B2B host. Run
   `scripts/deployment/seed_hf_models.sh` first, then check `/ready` reports
   `status: ready` and an empty `degraded_models`.
2. `docker compose ... up -d`
3. Verify from **outside** the box, not from on it. A service can be healthy
   to itself and unreachable to the internet.
4. Point the Stripe webhook at `https://api.aiprotect.app/billing/webhook` and
   send a test event. Until one arrives and returns 2xx, the billing path is
   unproven.

## Verifying

```bash
curl -s https://api.aiprotect.app/health
curl -s http://127.0.0.1:8102/ready | jq '{status, degraded_models, profile, detectors_skipped_by_profile}'
```

`status: degraded` means a model that was expected did not load — a fault.
`detectors_skipped_by_profile` listing `output_safety` is **not** a fault; the
consumer profile declines to run it. Those two are deliberately different
fields. See `services/detection/detection_profile.py`.

## First smoke test

Nothing is proven until this whole sequence works end to end:

1. `POST /auth/request-code` → `POST /auth/verify-code` (set
   `AIPROTECT_RETURN_LOGIN_CODE=true` temporarily, or read the mail)
2. `POST /devices` → returns a credential **once**
3. `POST /devices/{id}/join-code` → join a second surface, confirm it does
   **not** consume a device slot
4. `POST /safe-links` against a known-bad URL → expect `verdict: blocked`
5. `GET /activity` → the block appears, attributed to the right device
