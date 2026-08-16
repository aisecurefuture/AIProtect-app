# aiprotect/marketing — `aiprotect.app`

**Status:** not built. Built by Prompt 9.

Fork of the repo-root `marketing/` Next.js app, reskinned for consumers.

## Positioning
"AI security for your everyday devices." Value proposition, pricing, privacy
promise, sign-up CTA, app store badges.

## Honesty constraint
Do not claim capabilities the code does not have. Specifically: this platform
**inspects AI traffic; it does not parse documents** — there is no PDF/DOCX/
XLSX/OCR capability. No consumer copy may imply document scanning.

Wire analytics with consent.

---

## Built 2026-08-16

Next.js with `output: "export"` — the whole site is static files. No Node
process on the box, which matters because it shares a host with a paying
customer's stack. 23 files, 1.5 MB.

```bash
npm install && npm run build     # -> out/
```

**Pricing is read from `shared/tiers.json` at build time** (`lib/tiers.ts`), not
retyped. A price on a marketing page that disagrees with the entitlement check
is a customer billed for one thing and given another — and the marketing page is
the one people screenshot. Verified after each build: every `$n.nn` on the page
traces back to that file.

### The constraint on the copy

It may only claim what the code does. This product inspects AI traffic and
checks URLs; it does **not** parse documents — no PDF, DOCX, XLSX or OCR exists
anywhere in the codebase — and it is not antivirus. The *"What we don't do"*
section is on the page, beside the promises, rather than in a support article.

The call to action is a **waitlist, not a buy button**, because nothing is
deployed. `components/Waitlist.tsx` posts to `NEXT_PUBLIC_WAITLIST_ENDPOINT` if
one is set, and otherwise renders a mailto and says so — a form that silently
swallows an address is worse than no form.

### How it is served

A separate `aiprotect-site` container (nginx, static mount, no published
ports) on the CyberArmor compose network, with Caddy reverse-proxying to it.
**Deliberately not a Caddy bind mount:** that would require recreating Caddy,
which is 80/443 downtime for the pilot. This way deploying is a graceful
reload.

```bash
npm run build
scp -r out/. root@178.156.228.46:/opt/aiprotect/site/
ssh root@178.156.228.46 'docker restart docker-compose-aiprotect-site-1'
```

`aiprotect.app` and `www` serve this. `app` / `api` / `docs` / `support` keep
the holding page until they have something behind them.
