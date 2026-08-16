# aiprotect/web — responsive consumer portal

Next.js 15 (App Router) + Tailwind. One UI for phone, tablet and desktop.

```bash
npm install
npm run dev      # http://localhost:3000
npm test         # the honesty tests -- see below
npm run build
```

`NEXT_PUBLIC_API_URL` points at the consumer API (default
`https://api.aiprotect.app`).

## Screens

| Route | What it does |
|---|---|
| `/signin` | Passwordless email code, two steps |
| `/home` | Protection status, quick actions, device count |
| `/links` | Safe Links — check a URL |
| `/privacy` | Privacy Guard — check text before sharing it with an AI |
| `/devices` | List, add an install, remove a device |
| `/settings` | Subscription, "what we can see", sign out everywhere |
| `/family` | Honest placeholder — not built yet |

## `lib/protection.ts` is the important file

Three services take real care to distinguish **"we checked and it was fine"**
from **"we did not check"**:

- `entitlements.py` — four subscription states, only one of which stops
  protection, each carrying a reason
- `consumer_verdict.py` — `safe` plus `checks_performed` and `page_was_read`,
  because a reputation-only answer is a weaker claim than a fetched-and-scanned
  one
- detection — `scan_complete` and `checks_skipped_by_profile`

**Every one of those distinctions dies at a `? "Protected" : "Not protected"`
ternary in a component.** The backend cannot defend itself from the frontend.
So the mapping lives in one tested place instead of being re-improvised per
screen, and `lib/protection.test.ts` pins it:

- a fetched page and an unfetched one do not produce the same headline
- an incomplete scan never claims nothing was found
- `grace` renders as "still protected", not as an outage
- an unknown verdict never renders as safe

Run with `make test-web` from the repo root, or `npm test` here.

## Conventions

- **Colour is never the only signal.** Each status carries a word and a mark as
  well as a hue — the difference between "blocked" and "be careful" has to
  survive a colour vision deficiency in a security product.
- **`checks_performed` is always rendered**, never behind a disclosure. Someone
  deciding whether to type a password into a page should not have to go looking
  for whether we opened it.
- **A failed check is not a safe verdict.** Network errors say "we couldn't
  check", never a green tick.
- **Placeholders are honest.** `/family` says it isn't ready. Home has no
  Activity feed rather than a fake one — invented events in a security product
  are the worst possible placeholder.
- Touch targets are ≥ 48px; nav is a bottom bar on phones and a top bar from
  `sm` up.

## Not built yet

Onboarding/plan-picker flow, QR enrollment, Family invites, Kids preset,
Activity feed (the API does not read from the audit service yet), and
Apple/Google sign-in.
