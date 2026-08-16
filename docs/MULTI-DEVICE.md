# Multi-device subscriptions

One subscription covers many devices. That is the product — nobody owns one
screen — and it is also the single decision that shapes the consumer API, so
it is written down before the API is built rather than discovered during it.

**Status:** enforcement primitives built (see *Already built* below). The
account/device model itself is Prompt 3.

---

## The model

```
Account  (a person, or a family owner)
  └── Subscription   tier, device allowance, billing source
        ├── Member   (Family only — up to N people)
        └── Device   enrolled, named, revocable
```

**Device**, not "seat" or "install". A device is a thing a person points at:
*this iPhone*, *that laptop*. It is what the Activity feed attributes to
("Blocked on your iPhone"), so it has to match what the person would say.

## Proposed allowances

**These are pricing decisions and need confirmation.** The structure matters
more than the numbers; the numbers are a starting point.

| Tier | People | Devices | Notes |
|---|---:|---:|---|
| Free | 1 | 1 | Enough to feel the product on the device you care about most |
| Pro | 1 | 5 | Phone, tablet, laptop, work laptop, spare |
| Family | 6 | 25 | A shared pool, not 6 × a per-person cap |

**Family uses a shared device pool on purpose.** Per-person caps mean a
teenager with three devices is "over" while a parent with one is "under",
and the owner has to administer quotas inside their own household. A pool
fails in the direction of the product working.

## Rules

### 1. At the cap, refuse the new device — never silently evict an old one

Auto-evicting the least-recently-seen device to make room would leave a real
device unprotected without anyone being told. That is this codebase's recurring
defect expressed as a product behaviour: a protection claim that quietly stopped
being true. Enrollment fails with the current device list and two explicit
options — remove one, or upgrade.

### 2. A wiped device must not consume a second slot

Reinstall, factory reset, and OS upgrade are normal. If each one burns a slot,
a Pro user hits their cap through ordinary life and concludes the product is
broken. Enrollment carries a stable per-install identifier plus enough device
characteristics to offer **"is this the same iPhone you enrolled in March?"**
and reclaim the slot on confirmation. Offer — not decide silently, because
getting it wrong the other way merges two real devices into one.

### 3. Downgrade never silently unprotects

Dropping Family → Pro with 12 devices enrolled must not deactivate 7 of them
in the background. The account enters a grace state, every device keeps working,
and the person is asked to choose which to keep. Protection stops only after an
explicit choice or a clearly-communicated deadline.

### 4. Revocation is immediate and total

"Remove device" on a lost phone must invalidate that device's credential at the
API, not merely hide the row. A removed device that keeps scanning is a
credential leak with a UI that says otherwise.

### 5. Every device is individually attributable

Verdicts carry `device_id` end to end — the trust gate already does this
(`resolve_device_id`, echoed in the response). Without it the Activity feed can
only say "something was blocked", which is useless for the most common real
question: *which of my things did this happen on?*

## Rate limiting is two-level, and this is why

Ten devices at 60 rpm is 600 rpm from one subscription. A per-device limit alone
caps nothing that matters to the bill, and a Family plan makes that the normal
case rather than the abusive one.

- **Device bucket — fairness.** One compromised or runaway device must not
  consume the household's capacity and silently degrade protection on
  everyone else's phone.
- **Account bucket — cost.** The subscription is what gets billed and has a
  ceiling no number of enrolled devices may exceed.

The account ceiling is **not** `device_rpm × max_devices`. Multiplying would
re-open the exact hole it closes.

A 429 reports `scope` (`device` or `account`) because the two mean different
things to the person reading them: a device limit is transient and
self-correcting; an account limit means another device is misbehaving or the
plan is genuinely too small, and the app should say something different.

## Already built

| Piece | Where |
|---|---|
| Two-level limiter, per-device + per-account | `services/detection/rate_limit.py` — `SubscriptionLimiter` |
| `x-client-id` (device) / `x-account-id` headers, scoped 429 | `services/detection/main.py` — `_rate_limited` |
| Device attribution on every verdict | `services/url-trust-gate/main.py` — `resolve_device_id`, `TrustGateResponse.device_id` |
| Tests for the sum-past-the-ceiling case | `services/detection/tests/test_one_client_cannot_consume_every_scan_slot.py` |

Both ceilings default to `0` (unlimited) and are set per deployment in
`infra/docker-compose.yml`.

## Still to build (Prompt 3)

- Account, subscription, member, device tables; enrollment via QR / deep link.
- Per-device credentials, issue and revoke.
- Entitlement checks as FastAPI dependencies — including the cap refusal in
  rule 1 and the grace state in rule 3.
- Device re-identification for rule 2.
- The `x-account-id` / `x-client-id` values the API forwards to detection.
- Family invites and the Kids preset.

## Open questions

1. **Tier numbers** — the table above is a proposal, not a decision.
2. **Does the browser extension count as a device, or as part of the machine
   it runs on?** Counting it separately burns a slot for what a person
   experiences as one computer; not counting it means a laptop with the
   extension and the desktop agent is one device with two credentials.
   Leaning toward: **one device, many surfaces.**
3. **Grace period length** for rule 3.
