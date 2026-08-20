# Pricing

Decided 2026-08-16. Numbers live in [`shared/tiers.json`](../shared/tiers.json)
— that file is the single source of truth and this document is the reasoning.
Validated by `tests/test_pricing_is_coherent.py`.

## The table

| Tier | Devices | People | Monthly | Annual | Effective | Per device/yr |
|---|---:|---:|---:|---:|---|---:|
| **Personal** | 3 | 1 | $4.99 | $39.99 | ~$3.33/mo | $13.33 |
| **Pro** | 10 | 1 | $9.99 | $79.99 | ~$6.67/mo | $8.00 |
| **Family** | 30 | 7 | $14.99 | $119.99 | ~$10.00/mo | $4.00 |

**No free tier.** 14-day trial, card required, then the subscription starts.

**No per-device add-on.** Outgrow a tier, upgrade to the next one.

Annual is ~33% off (two months free) and is the default on the pricing page.
Annual prepay is cash flow *and* churn reduction — the renewal decision happens
once a year instead of twelve times, which matters a great deal to a company
funding itself.

## Why these numbers

**Market anchor.** Consumer security subscriptions cluster in the **$40–100/yr**
band (Norton, Bitdefender, McAfee all sit there, though promotional pricing
moves constantly — verify current numbers before launch). AI security is
differentiated enough to sit at the upper-middle of that band. It is not
differentiated enough to sit at 3× it.

**Devices are nearly free to serve.** Measured on the consumer profile:
~0.89 s per scan, plus a content-hash result cache on repeated content. An
active device costs well under a cent per month in compute. Device generosity
is therefore cheap, and the constraints that actually cost money — app-store
fees, support, acquisition — do not scale with device count. So the caps are
set generously on purpose.

**The marginal device gets cheaper, never dearer.** $13.33 → $8.00 → $4.00 per
device per year across the upgrade path. That is the property the rejected
add-on violated, and it is pinned by a test.

**Seven people, not six.** Changed 2026-08-16. Family was 6 to match Apple
Family Sharing, on the reasoning that the mental model is already installed in
the customer's head and fighting it buys nothing. That read the anchor
backwards. Apple, Microsoft 365 Family and Google One *all* stop at 6 — so 6 is
not a neutral default, it is the exact point at which a seven-person household
discovers that every option on the market fails it. Two parents and five
children is an ordinary family; so is one with a grandparent in it.

Exceeding the installed model by exactly one is legible *because* the model is
installed. "The one that fits our family" is a claim a customer checks in five
seconds against the plan they already pay for, and it is the only line on our
pricing page that a competitor cannot match without redesigning their own.

It is also nearly free to give: devices carry the compute cost and the device
cap did not move. The 7-person limit remains the real constraint against plan
sharing — 30 devices never was one.

## What was rejected, and why

### A $34 per-additional-device add-on

- **The marginal rate exceeded the average rate.** At Pro's $8/device/year, a
  $34 add-on is more than four times the rate of the tier it extends. Marginal
  pricing should decline with volume. A customer who does that arithmetic feels
  penalised for adopting the product more.
- **No cost basis.** Under a cent per device per month.
- **Wrong mental model.** Consumers ask "does this cover my stuff", not "how
  many seats do I need" — that is an SMB frame. The incumbents all sell device
  *tiers*, not add-ons.
- **It charges friction at the worst moment.** Someone adding a 6th device is
  the most engaged user you have, the one most likely to renew and refer.

### What counts as a device

Anything the agent or extension is installed on, including a **single-board
computer**. A maker with a Raspberry Pi running ROS 2 is a real customer —
they buy the board at Micro Center or direct, flash it themselves, and it
calls AI APIs from a machine with no browser on it, which is precisely the
case the desktop agent exists for. A Pi occupies one device slot, the same as
a laptop. See `apps/agent/README.md` for what is and is not covered there;
arm64 support is the prerequisite and is not built yet.

### A 1-device entry tier

Under [one device, many surfaces](MULTI-DEVICE.md), a laptop running the
extension *and* the desktop agent is one device. So a 1-device tier means
**phone or laptop, not both.** With no free tier this is the acquisition point,
and it cannot feel broken at the moment of first payment. Entry is 3 devices:
phone, laptop, tablet.

### A web-direct discount

Real money — Apple and Google take 15% under $1M/yr, 30% above; Stripe is
~2.9%. On Family annual that is $18–36 a sale. Rejected **for launch only**:
a second price needs a second explanation, per-jurisdiction anti-steering rules
to track, and support for both. Revisit when the fee is a number worth
optimising. Until then, one price on every channel.

## The trial

**14 days, not 7.** This product proves itself when it *blocks* something, and
that is an event a light user may not encounter in a week. A trial that can end
before the product has demonstrated anything converts on faith rather than
evidence.

**The conversion moment is the reminder, not the charge.** Three days before
billing, send a "here's what we caught for you" summary. That email is what
earns the subscription — the charge just records it.

**Send it even where it is not legally required.** Auto-renewal after a trial
is regulated: FTC negative-option / click-to-cancel rules, EU consumer law, and
both app stores require the terms, price and renewal date be explicit up front,
with several jurisdictions requiring advance notice. Apple and Google handle
much of this for in-app purchases; on web via Stripe it is on us.

For a company selling security, a surprise charge is a disproportionate
reputational hit — it is precisely the trust we are asking people to extend.
The compliance step and the conversion step are the same message, so there is
no reason to do less than the most generous version of it.

## Consequences for the build

- Entitlement checks read `shared/tiers.json`. No tier number is ever written
  a second time in code — see the header of that file for why.
- The device cap is enforced as **refuse the new device, never silently evict
  an old one** ([MULTI-DEVICE.md](MULTI-DEVICE.md), rule 1).
- Hitting a cap surfaces the upgrade path, since that is now the only way to
  add devices.
- Trial state is an entitlement state, not a flag: `trialing`, `active`,
  `grace`, `lapsed`. A lapsed subscriber must never be silently unprotected
  ([MULTI-DEVICE.md](MULTI-DEVICE.md), rule 3).

## Still open

- **Store product IDs** for Apple and Google, and whether monthly and annual
  are separate products or a single subscription group with two durations
  (they should be one group, so upgrades and downgrades are handled by the
  store rather than by us).
- **Regional pricing.** Both stores offer automatic conversion; flat USD is
  simplest for launch and worst for emerging markets. Revisit with real data
  about where customers are.
