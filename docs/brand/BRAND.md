# AIProtect brand assets

Source artwork supplied 2026-08-16. Everything in
`apps/web/public/brand/` is derived from it; nothing was redrawn.

## What the two supplied files actually are

They were labelled "one for dark, one for light". Measured, that is not what
they are — **both are dark-background artwork**, and one of them is broken on
every background. Dominant fill of each word, WCAG contrast:

| File | word | fill | on white | on near-black |
|---|---|---|---:|---:|
| **File 1** (`…1B2018A8…`) | AI | `#00D8F0` cyan | 1.74:1 | **11.30:1** |
| | Protect | `#F0F0F0` near-white | **1.14:1** | **17.24:1** |
| | .app | `#0078F0` blue | 4.25:1 | 4.63:1 |
| **File 2** (`…5184CC24…`) | AI | `#00A8F0` | 2.67:1 | **7.35:1** |
| | Protect | `#000018` near-black | **20.73:1** | **1.06:1** |
| | .app | `#00A8F0` | 2.67:1 | **7.35:1** |

**File 1 is a good dark-background lockup** — all three words clear the bar on
near-black, none of them work on white.

**File 2 works on neither.** Its `AI` and `.app` are tuned for a dark page
(7.35:1) but its `Protect` is near-black, at **1.06:1 against its own
background** — the middle word of the brand name is invisible on the artwork it
ships on. On white the reverse happens: `Protect` reads and the other two
don't. It looks fine at a glance only because the outer glow suggests letters
that aren't legible.

So there was no usable light-background asset. `lockup-on-light.png` is derived
from File 1 by recolouring only the near-neutral ink (`Protect`, a flat
`#F0F0F0` across 100% of its pixels — a clean selective swap, not a guess) to
brand navy. The coloured words are untouched.

**If you go back to the designer, the thing to ask for is File 2 reissued with
`Protect` in white**, and ideally a vector (SVG) master. Everything here is
raster upscaled from a 1254px PNG.

## Files

| File | Use |
|---|---|
| `lockup-on-dark.png` | Full lockup, dark pages. **File 1 unmodified.** |
| `lockup-on-light.png` | Full lockup, light pages. Derived; see above. |
| `mark.png` | Shield + pixel dissolve, no wordmark |
| `icon-{16,32,48,128,180,512}.png` | App/favicon/touch icons |
| `apps/extension/icons/icon{16,32,48,128}.png` | Browser extension |

Icons ≤64px use the **shield alone**; the pixel dissolve turns to mush at that
size. Larger sizes keep it. All icons carry 10% padding so a rounded-rect mask
(iOS, macOS, Android adaptive) does not clip the shield point.

**16px is marginal** — the inner "A" and the keyhole merge into a blob. It is
recognisable as a shield and no worse than most favicons at that size, but if
the favicon matters, a simplified 16px mark (shield outline, no keyhole) is
real design work worth commissioning.

## Palette

Sampled from the artwork, with measured contrast.

| Token | Hex | On white | On near-black |
|---|---|---:|---:|
| `brand-cyan` | `#00D8F0` | 1.74:1 | 11.30:1 |
| `brand-sky` | `#00A8F0` | 2.67:1 | 7.35:1 |
| `brand-blue` | `#0078F0` | 4.25:1 | 4.63:1 |
| `brand-indigo` | `#2010F0` | 8.77:1 | 2.24:1 |
| `brand-navy` | `#0D1B3E` | 17.4:1 | 1.3:1 |

### Where each colour may be used

**The cyan is a logo colour, not a text colour.** At 1.74:1 on white it fails
every text threshold. WCAG exempts logotypes from contrast minimums (SC 1.4.3),
so it is fine inside the lockup — but the moment it becomes a link, a label or
a button it is a defect.

- **On light backgrounds** — text and icons: `brand-blue` (4.25:1, large text
  and UI components only) or `brand-navy` (17.4:1, body text). Never cyan,
  never sky.
- **On dark backgrounds** — text and icons: `brand-cyan`, `brand-sky` or
  `brand-blue` all clear 4.5:1. Never navy, never indigo.
- **Gradients** in decorative artwork may use the full cyan→indigo ramp.

This is a security product: the status colours in
`apps/web/components/Status.tsx` (emerald / amber / red) are deliberately NOT
brand colours, and must not be replaced with them. Someone needs to tell
"blocked" from "be careful" at a glance, and both being brand blue would make
that impossible. Colour is never the only signal there either — each status
carries a word and a mark.
