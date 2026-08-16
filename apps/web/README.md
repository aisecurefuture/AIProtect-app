# aiprotect/web — responsive consumer portal

**Status:** not built. Built by Prompt 4.

Responsive Next.js app: phone → tablet → desktop. Authenticates against
`api.aiprotect.app`.

## Reuse
The Next.js stack and component conventions from the repo-root `marketing/`
app (Tailwind, `components.json`, TS config).

## Do NOT reuse
`customer-portal/` — it is a 536 KB vanilla-JS SPA with tenant/MFA/SIEM/SSO
assumptions baked in. Wrong framework and wrong product.

## Screens
Onboarding (target: under 60 s to first protected device) · Home ("You're
protected" + Activity) · Safe Links · Privacy Guard · Devices · Family ·
Settings.

## Bar
Accessibility AA, dark mode, no jargon, and a prominent honest "what we can and
cannot see" explainer that matches the actual data flows.
