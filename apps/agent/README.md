# aiprotect/agent — consumer desktop app

**Status:** branding scaffold only. `branding.py` and its guard test are in
place; no agent code has been ported yet.

Forked from `agents/endpoint-agent/` in CyberArmorAi. That agent is ~49,000
lines of Python across macOS/Windows/Linux, built for an enterprise control
plane. This is not a copy with the names changed — most of it should not ship
to a consumer, and the parts that should need their enrolment model replaced.

---

## Branding

Two names, and the split is load-bearing rather than decorative.

| Surface | Name |
|---|---|
| Menu bar, tray, notifications, status window | **AIProtect** |
| Installer welcome, About box, store listing, docs footer | **AIProtect.app by CyberArmor.AI** |
| Gatekeeper / SmartScreen publisher | **CyberArmor.AI** (the signing entity) |

The publisher string is not a choice. Authenticode on Windows and the
Developer ID on macOS display the *enrolled organisation*, which is
CyberArmor. An installer whose OS trust prompt names a company the customer
has never heard of is a supply-chain smell — to precisely the security-minded
customer this product is sold to. Naming it up front costs nothing and removes
the surprise.

Every name and identifier lives in [`branding.py`](branding.py).
`tests/test_the_agent_carries_no_cyberarmor_identifiers.py` fails the build if
a literal slips back in during the port; it allows exactly two things, both
deliberately — provenance comments, and `cyberarmor_core` imports (the shared
library keeps its name by decision of 2026-08-16).

**Identifiers are permanent.** macOS keys notification permission to
`CFBundleIdentifier`, so changing `STATUS_BUNDLE_ID` after the first install
silently resets that permission for every existing user and the agent goes
quiet without erroring. There are zero installs today. This is the free moment.

---

## What to port, and what not to

Line counts are the B2B originals, as a size signal — not an estimate of the
work, since the rewrites are where the time goes.

### Port — the consumer product is mostly these

| Module | Lines | Note |
|---|---:|---|
| `local_proxy/` | 3,624 | **"Protect everything" — decided: ship it, opt-in at install.** See below. |
| `ai_traffic_coverage.py` | 805 | What AI traffic is actually covered on this host. The honest-coverage reporting is the point. |
| `monitors/url_trust_gate.py` | 532 | Safe Links at the OS level, not just the browser. |
| `monitors/ai_tool_detector.py` | 634 | Finds the AI apps installed locally. |
| `clipboard_helper.py` | 316 | Privacy Guard for paste, outside the browser. |
| `captive_portal_watchdog.py` | 189 | Small, and prevents a hotel wifi looking like an outage. |
| `dlp/` | 820 | Subject to the labelled-PII rule — bare digit runs are not PII. |
| `status_ui/` | 3,713 | Menu bar / tray. Rebrand throughout; this is the most string-dense subsystem. |
| `status_document.py` | 570 | The status model already refuses to claim unverified protection. Keep that property. |
| `hostplat/` | 1,518 | Per-OS hooks. Consumer needs a subset. |

### Rewrite — same job, different product

| Module | Lines | Why it cannot come across |
|---|---:|---|
| `cyberarmor_policy_client.py` | 855 | Enrols against a tenant control plane. Consumer enrols a **device credential** against `api.aiprotect.app`, and there is no tenant. |
| `installer.py` | 1,823 | Takes `--control-plane-url`, `--tenant-id`, `--bootstrap-token`. Consumer install is a signed package and a six-character join code. |
| `policy_enforcer.py` | 751 | Enterprise policy objects. Consumer has presets. |
| `agent.py` | 2,320 | The main loop survives; its config surface and enrolment do not. |

### Do not port

Each of these is a deliberate exclusion, not an oversight.

| Module | Lines | Why |
|---|---:|---|
| `patch_manager.py` | 468 | Applies OS/app updates via winget, Homebrew, apt, yum. A consumer product that installs software is a different, much heavier trust and liability proposition than one that warns. |
| `privileged_actions.py` | 867 | The broker exists to make patching and EDR response auditable. With neither, it has no callers. |
| `zero_day/` | 3,456 | Sandbox detonation and RCE guard. Consumer machines are not a malware lab, and the containment story is per-OS and hard-won. |
| `collectors/abom.py` | 826 | AI bill-of-materials — a compliance artefact. No consumer asks for one. |
| `crypto/pqc.py`, `fips.py` | 387 | ML-KEM/ML-DSA telemetry signing exists for regulated B2B buyers. TLS is the consumer requirement. |
| `updater/` | 869 | Consumer auto-update should be the OS-native mechanism (Sparkle / MSIX), not the B2B manifest updater. |
| EDR response actions | — | Process kill and host isolation. Not consumer behaviour, whoever asks for it. |

**Excluded here, retained in the B2B product** — this list is a scoping
decision for a consumer product, not a judgement on that code. The two
response-side defects found on 2026-08-19 (uncontained `sandbox_enabled` on
Linux/Windows, Linux isolation reporting success on a failed link) were both
fixed there on the same day.

---

## "Protect everything" — decided

The local proxy ships, **off by default and opted into at install time**. It is
the difference between covering the browser and covering Claude Desktop and the
ChatGPT desktop app, and that difference is most of the product's value on a
machine where the AI tooling is not a browser tab.

What that costs is stated in full at the moment of the decision, not behind a
"learn more" — `apps/web/lib/coverage.ts`, pinned by `coverage.test.ts`:

- a root certificate is installed and stays until removed or uninstalled
- antivirus may flag the change
- certificate-pinning apps will refuse to connect while it is on
- it asks for the user's password

`deep_inspection` on the subscription records the choice. **Turning it ON is
an install-time action on the machine, never a web toggle** — the portal shows
its state and its consequences and points at the app, because a web page
cannot install a trust anchor and should not pretend to.

### Fail mode: already built, and the agent must obey the same one

The portal setting is live and directs every surface — `fail_mode` on the
subscription, served on `/me`, `/safe-links` and `/privacy-check`, cached by
the extension because it is consulted precisely when the API is unreachable.

**The agent reads the same value and must interpret it in exactly one place**,
the way `apps/extension/src/verdict.js` does. This is not style. The
2026-08-06 defect in CyberArmor.ai was one `FAIL_OPEN` flag with two code
paths reading it: the policy path honoured it, the redact path blocked
unconditionally, and an endpoint configured fail-open had its AI traffic
blocked while every description of its configuration said otherwise. It
surfaced as `API Error: 403` in Claude Code and the user uninstalled the agent
to get working again.

Two consequences for the port:

1. **One resolution point.** Port `local_proxy/`'s fail handling through a
   single function, and pin it with the structural equivalent of
   `behaviour.test.mjs`'s "no decision path branches on fail mode on its own".
2. **Port `user_notify.py`.** A fail-closed block that does not identify
   itself is indistinguishable from the destination being broken, and the
   rational response to "ChatGPT is broken" is to uninstall what you installed
   last. `classify_reason` keeping "blocked by policy" apart from "blocked
   because we could not check" is the load-bearing part.

**The consumer default is fail-OPEN**, which differs from B2B's fail-closed
(tenant decision 2026-08-06). A household has no administrator to call when
the browser stops working. Changing it is a product decision; it lives in one
constant per surface.

---

## The maker on a Raspberry Pi — decided: yes, and arm64 is the real work

An earlier draft of this file argued ROS 2 did not belong in a consumer
product because "nobody in that market runs a ROS 2 node". That is wrong.
People buy a Pi at Micro Center or direct from the manufacturer, flash ROS 2
onto it, and build something that moves. A Pi is a device on a household plan
exactly as a laptop is — Personal covers 3, Pro covers 10.

But the reason to support them is **not** the one the ROS agent was built for,
and conflating the two would ship the wrong product.

### What actually earns its place, in order

**1. The Pi is an AI surface with no browser.** This is the whole case, and it
needs no ROS-specific code at all. A hobby robot calling OpenAI or Anthropic
for voice or vision is doing exactly what this product exists to inspect, on a
machine where the browser extension cannot reach. The Linux agent covers it —
`ai_traffic_coverage`, `monitors/url_trust_gate`, and the local proxy under the
same opt-in and the same portal fail mode as every other device.

**The blocker is arm64, and nobody has looked at it.** There is no `aarch64`,
`arm64` or `armv7` handling anywhere in `agents/endpoint-agent/` — not in
`hostplat/linux.py`, not in the installer. Every Pi is arm64. Before any ROS
work, the Linux agent has to build and run on arm64, which also means the
detection calls it makes must be affordable from a 4–8 GB board. That is
ordinary porting work and it is the thing standing between a maker and the
product today.

**2. ROS 2's defaults are genuinely unsafe on a home network, and saying so is
cheap.** Default DDS discovery is unauthenticated and multicast — every topic
on the robot is readable by anything else on the LAN, including a guest phone.
`dds_inspector.py` (390 lines) already finds this. For a maker this is a
one-screen finding with a real fix, and it is the kind of thing a hobbyist has
no way to discover on their own.

**3. Actuator safety is real, hardware-verified, and a different product.**
`actuator_policy.py` has emergency stop, geofencing, safety zones, and
velocity, acceleration and rate limits; the on-wire speed clamp and e-stop were
verified on physical hardware. It is genuinely good, and it is **robotics
safety, not AI security**. It matters here only where the two meet: a prompt
injection that reaches something that moves has physical consequences, which
is the one place a consumer AI-security product has standing to clamp a
velocity command.

### What this means for scope

| | Ship |
|---|---|
| Linux agent on **arm64** | Yes — this is the maker story, and it is prerequisite to everything below |
| `dds_inspector.py` | Yes, as a **finding**, not enforcement: "your robot's topics are readable by anything on your wifi" |
| `actuator_policy` / `actuator_bridge` | Only behind the AI link — clamp on an injected instruction reaching an actuator. Not as general robot safety. |
| `sensor_integrity`, `service_guard`, `launch_guard` | No. Industrial robotics assurance; belongs in CyberArmor. |

`agents/ros-agent/` is ~3,600 lines across 11 modules and **touches no AI
traffic at all** — it is a robotics-safety agent. Porting it wholesale would
put an industrial safety product inside a consumer AI-security subscription and
leave us supporting both. Take the two pieces above; leave the rest where it
earns its money.

### Honest limits to state in the UI

A maker will test this, so it should not overstate. On a Pi we inspect AI
traffic the same as anywhere else; we do **not** certify a robot as safe, and
nothing here is a substitute for a hardware e-stop.

---

## Still open

Nothing blocking. `docs/PRICING.md` may want a sentence acknowledging that a
single-board computer counts as a device, since a maker reading "3 devices"
will ask.

---

## Order

Nothing below starts until the browser extension ships — that is the surface
consumers expect, and the desktop agent is the heaviest lift with the lowest
consumer expectation. Signed installers per OS plus auto-update is a large,
permanent, ongoing cost.

1. Consumer enrolment against `api.aiprotect.app` (device credential + join code),
   reading `fail_mode` and `deep_inspection` from the same responses the
   extension already uses
2. `ai_traffic_coverage` + `monitors/url_trust_gate`
3. Status UI (menu bar / tray), rebranded
4. `clipboard_helper` (Privacy Guard outside the browser)
5. `local_proxy/` + `user_notify.py` — "protect everything", opt-in at install
6. Signed installers, per OS
7. **arm64** — the Linux agent on a Raspberry Pi (see the maker section). Can
   move earlier: it needs no installer signing, since makers already run
   `apt`/`pip` on a board they flashed themselves.
8. `dds_inspector` as a finding, for ROS 2 makers

Port-back note: `test_a_chain_corroborates_it_does_not_convict.py` was dropped
at the fork because it imports `local_proxy/transparent_proxy.py`. **It comes
back with the proxy** — the property it pins, that a promptware chain
corroborates rather than convicts, is not B2B-specific. See
[`FORK-PROVENANCE.md`](../../FORK-PROVENANCE.md).
