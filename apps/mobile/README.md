# aiprotect/mobile — iOS & Android (phone + tablet)

**Status:** not built. v1 = Prompt 6, v2 = Prompt 7.

## Do NOT fork `/mobile`

The repo-root `mobile/` app is a **read-only B2B SOC dashboard** and it
**cannot build**: no Xcode project, no `AndroidManifest.xml`, no `index.js`, no
babel/metro config, and a Podfile targeting a `CyberArmorProtect` target that
does not exist. It calls `/api/v1/*` endpoints that were never implemented
server-side. Its `EndpointOS` type is `macos | windows | linux` — it does not
model mobile devices at all.

**Salvage patterns only:** API client shape, offline queue, WebSocket reconnect,
biometric gate, notification setup.

**Do not carry over its security bugs:** API key in AsyncStorage plaintext
(`src/services/auth.ts:5,71`), credential in the WebSocket query string
(`src/services/websocket.ts:33`), and a biometric gate defeated by its own
`onSkip` prop (`App.tsx:67`). Use Keychain / Keystore and real session tokens.

## Two stages

**v1 — ships with no Apple entitlement.** Account, Home, Devices, Family,
Settings, Activity. Safe Links via iOS Share Extension and Android share intent.
Safari Web Extension on iOS, Chromium extension on Android. Privacy Guard as an
in-app paste check. Tablet master/detail layouts. This is a real product and it
de-risks everything downstream.

**v2 — full on-device protection, gated on Apple.** Swift
`NEPacketTunnelProvider` (`ios-native/`) and Kotlin `VpnService`
(`android-native/`). **React Native cannot host either** — they are native.

## The long pole
The **Apple Network Extension entitlement** must be applied for on day 0; it
gates all of v2. Read `docs/specs/mobile-endpoint-security.md` first — it
already analyzes this and rules out the Android Accessibility-service route on
Play-policy grounds.
