/**
 * Talking to api.aiprotect.app from the extension.
 *
 * THE EXTENSION IS A SURFACE, NOT A DEVICE.
 *
 * A laptop running this extension and the desktop app is ONE device with two
 * installs (docs/MULTI-DEVICE.md). That means:
 *
 *   * enrolling here must NOT consume a second subscription slot when the
 *     desktop app is already enrolled -- it joins that device by code
 *   * every request sends the DEVICE id as x-device-id, never a per-install
 *     id, or this laptop quietly gets double its rate-limit allowance with no
 *     second ceiling underneath to catch it
 *
 * Both are properties of what this file sends, so both live here.
 */

const DEFAULT_BASE = "https://api.aiprotect.app";

const KEYS = {
  base: "aiprotect.apiBase",
  token: "aiprotect.token",
  credential: "aiprotect.credential",
  deviceId: "aiprotect.deviceId",
  // The account's fail mode, as of the last successful call. Cached because
  // it is consulted PRECISELY when the API is unreachable -- which is the one
  // moment we cannot go and ask for it. See rememberSettings().
  failMode: "aiprotect.failMode",
};

async function stored(keys) {
  return await chrome.storage.local.get(keys);
}

export async function getConfig() {
  const s = await stored(Object.values(KEYS));
  return {
    base: s[KEYS.base] || DEFAULT_BASE,
    token: s[KEYS.token] || null,
    credential: s[KEYS.credential] || null,
    deviceId: s[KEYS.deviceId] || null,
    // Undefined until the first successful call. verdict.js resolves that to
    // the default rather than to `closed`, so a fresh install never blocks
    // browsing before it has ever spoken to us.
    failMode: s[KEYS.failMode] ?? null,
  };
}

/** The cached fail mode. Never throws, never blocks on the network. */
export async function getFailMode() {
  const s = await stored([KEYS.failMode]);
  return s[KEYS.failMode] ?? null;
}

/**
 * Refresh the cached settings from a response that carried them.
 *
 * Every check response includes a `protection` block for exactly this reason:
 * the cache updates on every success, so it cannot silently go stale between
 * a portal change and the next time this surface happens to ask.
 */
async function rememberSettings(body) {
  const mode = body?.protection?.fail_mode;
  if (mode) await chrome.storage.local.set({ [KEYS.failMode]: mode });
}

export async function saveEnrollment({ credential, deviceId }) {
  await chrome.storage.local.set({
    [KEYS.credential]: credential,
    [KEYS.deviceId]: deviceId,
  });
}

export async function saveToken(token) {
  await chrome.storage.local.set({ [KEYS.token]: token });
}

export async function clearEnrollment() {
  await chrome.storage.local.remove(Object.values(KEYS));
}

export async function isEnrolled() {
  const { credential, deviceId } = await getConfig();
  return Boolean(credential && deviceId);
}

/**
 * Every response is `{ok, body}`. Nothing throws.
 *
 * The callers' whole design is that a failed check is a DIFFERENT outcome
 * from a clean one (see verdict.js), so an exception that unwound to a
 * try/catch would lose the distinction the moment somebody wrote
 * `catch { return null }`.
 */
async function call(path, { method = "POST", body, timeoutMs = 6000 } = {}) {
  const { base, token, deviceId } = await getConfig();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = { "content-type": "application/json" };
    if (token) headers.authorization = `Bearer ${token}`;
    // THE DEVICE, never this install. See the header.
    if (deviceId) headers["x-device-id"] = deviceId;

    const res = await fetch(`${base}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    const parsed = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, body: parsed };
  } catch (err) {
    // Timeout, offline, DNS, CORS -- all the same to a caller: no answer.
    return { ok: false, status: 0, body: { reason: String(err?.name || err) } };
  } finally {
    clearTimeout(timer);
  }
}

export async function checkLink(url) {
  const res = await call("/safe-links", { body: { url } });
  if (res.ok) await rememberSettings(res.body);
  return {
    ok: res.ok,
    consumer: res.body?.consumer ?? null,
    status: res.status,
    failMode: res.body?.protection?.fail_mode ?? (await getFailMode()),
  };
}

export async function checkText(text) {
  const res = await call("/privacy-check", { body: { text } });
  if (res.ok) await rememberSettings(res.body);
  return {
    ok: res.ok,
    result: res.body ?? null,
    status: res.status,
    failMode: res.body?.protection?.fail_mode ?? (await getFailMode()),
  };
}

/** Join an already-enrolled device using a code from another install. */
export async function joinDevice(code) {
  const res = await call("/devices/join", {
    body: { code, surface: "browser-extension" },
  });
  return res;
}

/** Enrol this machine as a NEW device. Consumes a subscription slot. */
export async function enrollDevice(name) {
  const res = await call("/devices", {
    body: { name, surface: "browser-extension", platform: "browser" },
  });
  return res;
}
