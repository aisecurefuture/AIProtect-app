/**
 * Client for api.aiprotect.app.
 *
 * Passes responses through WHOLE. The temptation in a client like this is to
 * simplify -- return a boolean instead of an entitlement, a string instead of
 * a verdict object -- and every such simplification throws away a distinction
 * the services went to trouble to preserve. Narrowing happens in
 * protection.ts, where it is tested.
 */

import type { ConsumerVerdict, Entitlement, PrivacyResult } from "./protection.ts";

const BASE =
  process.env.NEXT_PUBLIC_API_URL ?? "https://api.aiprotect.app";

const TOKEN_KEY = "aiprotect.token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null): void {
  if (typeof window === "undefined") return;
  if (token) window.localStorage.setItem(TOKEN_KEY, token);
  else window.localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(status: number, detail: unknown, message: string) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  deviceId?: string
): Promise<T> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...(init.headers as Record<string, string> | undefined),
  };
  const token = getToken();
  if (token) headers.authorization = `Bearer ${token}`;
  // The DEVICE, never the surface. A laptop's extension and desktop app share
  // one device id, which is what makes them share a rate-limit bucket.
  if (deviceId) headers["x-device-id"] = deviceId;

  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  const body = await res.json().catch(() => ({}));

  if (!res.ok) {
    const detail = (body as { detail?: unknown }).detail ?? body;
    const message =
      typeof detail === "object" && detail !== null && "detail" in detail
        ? String((detail as { detail: unknown }).detail)
        : typeof detail === "object" && detail !== null && "reason" in detail
          ? String((detail as { reason: unknown }).reason)
          : `Request failed (${res.status})`;
    throw new ApiError(res.status, detail, message);
  }
  return body as T;
}

/* ---------------- auth ---------------- */

export const requestCode = (email: string) =>
  request<{ sent: boolean }>("/auth/request-code", {
    method: "POST",
    body: JSON.stringify({ email }),
  });

export const verifyCode = (email: string, code: string) =>
  request<{
    token: string;
    account: { id: string; email: string };
    entitlement: Entitlement;
  }>("/auth/verify-code", {
    method: "POST",
    body: JSON.stringify({ email, code }),
  });

export const signOutEverywhere = () =>
  request<{ sessions_revoked: number }>("/auth/sign-out-everywhere", {
    method: "POST",
  });

/* ---------------- account ---------------- */

export const getMe = () =>
  request<{
    account: { id: string; email: string };
    entitlement: Entitlement;
    devices_in_use: number;
  }>("/me");

export const getTiers = () =>
  request<{
    tiers: Record<
      string,
      {
        display_name: string;
        devices: number;
        people: number;
        price_monthly: number;
        price_annual: number;
      }
    >;
    upgrade_path: string[];
    trial_days: number;
  }>("/tiers");

/* ---------------- devices ---------------- */

export interface DeviceRow {
  id: string;
  name: string;
  platform: string | null;
  enrolled_at: string | null;
  last_seen_at: string | null;
  surfaces: Array<{ kind: string; active: boolean; last_seen_at: string | null }>;
}

export const listDevices = () =>
  request<{
    devices: DeviceRow[];
    devices_in_use: number;
    devices_allowed: number;
  }>("/devices");

export const enrollDevice = (body: {
  name: string;
  surface: string;
  platform?: string;
  machine_hint?: string;
}) =>
  request<
    | { device: DeviceRow; credential: string }
    // Rule 2: a re-enrolment match is OFFERED, never decided.
    | { needs_confirmation: true; question: string; candidate_device_id: string }
  >("/devices", { method: "POST", body: JSON.stringify(body) });

export const createJoinCode = (deviceId: string) =>
  request<{ code: string; expires_at: string }>(
    `/devices/${deviceId}/join-code`,
    { method: "POST" }
  );

export const joinDevice = (code: string, surface: string) =>
  request<{
    device: DeviceRow;
    credential: string;
    consumed_a_device_slot: boolean;
  }>("/devices/join", {
    method: "POST",
    body: JSON.stringify({ code, surface }),
  });

export const removeDevice = (deviceId: string) =>
  request<{ removed: boolean; surfaces_revoked: number }>(
    `/devices/${deviceId}`,
    { method: "DELETE" }
  );

/* ---------------- protection ---------------- */

export const checkLink = (url: string, deviceId?: string) =>
  request<{ consumer: ConsumerVerdict; device_id: string | null }>(
    "/safe-links",
    { method: "POST", body: JSON.stringify({ url }) },
    deviceId
  );

export const checkPrivacy = (text: string, deviceId?: string) =>
  request<PrivacyResult>(
    "/privacy-check",
    { method: "POST", body: JSON.stringify({ text }) },
    deviceId
  );

/* ---------------- billing ---------------- */

export const startCheckout = (tier: string, priceId: string) =>
  request<{ id: string; url: string }>("/billing/checkout", {
    method: "POST",
    body: JSON.stringify({ tier, price_id: priceId }),
  });

export const openBillingPortal = () =>
  request<{ url: string }>("/billing/portal", { method: "POST" });

/* ---------------- activity ---------------- */

export interface ActivityItem {
  id: string;
  at: string;
  headline: string;
  tone: "good" | "attention" | "bad";
  device: string;
  surface: string | null;
  detail: string;
}

export const getActivity = () =>
  request<{
    items: ActivityItem[];
    /** False when the audit service is unreachable. An empty feed and a
     *  broken one are different facts -- do not collapse them. */
    available: boolean;
    caveats: string[];
  }>("/activity");
