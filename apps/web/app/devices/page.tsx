"use client";
import { useEffect, useState } from "react";
import { listDevices, removeDevice, createJoinCode, type DeviceRow, ApiError } from "@/lib/api";
import { describeDevice, capMessage } from "@/lib/protection";
import { StatusCard } from "@/components/Status";

export default function Devices() {
  const [rows, setRows] = useState<DeviceRow[]>([]);
  const [inUse, setInUse] = useState(0);
  const [allowed, setAllowed] = useState(0);
  const [error, setError] = useState("");
  const [joinCode, setJoinCode] = useState<{ code: string; expires: string } | null>(null);

  async function load() {
    try {
      const out = await listDevices();
      setRows(out.devices); setInUse(out.devices_in_use); setAllowed(out.devices_allowed);
    } catch { setError("We couldn't load your devices."); }
  }
  useEffect(() => { load(); }, []);

  async function remove(d: DeviceRow) {
    // Removing a device revokes EVERY surface on it -- say so before doing it,
    // because on a lost laptop that is the whole point.
    const installed = d.surfaces.filter((s) => s.active).length;
    const ok = window.confirm(
      `Remove “${d.name}”? This signs out all ${installed} install${installed === 1 ? "" : "s"} on it and frees a device slot.`
    );
    if (!ok) return;
    try { await removeDevice(d.id); await load(); }
    catch (err) { setError(err instanceof ApiError ? err.message : "We couldn't remove that device."); }
  }

  async function addSurface(d: DeviceRow) {
    try {
      const out = await createJoinCode(d.id);
      setJoinCode({ code: out.code, expires: out.expires_at });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "We couldn't create a code.");
    }
  }

  const atCap = inUse >= allowed && allowed > 0;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Devices</h1>
        <p className="mt-1 text-sm opacity-70">{capMessage(inUse, allowed)}</p>
      </header>

      {error ? <p role="alert" className="text-sm text-red-600">{error}</p> : null}

      {atCap ? (
        <StatusCard
          tone="attention"
          headline="You're using all your devices"
          detail="Remove one you no longer use, or move to a bigger plan. We never remove a device for you."
        />
      ) : null}

      {joinCode ? (
        <StatusCard tone="good" headline="Add another install to this device"
          detail="Enter this code in the app or extension you're installing.">
          <p className="mt-2 font-mono text-3xl tracking-[0.3em]">{joinCode.code}</p>
          <p className="mt-1 text-sm opacity-80">
            Expires {new Date(joinCode.expires).toLocaleTimeString()}. It doesn't use another device slot.
          </p>
        </StatusCard>
      ) : null}

      <ul className="space-y-3">
        {rows.map((d) => (
          <li key={d.id} className="rounded-xl border border-slate-200 p-4 dark:border-slate-800">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <h2 className="font-medium">{d.name}</h2>
                {/* Surfaces shown per device, so one laptop reads as one
                    device with two installs rather than a count that does not
                    match what the person installed. */}
                <p className="mt-0.5 text-sm opacity-70">{describeDevice(d)}</p>
                {d.last_seen_at ? (
                  <p className="mt-0.5 text-xs opacity-50">
                    Last seen {new Date(d.last_seen_at).toLocaleDateString()}
                  </p>
                ) : null}
              </div>
              <div className="flex shrink-0 flex-col gap-2">
                <button onClick={() => addSurface(d)}
                  className="rounded-lg border border-slate-300 px-3 py-2 text-sm dark:border-slate-700">
                  Add install
                </button>
                <button onClick={() => remove(d)}
                  className="rounded-lg border border-red-300 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:text-red-300">
                  Remove
                </button>
              </div>
            </div>
          </li>
        ))}
      </ul>

      {!rows.length ? <p className="text-sm opacity-70">No devices yet.</p> : null}
    </div>
  );
}
