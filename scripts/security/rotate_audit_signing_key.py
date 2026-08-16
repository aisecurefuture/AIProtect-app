#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path


def _read_env(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="ignore").splitlines()


def _set_kv(lines: list[str], key: str, value: str) -> list[str]:
    prefix = f"{key}="
    out = []
    replaced = False
    for line in lines:
        if line.startswith(prefix):
            out.append(f"{key}={value}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(f"{key}={value}")
    return out


def _get(lines: list[str], key: str, default: str = "") -> str:
    prefix = f"{key}="
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix):]
    return default


def main() -> int:
    parser = argparse.ArgumentParser(description="Rotate audit signing keys in env file.")
    parser.add_argument("--env-file", default="infra/docker-compose/.env")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    env_path = Path(args.env_file)
    lines = _read_env(env_path)

    active_key = _get(lines, "CYBERARMOR_AUDIT_SIGNING_KEY", _get(lines, "AUDIT_API_SECRET", ""))
    active_kid = _get(lines, "CYBERARMOR_AUDIT_SIGNING_KEY_ID", "k1")
    next_key = _get(lines, "CYBERARMOR_AUDIT_NEXT_SIGNING_KEY", "")
    next_kid = _get(lines, "CYBERARMOR_AUDIT_NEXT_SIGNING_KEY_ID", "k2")

    if not next_key:
        next_key = secrets.token_urlsafe(48)
    if not next_kid:
        next_kid = f"{active_kid}_next"

    # Promote staged -> active, mint new staged key.
    new_active_key = next_key
    new_active_kid = next_kid
    new_next_key = secrets.token_urlsafe(48)
    new_next_kid = f"{new_active_kid}_next"

    # RETIRE THE OUTGOING KEY. Before 2026-08-12 this step did not exist: the
    # old key was simply dropped, and services/audit/main.py skips any candidate
    # whose kid does not match, so EVERY RECORD SIGNED BEFORE A ROTATION BECAME
    # PERMANENTLY UNVERIFIABLE. It would have presented as mass tampering --
    # valid=false, SIGNATURE_MISMATCH, across the whole trail, with nothing to
    # distinguish it from the real thing.
    retired_raw = _get(lines, "CYBERARMOR_AUDIT_RETIRED_KEYS", "")
    retired = [e.strip() for e in retired_raw.split(",") if e.strip()]
    retired_kids = {e.split(":", 1)[0].strip() for e in retired if ":" in e}
    retire_note = "(nothing to retire)"

    if active_key and active_kid:
        # The list is "kid:key,kid:key". token_urlsafe never emits ':' or ',',
        # but the ACTIVE key may predate this script -- on this deployment it
        # defaulted to AUDIT_API_SECRET, which is set by hand. Refuse rather
        # than write an entry that parses back wrong: a mangled retired key is
        # indistinguishable from a forged record at verify time.
        if ":" in active_key or "," in active_key or ":" in active_kid or "," in active_kid:
            print("ROTATION_ABORTED: the outgoing key or kid contains ':' or ',', "
                  "which are the separators for CYBERARMOR_AUDIT_RETIRED_KEYS. "
                  "Retiring it would corrupt the list and silently orphan every "
                  "record it signed. Re-key by hand instead.")
            return 2
        if active_kid in retired_kids:
            retire_note = f"{active_kid} already retired, not duplicated"
        elif active_kid == new_active_kid:
            retire_note = f"{active_kid} is also the new active kid, not retired"
        else:
            retired.append(f"{active_kid}:{active_key}")
            retire_note = f"{active_kid} -> retired (verify-only)"

    updated = list(lines)
    updated = _set_kv(updated, "CYBERARMOR_AUDIT_SIGNING_KEY", new_active_key)
    updated = _set_kv(updated, "CYBERARMOR_AUDIT_SIGNING_KEY_ID", new_active_kid)
    updated = _set_kv(updated, "CYBERARMOR_AUDIT_NEXT_SIGNING_KEY", new_next_key)
    updated = _set_kv(updated, "CYBERARMOR_AUDIT_NEXT_SIGNING_KEY_ID", new_next_kid)
    updated = _set_kv(updated, "CYBERARMOR_AUDIT_RETIRED_KEYS", ",".join(retired))

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = env_path.with_suffix(env_path.suffix + f".bak.{ts}")

    print("AUDIT_KEY_ROTATION_PLAN")
    print(f" - env_file: {env_path}")
    print(f" - old_active_kid: {active_kid or '(unset)'}")
    print(f" - new_active_kid: {new_active_kid}")
    print(f" - new_next_kid: {new_next_kid}")
    print(f" - retiring: {retire_note}")
    print(f" - retired_kids_after: {sorted(retired_kids | ({active_kid} if retire_note.endswith('(verify-only)') else set()))}")
    print(f" - backup: {backup}")
    print(" - NOTE: point --env-file at the file the AUDIT SERVICE reads. Since")
    print("   2026-08-12 that is the audit-only env file (CYBERARMOR_AUDIT_ENV_FILE),")
    print("   NOT the shared demo.env — 19 services read the shared one.")

    if args.dry_run:
        print("DRY_RUN: no file changes made")
        return 0

    if env_path.exists():
        backup.write_text("\n".join(lines) + "\n", encoding="utf-8")
    env_path.write_text("\n".join(updated) + "\n", encoding="utf-8")
    print("ROTATION_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
