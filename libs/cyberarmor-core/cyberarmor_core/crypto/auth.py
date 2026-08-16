"""Shared PQC auth helpers for CyberArmor services.

This module standardizes two behaviors across services:

1. Incoming API key verification:
   - accept plaintext keys in compatibility mode
   - accept PQC-wrapped keys using the shared key transport
   - support current + previous key material during rotation

2. Outbound API key transport:
   - fetch the target service's public key
   - cache it briefly
   - encrypt the shared secret into ``x-api-key: PQC:<...>``
   - optionally fall back to plaintext during staged rollout
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, Optional

from fastapi import HTTPException

from .key_rotation import KeyRotationManager
from .key_transport import PQCKeyTransport


_MANAGERS: Dict[tuple[str, str], KeyRotationManager] = {}
_MANAGERS_LOCK = threading.Lock()

_PUBLIC_KEY_CACHE: Dict[str, dict] = {}
_PUBLIC_KEY_CACHE_LOCK = threading.Lock()


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _service_env_prefix(service_name: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in service_name.upper())


def _default_key_store_path(service_name: str) -> str:
    safe_name = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in service_name)
    return f"./data/{safe_name}-keys"


def resolve_key_store_path(service_name: str, key_store_path: Optional[str] = None) -> str:
    if key_store_path:
        return key_store_path
    prefix = _service_env_prefix(service_name)
    return (
        os.getenv(f"{prefix}_PQC_KEY_STORE_PATH")
        or os.getenv("CYBERARMOR_PQC_KEY_STORE_PATH")
        or _default_key_store_path(service_name)
    )


def get_key_manager(service_name: str, key_store_path: Optional[str] = None) -> KeyRotationManager:
    resolved = resolve_key_store_path(service_name, key_store_path)
    cache_key = (service_name, resolved)
    with _MANAGERS_LOCK:
        manager = _MANAGERS.get(cache_key)
        if manager is None:
            rotation_interval = int(os.getenv("CYBERARMOR_PQC_ROTATION_INTERVAL_SECONDS", "86400"))
            manager = KeyRotationManager(
                service_name=service_name,
                rotation_interval_s=rotation_interval,
                key_store_path=resolved,
            )
            manager.initialize()
            _MANAGERS[cache_key] = manager
        elif manager.needs_rotation():
            manager.rotate()
    return manager


@dataclass
class ResolvedAPIKey:
    plaintext_key: str
    transport: str
    key_id: Optional[str] = None


def resolve_api_key_header(
    api_key: Optional[str],
    *,
    service_name: str,
    key_store_path: Optional[str] = None,
    allow_plaintext: Optional[bool] = None,
    require_encrypted: Optional[bool] = None,
) -> ResolvedAPIKey:
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    plaintext_allowed = (
        _bool_env("CYBERARMOR_PQC_ALLOW_PLAINTEXT", True)
        if allow_plaintext is None
        else allow_plaintext
    )
    encrypted_required = (
        _bool_env("CYBERARMOR_PQC_REQUIRE_ENCRYPTED", False)
        if require_encrypted is None
        else require_encrypted
    )

    if not PQCKeyTransport.is_pqc_encrypted(api_key):
        if encrypted_required:
            raise HTTPException(status_code=401, detail="PQC-encrypted API key required")
        if not plaintext_allowed:
            raise HTTPException(status_code=401, detail="Plaintext API keys are disabled")
        return ResolvedAPIKey(plaintext_key=api_key, transport="plaintext")

    manager = get_key_manager(service_name, key_store_path)
    transport = PQCKeyTransport()
    for key_id in manager.list_all_key_ids():
        secret = manager.get_kem_secret_key(key_id)
        if not secret:
            continue
        try:
            plaintext = transport.decrypt_api_key(api_key, secret)
            return ResolvedAPIKey(plaintext_key=plaintext, transport="pqc", key_id=key_id)
        except Exception:
            continue
    raise HTTPException(status_code=401, detail="Invalid PQC-encrypted API key")


def verify_shared_secret(
    api_key: Optional[str],
    expected_secret: str,
    *,
    service_name: str,
    key_store_path: Optional[str] = None,
    allow_plaintext: Optional[bool] = None,
    require_encrypted: Optional[bool] = None,
) -> ResolvedAPIKey:
    resolved = resolve_api_key_header(
        api_key,
        service_name=service_name,
        key_store_path=key_store_path,
        allow_plaintext=allow_plaintext,
        require_encrypted=require_encrypted,
    )
    if resolved.plaintext_key != expected_secret:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return resolved


def get_public_key_info(service_name: str, key_store_path: Optional[str] = None) -> dict:
    manager = get_key_manager(service_name, key_store_path)
    info = manager.get_public_key_info()
    info["service"] = service_name
    info["public_key_url"] = "/pki/public-key"
    return info


def _fetch_public_key_info(public_key_url: str, timeout_s: float) -> dict:
    request = urllib.request.Request(
        public_key_url,
        headers={"Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout_s) as response:
        payload = response.read().decode("utf-8")
        return json.loads(payload)


def _resolve_public_key_url(service_url: str) -> str:
    parsed = urllib.parse.urlparse(str(service_url or "").strip())
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid service URL for PQC auth: {service_url}")
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/pki/public-key", "", "", ""))


def build_pqc_auth_header(
    target_base_url: str,
    api_key_secret: str,
    *,
    cache_ttl_seconds: Optional[int] = None,
    timeout_s: Optional[float] = None,
    strict: Optional[bool] = None,
) -> str:
    if not api_key_secret:
        raise ValueError("api_key_secret is required")

    ttl = cache_ttl_seconds or int(os.getenv("CYBERARMOR_PQC_PUBLIC_KEY_CACHE_TTL_SECONDS", "300"))
    fetch_timeout = timeout_s or float(os.getenv("CYBERARMOR_PQC_PUBLIC_KEY_TIMEOUT_SECONDS", "3"))
    strict_mode = (
        _bool_env("CYBERARMOR_PQC_OUTBOUND_STRICT", False)
        if strict is None
        else strict
    )
    public_key_url = _resolve_public_key_url(target_base_url)

    now = time.time()
    info = None
    with _PUBLIC_KEY_CACHE_LOCK:
        cached = _PUBLIC_KEY_CACHE.get(public_key_url)
        if cached and now < cached["expires_at"]:
            info = cached["info"]

    if info is None:
        try:
            fetched = _fetch_public_key_info(public_key_url, fetch_timeout)
            if "kem_public_key" not in fetched:
                raise ValueError("public key response missing kem_public_key")
            info = fetched
            with _PUBLIC_KEY_CACHE_LOCK:
                _PUBLIC_KEY_CACHE[public_key_url] = {
                    "info": info,
                    "expires_at": now + ttl,
                }
        except Exception:
            if strict_mode:
                raise
            return api_key_secret

    try:
        public_key = bytes.fromhex(info["kem_public_key"])
        return PQCKeyTransport().encrypt_api_key(api_key_secret, public_key)
    except Exception:
        if strict_mode:
            raise
        return api_key_secret


def build_auth_headers(
    target_base_url: str,
    api_key_secret: Optional[str],
    base_headers: Optional[Dict[str, str]] = None,
    *,
    enable_pqc: Optional[bool] = None,
    strict: Optional[bool] = None,
) -> Dict[str, str]:
    headers = dict(base_headers or {})
    if not api_key_secret:
        return headers

    pqc_enabled = (
        _bool_env("CYBERARMOR_PQC_AUTH_ENABLED", False)
        if enable_pqc is None
        else enable_pqc
    )
    if pqc_enabled:
        headers["x-api-key"] = build_pqc_auth_header(
            target_base_url,
            api_key_secret,
            strict=strict,
        )
    else:
        headers["x-api-key"] = api_key_secret
    return headers
