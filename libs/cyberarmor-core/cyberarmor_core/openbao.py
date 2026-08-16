"""Shared OpenBao client helpers for CyberArmor services.

This module intentionally provides a thin wrapper around the OpenBao HTTP API.
The goal is to centralize transport, path construction, error handling, and
future auth changes without forcing every service to reimplement them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx


class OpenBaoError(RuntimeError):
    """Raised when OpenBao returns an error or cannot be reached."""


@dataclass(frozen=True)
class OpenBaoConfig:
    addr: str
    token: str
    namespace: Optional[str] = None
    kv_mount: str = "cyberarmor-kv"
    transit_mount: str = "cyberarmor-transit"
    timeout_seconds: float = 5.0
    verify: bool | str = True
    client_cert: Optional[tuple[str, str]] = None


class OpenBaoClient:
    """Minimal sync client for OpenBao KV and Transit operations."""

    def __init__(self, config: OpenBaoConfig):
        self.config = config

    def _headers(self) -> Dict[str, str]:
        headers = {"X-Vault-Token": self.config.token}
        if self.config.namespace:
            headers["X-Vault-Namespace"] = self.config.namespace
        return headers

    def _request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.config.addr.rstrip('/')}/v1/{path.lstrip('/')}"
        kwargs: Dict[str, Any] = {
            "headers": self._headers(),
            "timeout": self.config.timeout_seconds,
            "verify": self.config.verify,
        }
        if self.config.client_cert:
            kwargs["cert"] = self.config.client_cert
        if payload is not None:
            kwargs["json"] = payload
        try:
            response = httpx.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise OpenBaoError(f"OpenBao request failed: {exc}") from exc
        if response.status_code >= 400:
            detail = response.text.strip()
            raise OpenBaoError(
                f"OpenBao {method} {path} failed with {response.status_code}: {detail}"
            )
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise OpenBaoError(f"OpenBao returned non-JSON response for {path}") from exc

    def health(self) -> Dict[str, Any]:
        return self._request("GET", "sys/health")

    def seal_status(self) -> Dict[str, Any]:
        return self._request("GET", "sys/seal-status")

    def kv_read(self, path: str) -> Dict[str, Any]:
        payload = self._request("GET", f"{self.config.kv_mount}/data/{path}")
        return payload.get("data", {})

    def kv_read_secret(self, path: str) -> Dict[str, Any]:
        data = self.kv_read(path)
        return data.get("data", {})

    def kv_metadata(self, path: str) -> Dict[str, Any]:
        payload = self._request("GET", f"{self.config.kv_mount}/metadata/{path}")
        return payload.get("data", {})

    def kv_write(self, path: str, data: Dict[str, Any], cas: Optional[int] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"data": data}
        if cas is not None:
            payload["options"] = {"cas": cas}
        response = self._request("POST", f"{self.config.kv_mount}/data/{path}", payload)
        return response.get("data", {})

    def kv_delete_latest(self, path: str) -> None:
        self._request("DELETE", f"{self.config.kv_mount}/data/{path}")

    def transit_encrypt(
        self,
        key_name: str,
        plaintext_b64: str,
        context_b64: Optional[str] = None,
        key_version: Optional[int] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"plaintext": plaintext_b64}
        if context_b64:
            payload["context"] = context_b64
        if key_version is not None:
            payload["key_version"] = key_version
        response = self._request(
            "POST",
            f"{self.config.transit_mount}/encrypt/{key_name}",
            payload,
        )
        return response.get("data", {})

    def transit_decrypt(self, key_name: str, ciphertext: str, context_b64: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"ciphertext": ciphertext}
        if context_b64:
            payload["context"] = context_b64
        response = self._request(
            "POST",
            f"{self.config.transit_mount}/decrypt/{key_name}",
            payload,
        )
        return response.get("data", {})

    def transit_sign(
        self,
        key_name: str,
        input_b64: str,
        hash_algorithm: str = "sha2-256",
        key_version: Optional[int] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"input": input_b64}
        if key_version is not None:
            payload["key_version"] = key_version
        response = self._request(
            "POST",
            f"{self.config.transit_mount}/sign/{key_name}/{hash_algorithm}",
            payload,
        )
        return response.get("data", {})

    def transit_key_read(self, key_name: str) -> Dict[str, Any]:
        response = self._request("GET", f"{self.config.transit_mount}/keys/{key_name}")
        return response.get("data", {})

    def transit_key_rotate(self, key_name: str) -> Dict[str, Any]:
        response = self._request("POST", f"{self.config.transit_mount}/keys/{key_name}/rotate")
        return response.get("data", {})

    def transit_key_create(self, key_name: str, key_type: str = "ed25519", exportable: bool = False) -> Dict[str, Any]:
        """Create a Transit signing key. Default to ed25519 — small
        signatures, modern crypto, the right pick for SBOM/BOM
        attestations. Idempotent: a 400 "already exists" from OpenBao
        is swallowed by the caller so a service can call this on
        startup without coordinating."""
        return self._request(
            "POST",
            f"{self.config.transit_mount}/keys/{key_name}",
            {"type": key_type, "exportable": exportable, "allow_plaintext_backup": False},
        )

    def transit_verify(
        self,
        key_name: str,
        input_b64: str,
        signature: str,
        hash_algorithm: str = "sha2-256",
    ) -> Dict[str, Any]:
        """Verify a Transit signature. ``signature`` is the
        ``vault:v<n>:...`` string Transit emits. Returns
        ``{"valid": bool}``."""
        payload = {"input": input_b64, "signature": signature}
        response = self._request(
            "POST",
            f"{self.config.transit_mount}/verify/{key_name}/{hash_algorithm}",
            payload,
        )
        return response.get("data", {})
