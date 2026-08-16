"""Automated Key Rotation Manager.

Manages the lifecycle of PQC keypairs: generation, rotation, and graceful
transition. Supports configurable rotation intervals and maintains a short
history of previous keypairs for in-flight request decryption.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
import urllib.error
import urllib.parse
import urllib.request

from .pqc_kem import PQCKEM, KEMKeyPair
from .pqc_sign import PQCSigner, SigningKeyPair


@dataclass
class KeyRecord:
    """A timestamped key record for rotation tracking."""
    key_id: str
    created_at: float
    expires_at: float
    active: bool = True
    kem_public_key_hex: str = ""
    kem_secret_key_hex: str = ""
    sign_public_key_hex: str = ""
    sign_secret_key_hex: str = ""

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "active": self.active,
            "kem_public_key_hex": self.kem_public_key_hex,
            "sign_public_key_hex": self.sign_public_key_hex,
        }


class KeyRotationManager:
    """Manages PQC keypair rotation lifecycle.

    Features:
    - Generates new KEM and signing keypairs
    - Rotates keys based on configurable interval (default: 24 hours)
    - Maintains previous keypair for graceful transition
    - Persists key state to filesystem (encrypted at rest via OS keychain in production)
    - Provides current and previous public keys for client discovery

    Usage:
        manager = KeyRotationManager(rotation_interval_s=86400)
        manager.initialize()

        # Get current keys for /pki/public-key endpoint
        current = manager.current_kem_keypair()

        # Check if rotation is needed (call periodically)
        if manager.needs_rotation():
            manager.rotate()

        # Decrypt using current or previous key
        secret_key = manager.get_kem_secret_key(key_id)
    """

    def __init__(
        self,
        service_name: str = "unknown",
        rotation_interval_s: int = 86400,  # 24 hours
        key_store_path: str = "./data/keys",
        max_previous_keys: int = 2,
    ):
        self.service_name = service_name
        self.rotation_interval_s = rotation_interval_s
        self.key_store_path = Path(key_store_path)
        self.max_previous_keys = max_previous_keys
        self.kem = PQCKEM()
        self.signer = PQCSigner()
        self._current: Optional[KeyRecord] = None
        self._previous: List[KeyRecord] = []
        self._kem_keypairs: Dict[str, KEMKeyPair] = {}
        self._sign_keypairs: Dict[str, SigningKeyPair] = {}
        self._backend = self._resolve_backend()

    def _service_env_prefix(self) -> str:
        return "".join(ch if ch.isalnum() else "_" for ch in self.service_name.upper())

    def _resolve_backend(self) -> str:
        prefix = self._service_env_prefix()
        return (
            os.getenv(f"{prefix}_PQC_BACKEND")
            or os.getenv("CYBERARMOR_PQC_BACKEND")
            or "filesystem"
        ).strip().lower()

    def initialize(self) -> None:
        """Initialize key store. Load existing or generate new keys."""
        if self._backend == "secrets-service":
            self._load_state_from_secrets_service()
        else:
            self.key_store_path.mkdir(parents=True, exist_ok=True)
            state_file = self.key_store_path / "key_state.json"
            if state_file.exists():
                self._load_state(state_file)
        if not self._current or self._current.is_expired():
            self.rotate()

    def rotate(self) -> KeyRecord:
        """Generate new keypairs and rotate the current key."""
        # Move current to previous
        if self._current:
            self._current.active = False
            self._previous.insert(0, self._current)
            # Trim previous keys
            self._previous = self._previous[: self.max_previous_keys]

        # Generate new keypairs
        kem_kp = self.kem.generate_keypair()
        sign_kp = self.signer.generate_keypair()
        now = time.time()

        record = KeyRecord(
            key_id=kem_kp.key_id,
            created_at=now,
            expires_at=now + self.rotation_interval_s,
            active=True,
            kem_public_key_hex=kem_kp.public_key.hex(),
            kem_secret_key_hex=kem_kp.secret_key.hex(),
            sign_public_key_hex=sign_kp.public_key.hex(),
            sign_secret_key_hex=sign_kp.secret_key.hex(),
        )

        self._current = record
        self._kem_keypairs[kem_kp.key_id] = kem_kp
        self._sign_keypairs[sign_kp.key_id] = sign_kp

        self._save_state()
        return record

    def needs_rotation(self) -> bool:
        """Check if the current key needs rotation."""
        if not self._current:
            return True
        return self._current.is_expired()

    def current_kem_keypair(self) -> Optional[KEMKeyPair]:
        """Get the current active KEM keypair."""
        if not self._current:
            return None
        return self._kem_keypairs.get(self._current.key_id)

    def current_sign_keypair(self) -> Optional[SigningKeyPair]:
        """Get the current active signing keypair."""
        if not self._current:
            return None
        return self._sign_keypairs.get(self._current.key_id)

    def get_kem_secret_key(self, key_id: str) -> Optional[bytes]:
        """Get KEM secret key by key_id (current or previous)."""
        kp = self._kem_keypairs.get(key_id)
        if kp:
            return kp.secret_key
        # Check records for previous keys loaded from disk
        for record in [self._current] + self._previous:
            if record and record.key_id == key_id and record.kem_secret_key_hex:
                return bytes.fromhex(record.kem_secret_key_hex)
        return None

    def get_public_key_info(self) -> dict:
        """Get public key info for the /pki/public-key endpoint."""
        if not self._current:
            return {"error": "No keys initialized"}
        return {
            "key_id": self._current.key_id,
            "algorithm": self.kem.algorithm,
            "kem_public_key": self._current.kem_public_key_hex,
            "sign_algorithm": self.signer.algorithm,
            "sign_public_key": self._current.sign_public_key_hex,
            "expires_at": self._current.expires_at,
            "native_pqc": PQCKEM.is_native_pqc_available(),
        }

    def list_all_key_ids(self) -> List[str]:
        """List all known key IDs (current + previous)."""
        ids = []
        if self._current:
            ids.append(self._current.key_id)
        for prev in self._previous:
            ids.append(prev.key_id)
        return ids

    def revoke_key(self, key_id: str) -> bool:
        """Revoke a key by ID."""
        if self._current and self._current.key_id == key_id:
            self._current.active = False
            self.rotate()
            self._save_state()
            return True
        for prev in self._previous:
            if prev.key_id == key_id:
                prev.active = False
                self._kem_keypairs.pop(key_id, None)
                self._sign_keypairs.pop(key_id, None)
                self._save_state()
                return True
        return False

    def _save_state(self) -> None:
        """Persist key state to disk."""
        if self._backend == "secrets-service":
            self._save_state_to_secrets_service()
            return
        state_file = self.key_store_path / "key_state.json"
        state = {
            "current": self._record_to_dict(self._current) if self._current else None,
            "previous": [self._record_to_dict(r) for r in self._previous],
        }
        state_file.write_text(json.dumps(state, indent=2))
        # Restrict permissions
        try:
            os.chmod(state_file, 0o600)
        except OSError:
            pass

    def _load_state(self, state_file: Path) -> None:
        """Load key state from disk."""
        try:
            state = json.loads(state_file.read_text())
            self._restore_from_state_dict(state)
        except Exception:
            # Corrupt state file; will regenerate
            self._current = None
            self._previous = []

    def _record_to_dict(self, record: KeyRecord) -> dict:
        return {
            "key_id": record.key_id,
            "created_at": record.created_at,
            "expires_at": record.expires_at,
            "active": record.active,
            "kem_public_key_hex": record.kem_public_key_hex,
            "kem_secret_key_hex": record.kem_secret_key_hex,
            "sign_public_key_hex": record.sign_public_key_hex,
            "sign_secret_key_hex": record.sign_secret_key_hex,
        }

    def _dict_to_record(self, d: dict) -> KeyRecord:
        return KeyRecord(
            key_id=d["key_id"],
            created_at=d["created_at"],
            expires_at=d["expires_at"],
            active=d.get("active", True),
            kem_public_key_hex=d.get("kem_public_key_hex", ""),
            kem_secret_key_hex=d.get("kem_secret_key_hex", ""),
            sign_public_key_hex=d.get("sign_public_key_hex", ""),
            sign_secret_key_hex=d.get("sign_secret_key_hex", ""),
        )

    def _rebuild_keypair(self, record: KeyRecord) -> None:
        """Rebuild in-memory keypair objects from hex strings."""
        if record.kem_public_key_hex and record.kem_secret_key_hex:
            kp = KEMKeyPair(
                algorithm=self.kem.algorithm,
                public_key=bytes.fromhex(record.kem_public_key_hex),
                secret_key=bytes.fromhex(record.kem_secret_key_hex),
                key_id=record.key_id,
            )
            self._kem_keypairs[record.key_id] = kp
        if record.sign_public_key_hex and record.sign_secret_key_hex:
            skp = SigningKeyPair(
                algorithm=self.signer.algorithm,
                public_key=bytes.fromhex(record.sign_public_key_hex),
                secret_key=bytes.fromhex(record.sign_secret_key_hex),
                key_id=record.key_id,
            )
            self._sign_keypairs[record.key_id] = skp

    def _state_dict(self) -> dict:
        return {
            "current": self._record_to_dict(self._current) if self._current else None,
            "previous": [self._record_to_dict(r) for r in self._previous],
        }

    def _restore_from_state_dict(self, state: dict) -> None:
        self._current = None
        self._previous = []
        self._kem_keypairs = {}
        self._sign_keypairs = {}
        if state.get("current"):
            self._current = self._dict_to_record(state["current"])
            self._rebuild_keypair(self._current)
        for prev_dict in state.get("previous", []):
            record = self._dict_to_record(prev_dict)
            self._previous.append(record)
            self._rebuild_keypair(record)

    def _secrets_service_url(self) -> Optional[str]:
        return os.getenv("SECRETS_SERVICE_URL")

    def _secrets_service_api_secret(self) -> Optional[str]:
        return os.getenv("SECRETS_SERVICE_API_SECRET")

    def _secrets_service_request(self, method: str, payload: Optional[dict] = None) -> dict:
        base_url = (self._secrets_service_url() or "").strip()
        api_secret = self._secrets_service_api_secret()
        if not base_url or not api_secret:
            raise RuntimeError("Secrets service configuration is missing for PQC key backend")
        url = urllib.parse.urljoin(
            f"{base_url.rstrip('/')}/",
            f"v1/keys/pqc/{self.service_name}/state",
        )
        body = None
        headers = {
            "Accept": "application/json",
            "x-api-key": api_secret,
        }
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=5.0) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Secrets service {method} failed with {exc.code}: {body_text}") from exc
        except Exception as exc:
            raise RuntimeError(f"Secrets service {method} failed: {exc}") from exc

    def _load_state_from_secrets_service(self) -> None:
        try:
            payload = self._secrets_service_request("GET")
            self._restore_from_state_dict(payload.get("state") or {})
        except Exception:
            self._current = None
            self._previous = []
            self._kem_keypairs = {}
            self._sign_keypairs = {}

    def _save_state_to_secrets_service(self) -> None:
        payload = {
            "service_name": self.service_name,
            "state": self._state_dict(),
        }
        self._secrets_service_request("POST", payload)
