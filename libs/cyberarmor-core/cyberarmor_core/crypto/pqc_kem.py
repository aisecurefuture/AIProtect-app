"""ML-KEM-1024 (Kyber) Key Encapsulation Mechanism wrapper.

Provides post-quantum key encapsulation for API key transport and session
key agreement. Targets CNSA 2.0 / FIPS 203 compliance.

When the oqs (liboqs) library is available, uses native ML-KEM-1024.
Falls back to a hybrid X25519 + AES-256 scheme when liboqs is not installed.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass, field
from typing import Optional, Tuple

# Try to import liboqs for native PQC support
_HAS_OQS = False
try:
    import oqs  # type: ignore
    _HAS_OQS = True
except ImportError:
    pass

# Fallback: use cryptography library for hybrid mode
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


KEM_ALGORITHM = "ML-KEM-1024"  # FIPS 203 / Kyber-1024
FALLBACK_ALGORITHM = "X25519-HKDF-SHA256"  # Classical fallback


@dataclass
class KEMKeyPair:
    """Post-quantum KEM keypair."""
    algorithm: str
    public_key: bytes
    secret_key: bytes  # Private key material - protect accordingly
    key_id: str = field(default_factory=lambda: secrets.token_hex(16))

    def public_key_hex(self) -> str:
        return self.public_key.hex()

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "public_key": self.public_key.hex(),
            "key_id": self.key_id,
        }


@dataclass
class KEMCiphertext:
    """Encapsulated ciphertext + shared secret."""
    ciphertext: bytes
    shared_secret: bytes  # 32 bytes for AES-256


class PQCKEM:
    """ML-KEM-1024 Key Encapsulation Mechanism.

    Usage:
        kem = PQCKEM()
        keypair = kem.generate_keypair()
        ct = kem.encapsulate(keypair.public_key)  # client-side
        ss = kem.decapsulate(ct.ciphertext, keypair.secret_key)  # server-side
        assert ct.shared_secret == ss  # both sides have same 32-byte secret
    """

    def __init__(self, algorithm: str = KEM_ALGORITHM):
        self.algorithm = algorithm
        self._use_oqs = _HAS_OQS and algorithm == KEM_ALGORITHM

    def generate_keypair(self) -> KEMKeyPair:
        """Generate a new KEM keypair."""
        if self._use_oqs:
            return self._oqs_keygen()
        return self._fallback_keygen()

    def encapsulate(self, public_key: bytes) -> KEMCiphertext:
        """Encapsulate: produce ciphertext + shared secret from public key."""
        if self._use_oqs:
            return self._oqs_encaps(public_key)
        return self._fallback_encaps(public_key)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate: recover shared secret from ciphertext + secret key."""
        if self._use_oqs:
            return self._oqs_decaps(ciphertext, secret_key)
        return self._fallback_decaps(ciphertext, secret_key)

    # --- Native ML-KEM-1024 via liboqs ---

    def _oqs_keygen(self) -> KEMKeyPair:
        with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            return KEMKeyPair(
                algorithm=KEM_ALGORITHM,
                public_key=public_key,
                secret_key=secret_key,
            )

    def _oqs_encaps(self, public_key: bytes) -> KEMCiphertext:
        with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
            return KEMCiphertext(
                ciphertext=ciphertext,
                shared_secret=shared_secret[:32],
            )

    def _oqs_decaps(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        with oqs.KeyEncapsulation("ML-KEM-1024", secret_key=secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
            return shared_secret[:32]

    # --- Fallback: X25519 + HKDF (classical, for environments without liboqs) ---

    def _fallback_keygen(self) -> KEMKeyPair:
        private_key = X25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        secret_key_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return KEMKeyPair(
            algorithm=FALLBACK_ALGORITHM,
            public_key=public_key_bytes,
            secret_key=secret_key_bytes,
        )

    def _fallback_encaps(self, public_key: bytes) -> KEMCiphertext:
        ephemeral = X25519PrivateKey.generate()
        ephemeral_pub = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        peer_pub = X25519PublicKey.from_public_bytes(public_key)
        raw_shared = ephemeral.exchange(peer_pub)
        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"cyberarmor-kem-v1",
        ).derive(raw_shared)
        return KEMCiphertext(
            ciphertext=ephemeral_pub,  # 32 bytes
            shared_secret=shared_secret,
        )

    def _fallback_decaps(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        private_key = X25519PrivateKey.from_private_bytes(secret_key)
        peer_pub = X25519PublicKey.from_public_bytes(ciphertext)
        raw_shared = private_key.exchange(peer_pub)
        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"cyberarmor-kem-v1",
        ).derive(raw_shared)
        return shared_secret

    @staticmethod
    def is_native_pqc_available() -> bool:
        """Check if native ML-KEM-1024 support is available."""
        return _HAS_OQS
