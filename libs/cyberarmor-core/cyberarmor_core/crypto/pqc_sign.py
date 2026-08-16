"""ML-DSA (Dilithium) Digital Signature wrapper.

Provides post-quantum digital signatures for JWT tokens, policy signing,
and software integrity verification. Targets CNSA 2.0 / FIPS 204 compliance.

Falls back to Ed25519 when liboqs is not available.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Optional

_HAS_OQS = False
try:
    import oqs  # type: ignore
    _HAS_OQS = True
except ImportError:
    pass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


SIGN_ALGORITHM = "ML-DSA-87"  # FIPS 204 / Dilithium5
FALLBACK_SIGN_ALGORITHM = "Ed25519"


@dataclass
class SigningKeyPair:
    """Digital signing keypair."""
    algorithm: str
    public_key: bytes
    secret_key: bytes
    key_id: str = field(default_factory=lambda: secrets.token_hex(16))

    def public_key_hex(self) -> str:
        return self.public_key.hex()

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "public_key": self.public_key.hex(),
            "key_id": self.key_id,
        }


class PQCSigner:
    """ML-DSA (Dilithium) digital signature provider.

    Usage:
        signer = PQCSigner()
        keypair = signer.generate_keypair()
        signature = signer.sign(b"message", keypair.secret_key)
        valid = signer.verify(b"message", signature, keypair.public_key)
    """

    def __init__(self, algorithm: str = SIGN_ALGORITHM):
        self.algorithm = algorithm
        self._use_oqs = _HAS_OQS and algorithm == SIGN_ALGORITHM

    def generate_keypair(self) -> SigningKeyPair:
        if self._use_oqs:
            return self._oqs_keygen()
        return self._fallback_keygen()

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        if self._use_oqs:
            return self._oqs_sign(message, secret_key)
        return self._fallback_sign(message, secret_key)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        if self._use_oqs:
            return self._oqs_verify(message, signature, public_key)
        return self._fallback_verify(message, signature, public_key)

    # --- Native ML-DSA via liboqs ---

    def _oqs_keygen(self) -> SigningKeyPair:
        with oqs.Signature("ML-DSA-87") as sig:
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()
            return SigningKeyPair(
                algorithm=SIGN_ALGORITHM,
                public_key=public_key,
                secret_key=secret_key,
            )

    def _oqs_sign(self, message: bytes, secret_key: bytes) -> bytes:
        with oqs.Signature("ML-DSA-87", secret_key=secret_key) as sig:
            return sig.sign(message)

    def _oqs_verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        with oqs.Signature("ML-DSA-87") as sig:
            return sig.verify(message, signature, public_key)

    # --- Fallback: Ed25519 ---

    def _fallback_keygen(self) -> SigningKeyPair:
        private_key = Ed25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        secret_key_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return SigningKeyPair(
            algorithm=FALLBACK_SIGN_ALGORITHM,
            public_key=public_key_bytes,
            secret_key=secret_key_bytes,
        )

    def _fallback_sign(self, message: bytes, secret_key: bytes) -> bytes:
        private_key = Ed25519PrivateKey.from_private_bytes(secret_key)
        return private_key.sign(message)

    def _fallback_verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        try:
            pub = Ed25519PublicKey.from_public_bytes(public_key)
            pub.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def is_native_pqc_available() -> bool:
        return _HAS_OQS
