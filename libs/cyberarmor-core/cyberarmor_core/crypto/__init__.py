"""CyberArmor PQC Cryptography Module.

Provides FIPS 140-3 compliant and post-quantum cryptographic primitives
using ML-KEM-1024 (Kyber) for key encapsulation and ML-DSA (Dilithium)
for digital signatures, per CNSA 2.0 requirements.
"""

from .pqc_kem import PQCKEM, KEMKeyPair, KEMCiphertext
from .pqc_sign import PQCSigner, SigningKeyPair
from .key_transport import PQCKeyTransport, EncryptedAPIKey
from .key_rotation import KeyRotationManager
from .auth import (
    ResolvedAPIKey,
    build_auth_headers,
    build_pqc_auth_header,
    get_public_key_info,
    resolve_api_key_header,
    verify_shared_secret,
)

__all__ = [
    "PQCKEM",
    "KEMKeyPair",
    "KEMCiphertext",
    "PQCSigner",
    "SigningKeyPair",
    "PQCKeyTransport",
    "EncryptedAPIKey",
    "KeyRotationManager",
    "ResolvedAPIKey",
    "build_auth_headers",
    "build_pqc_auth_header",
    "get_public_key_info",
    "resolve_api_key_header",
    "verify_shared_secret",
]
