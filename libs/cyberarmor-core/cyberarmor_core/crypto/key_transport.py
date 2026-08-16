"""PQC-Encrypted API Key Transport Protocol.

Encrypts API keys using ML-KEM-1024 encapsulated shared secret + AES-256-GCM.
Wire format: PQC:<base64(kem_ciphertext || iv || aes_ciphertext || aes_tag)>

Server-side: decapsulate KEM ciphertext -> recover shared secret -> decrypt API key
Client-side: encapsulate with server public key -> encrypt API key -> encode for header
"""

from __future__ import annotations

import base64
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .pqc_kem import PQCKEM, KEMKeyPair

PQC_HEADER_PREFIX = "PQC:"
AES_KEY_SIZE = 32  # 256-bit
AES_IV_SIZE = 12   # 96-bit nonce for GCM


@dataclass
class EncryptedAPIKey:
    """Parsed PQC-encrypted API key from transport header."""
    kem_ciphertext: bytes
    aes_iv: bytes
    aes_ciphertext: bytes
    aes_tag: bytes

    def encode(self) -> str:
        """Encode to wire format: PQC:<base64(...)>"""
        kem_ct_len = len(self.kem_ciphertext)
        # Pack: [4-byte kem_ct_len][kem_ciphertext][12-byte iv][aes_ciphertext][16-byte tag]
        payload = (
            struct.pack(">I", kem_ct_len)
            + self.kem_ciphertext
            + self.aes_iv
            + self.aes_ciphertext
            + self.aes_tag
        )
        return PQC_HEADER_PREFIX + base64.b64encode(payload).decode("ascii")

    @classmethod
    def decode(cls, header_value: str) -> "EncryptedAPIKey":
        """Decode from wire format."""
        if not header_value.startswith(PQC_HEADER_PREFIX):
            raise ValueError("Not a PQC-encrypted key (missing prefix)")
        b64_part = header_value[len(PQC_HEADER_PREFIX):]
        raw = base64.b64decode(b64_part)
        if len(raw) < 4 + 12 + 16:
            raise ValueError("Encrypted key payload too short")
        kem_ct_len = struct.unpack(">I", raw[:4])[0]
        offset = 4
        kem_ct = raw[offset:offset + kem_ct_len]
        offset += kem_ct_len
        iv = raw[offset:offset + AES_IV_SIZE]
        offset += AES_IV_SIZE
        # Remaining bytes: aes_ciphertext + 16-byte tag
        aes_ct_and_tag = raw[offset:]
        if len(aes_ct_and_tag) < 16:
            raise ValueError("Missing AES-GCM tag")
        # AESGCM in cryptography lib appends tag to ciphertext
        aes_ciphertext = aes_ct_and_tag[:-16]
        aes_tag = aes_ct_and_tag[-16:]
        return cls(
            kem_ciphertext=kem_ct,
            aes_iv=iv,
            aes_ciphertext=aes_ciphertext,
            aes_tag=aes_tag,
        )


class PQCKeyTransport:
    """Encrypt/decrypt API keys using PQC key encapsulation + AES-256-GCM.

    Server-side usage:
        transport = PQCKeyTransport()
        keypair = transport.kem.generate_keypair()
        # Store keypair.secret_key securely
        # Publish keypair.public_key at /pki/public-key

        # On each request:
        api_key = transport.decrypt_api_key(header_value, keypair.secret_key)

    Client-side usage:
        transport = PQCKeyTransport()
        # Fetch server_public_key from /pki/public-key
        header_value = transport.encrypt_api_key("my-secret-key", server_public_key)
        # Send header: x-api-key: PQC:<base64...>
    """

    def __init__(self):
        self.kem = PQCKEM()

    def encrypt_api_key(self, api_key: str, server_public_key: bytes) -> str:
        """Client-side: encrypt API key for transport."""
        import os
        encap = self.kem.encapsulate(server_public_key)
        shared_secret = encap.shared_secret
        iv = os.urandom(AES_IV_SIZE)
        aesgcm = AESGCM(shared_secret)
        plaintext = api_key.encode("utf-8")
        # AESGCM.encrypt returns ciphertext + tag concatenated
        ct_with_tag = aesgcm.encrypt(iv, plaintext, None)
        aes_ciphertext = ct_with_tag[:-16]
        aes_tag = ct_with_tag[-16:]
        encrypted = EncryptedAPIKey(
            kem_ciphertext=encap.ciphertext,
            aes_iv=iv,
            aes_ciphertext=aes_ciphertext,
            aes_tag=aes_tag,
        )
        return encrypted.encode()

    def decrypt_api_key(self, header_value: str, server_secret_key: bytes) -> str:
        """Server-side: decrypt API key from transport header."""
        encrypted = EncryptedAPIKey.decode(header_value)
        shared_secret = self.kem.decapsulate(
            encrypted.kem_ciphertext, server_secret_key
        )
        aesgcm = AESGCM(shared_secret)
        # Reconstruct ciphertext + tag as AESGCM expects
        ct_with_tag = encrypted.aes_ciphertext + encrypted.aes_tag
        plaintext = aesgcm.decrypt(encrypted.aes_iv, ct_with_tag, None)
        return plaintext.decode("utf-8")

    @staticmethod
    def is_pqc_encrypted(header_value: str) -> bool:
        """Check if a header value uses PQC encryption."""
        return header_value.startswith(PQC_HEADER_PREFIX) if header_value else False
