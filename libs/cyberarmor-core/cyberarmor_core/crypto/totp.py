"""TOTP (RFC 6238) + backup-code helpers.

Shared between dashboard-auth (admin sign-in) and control-plane
(tenant-user sign-in). Secrets are encrypted at rest with Fernet; the
KEK is derived from the calling service's session secret via
PBKDF2-HMAC-SHA256 so that rotating the session secret rotates the KEK
(existing sessions already invalidate on that rotation, so this is a
consistent story). The KEK is per-service: a TOTP secret encrypted by
dashboard-auth is NOT decryptable by control-plane and vice versa,
which is intentional — admin users and tenant users are separate
identity domains.
"""
from __future__ import annotations

import base64
import hashlib
import io
import re
import secrets
from typing import List

import pyotp
import qrcode
import qrcode.image.svg
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


_BACKUP_CODE_BYTES = 4  # 8 hex chars => "XXXX-XXXX"


def _derive_key(session_secret: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=120_000)
    return base64.urlsafe_b64encode(kdf.derive(session_secret.encode("utf-8")))


class TOTPCipher:
    """Encrypts TOTP secrets before they touch the DB."""

    def __init__(self, session_secret: str, salt: bytes = b"ca-totp-kek-v1") -> None:
        if not session_secret:
            raise ValueError("session_secret required for TOTP encryption")
        self._fernet = Fernet(_derive_key(session_secret, salt))

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, token: str) -> str:
        return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")


def generate_secret() -> str:
    return pyotp.random_base32()


def otpauth_uri(secret: str, label: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=label, issuer_name=issuer)


def qr_svg(uri: str) -> str:
    """Render the otpauth URI as an inline-HTML-safe SVG string.

    qrcode's default ``SvgImage`` factory emits ``<svg:rect>`` elements with
    namespace prefixes; when the browser parses such markup via ``innerHTML``
    (HTML mode, not XML), it treats those tags as unknown HTML elements and
    silently drops them on the floor — the SVG container is present in the
    DOM but no QR modules render. The ``SvgPathImage`` factory emits a single
    unprefixed ``<path>`` element which renders cleanly.

    We additionally strip the XML prolog (``<?xml …?>``) — which HTML's
    parser treats as a comment/PI and which has been known to break
    sibling-SVG rendering — and rewrite the millimeter dimensions to plain
    pixels. The viewBox is preserved so the QR scales correctly inside the
    fixed-size box.
    """
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(uri, image_factory=factory, box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf)
    svg = buf.getvalue().decode("utf-8")
    if svg.lstrip().startswith("<?xml"):
        svg = svg[svg.index("?>") + 2:].lstrip()
    svg = re.sub(r'\swidth="[^"]+"', ' width="200"', svg, count=1)
    svg = re.sub(r'\sheight="[^"]+"', ' height="200"', svg, count=1)
    return svg


def _normalize_code(code: str) -> str:
    return "".join(ch for ch in (code or "") if ch.isalnum())


def verify_totp(secret: str, code: str) -> bool:
    code = _normalize_code(code)
    if not secret or len(code) != 6 or not code.isdigit():
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def generate_backup_codes(n: int = 10) -> List[str]:
    """Plaintext codes returned to the user ONCE (formatted XXXX-XXXX)."""
    codes = []
    for _ in range(n):
        raw = secrets.token_hex(_BACKUP_CODE_BYTES).upper()
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def hash_backup_code(session_secret: str, code: str) -> str:
    normalized = _normalize_code(code).upper()
    return hashlib.sha256(f"{session_secret}:{normalized}".encode("utf-8")).hexdigest()
