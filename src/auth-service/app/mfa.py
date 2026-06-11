"""TOTP-based MFA. ASVS V2.7."""
from __future__ import annotations

import base64
import io
from dataclasses import dataclass

import pyotp
import qrcode


@dataclass(slots=True)
class TOTPEnrollment:
    secret_b32: str
    otpauth_url: str
    qr_png_b64: str


def new_enrollment(account: str, issuer: str = "SecureBank") -> TOTPEnrollment:
    secret = pyotp.random_base32()
    url = pyotp.totp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer)
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return TOTPEnrollment(
        secret_b32=secret,
        otpauth_url=url,
        qr_png_b64=base64.b64encode(buf.getvalue()).decode(),
    )


def verify(secret_b32: str, code: str) -> bool:
    if not code.isdigit() or len(code) != 6:
        return False
    return pyotp.TOTP(secret_b32).verify(code, valid_window=1)
