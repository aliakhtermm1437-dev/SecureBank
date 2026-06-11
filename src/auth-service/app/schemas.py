from __future__ import annotations

from pydantic import BaseModel, Field, StringConstraints
from typing import Annotated

from securebank_shared.validation import SafeEmail, SafePhoneNumber


Password = Annotated[
    str, StringConstraints(min_length=12, max_length=128, strip_whitespace=False)
]


class RegisterIn(BaseModel):
    email: SafeEmail
    phone: SafePhoneNumber | None = None
    password: Password


class RegisterOut(BaseModel):
    detail: str = "If the email is not already registered, you will receive a verification message."


class LoginIn(BaseModel):
    email: SafeEmail
    password: Password


class LoginOut(BaseModel):
    pre_auth_token: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int | None = None
    mfa_required: bool = False


class MFAVerifyIn(BaseModel):
    pre_auth_token: str
    code: Annotated[str, StringConstraints(pattern=r"^\d{6}$")]


class MFAEnrollOut(BaseModel):
    otpauth_url: str
    qr_png_b64: str
    recovery_codes: list[str] = Field(default_factory=list)


class RefreshIn(BaseModel):
    refresh_token: str


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int


class GenericOK(BaseModel):
    ok: bool = True
