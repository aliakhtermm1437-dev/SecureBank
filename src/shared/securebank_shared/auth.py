"""Authentication primitives.

- Argon2id password hashing (ASVS V2.4.1)
- RS256/ES256 JWT issue & verify with `iss/aud/exp/nbf/iat/jti` checks
- ``JWTClaims`` Pydantic model so downstream code gets typed claims
- All operations constant-time where applicable; user-not-found vs wrong-password
  intentionally return the same shape & latency
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Literal

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from pydantic import BaseModel, Field

_PH = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

# Dummy hash used to keep timing constant when the user doesn't exist (T-AU-5).
_DUMMY_HASH = _PH.hash("this-is-only-here-to-equalise-timing")

JWT_ALG = "RS256"  # ASVS V3.5 — strong, asymmetric, no "alg":"none" allowed.
DEFAULT_ACCESS_TTL = 900    # 15 min
DEFAULT_REFRESH_TTL = 7 * 24 * 3600  # 7 d


class JWTClaims(BaseModel):
    sub: str
    iss: str
    aud: str | list[str]
    exp: int
    nbf: int
    iat: int
    jti: str
    typ: Literal["access", "refresh", "pre-auth"] = "access"
    scope: str = ""
    roles: list[str] = Field(default_factory=list)
    mfa: bool = False
    sid: str | None = None  # session id


def hash_password(plain: str) -> str:
    if len(plain) < 12:
        raise ValueError("password must be ≥12 chars (ASVS V2.1)")
    return _PH.hash(plain)


def verify_password(stored: str | None, supplied: str) -> bool:
    """Constant-time-ish password check that also handles user-not-found by
    comparing against a dummy hash, so attackers cannot distinguish via timing.
    """
    target = stored or _DUMMY_HASH
    try:
        _PH.verify(target, supplied)
    except VerifyMismatchError:
        return False
    except Exception:  # pragma: no cover
        return False
    # If we used the dummy, the user does not exist — still return False.
    return stored is not None


def needs_rehash(stored: str) -> bool:
    return _PH.check_needs_rehash(stored)


def issue_jwt(
    *,
    private_key_pem: bytes,
    subject: str,
    issuer: str,
    audience: str,
    ttl_seconds: int = DEFAULT_ACCESS_TTL,
    typ: Literal["access", "refresh", "pre-auth"] = "access",
    roles: list[str] | None = None,
    scope: str = "",
    mfa: bool = False,
    sid: str | None = None,
    kid: str | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": subject,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
        "typ": typ,
        "roles": roles or [],
        "scope": scope,
        "mfa": mfa,
    }
    if sid:
        payload["sid"] = sid
    if extra:
        payload.update(extra)
    headers: dict[str, Any] = {"alg": JWT_ALG, "typ": "JWT"}
    if kid:
        headers["kid"] = kid
    return jwt.encode(payload, private_key_pem, algorithm=JWT_ALG, headers=headers)


def verify_jwt(
    token: str,
    *,
    public_key_pem: bytes,
    issuer: str,
    audience: str,
    expected_typ: str | None = "access",
) -> JWTClaims:
    """Verify a JWT — RS256 only — and return typed claims.

    Raises :class:`jwt.PyJWTError` (or subclass) on any failure.
    """
    decoded = jwt.decode(
        token,
        public_key_pem,
        algorithms=[JWT_ALG],  # alg allow-list, prevents alg-confusion
        issuer=issuer,
        audience=audience,
        options={
            "require": ["exp", "iat", "nbf", "iss", "aud", "jti", "sub", "typ"],
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_aud": True,
            "verify_iss": True,
        },
    )
    claims = JWTClaims.model_validate(decoded)
    if expected_typ and claims.typ != expected_typ:
        raise jwt.InvalidTokenError(f"unexpected token typ: {claims.typ}")
    return claims
