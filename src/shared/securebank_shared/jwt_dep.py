"""FastAPI dependency: extract & verify a Bearer JWT and attach claims.

Public keys come from a JWKS endpoint (cached). Algorithm allow-list = RS256.
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import jwt
from fastapi import Header, HTTPException, Request, status

from securebank_shared.auth import JWTClaims
from securebank_shared.logging import get_logger

_LOG = get_logger("jwt")


class JWKSCache:
    def __init__(self, url: str, ttl: int = 300) -> None:
        self.url = url
        self.ttl = ttl
        self._exp = 0.0
        self._keys: dict[str, Any] = {}

    async def _refresh(self) -> None:
        async with httpx.AsyncClient(timeout=2.0) as c:
            r = await c.get(self.url)
            r.raise_for_status()
            data = r.json()
        self._keys = {k["kid"]: k for k in data.get("keys", [])}
        self._exp = time.time() + self.ttl
        _LOG.info("jwks.refreshed", n=len(self._keys))

    async def get(self, kid: str) -> Any:
        if time.time() >= self._exp or kid not in self._keys:
            await self._refresh()
        if kid not in self._keys:
            raise KeyError(kid)
        return self._keys[kid]


def jwt_dependency(jwks: JWKSCache, *, issuer: str, audience: str, required_typ: str = "access"):
    async def _dep(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> JWTClaims:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
        token = authorization.split(" ", 1)[1].strip()
        try:
            unv = jwt.get_unverified_header(token)
        except jwt.PyJWTError as e:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "malformed token") from e
        kid = unv.get("kid")
        if not kid:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing kid")
        try:
            jwk = await jwks.get(kid)
        except KeyError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown kid") from None
        try:
            pub = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
        except Exception as e:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad jwk") from e
        try:
            payload = jwt.decode(
                token, pub, algorithms=["RS256"],
                issuer=issuer, audience=audience,
                options={"require": ["exp","iat","nbf","iss","aud","jti","sub","typ"]},
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token expired") from None
        except jwt.PyJWTError as e:
            _LOG.warning("jwt.invalid", err=str(e))
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from e

        claims = JWTClaims.model_validate(payload)
        if claims.typ != required_typ:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "wrong token type")
        request.state.claims = claims
        return claims
    return _dep
