"""Reverse-proxy API gateway with auth, WAF, rate limiting, and OPA hook."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.responses import JSONResponse, StreamingResponse

from securebank_shared.jwt_dep import JWKSCache
from securebank_shared.logging import configure_logging, get_logger
from securebank_shared.middleware import install_security_middleware

from app.routing import requires_auth, resolve_upstream
from app.settings import settings
from app.waf import scan as waf_scan

_LOG = get_logger("gateway")

limiter = Limiter(
    key_func=lambda r: r.state.auth_user_id or get_remote_address(r),
    default_limits=[f"{settings.anon_rate_per_min}/minute"],
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    configure_logging(level=settings.log_level, json_logs=settings.log_json)
    app.state.http = httpx.AsyncClient(timeout=10.0, verify=True)
    app.state.jwks = JWKSCache(settings.jwks_url)
    app.state.limiter = limiter
    try:
        yield
    finally:
        await app.state.http.aclose()


app = FastAPI(
    title="SecureBank API Gateway",
    version="1.0.0",
    docs_url=None, redoc_url=None,
    openapi_url=None,  # no public OpenAPI from gateway
    lifespan=lifespan,
)

install_security_middleware(
    app,
    service=settings.service_name,
    cors_origins=["https://app.securebank.local"],
    trusted_hosts=["*"],   # public ingress; cert termination upstream
    metrics_path=settings.metrics_path,
)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.exception_handler(RateLimitExceeded)
async def ratelimit_handler(request, exc):  # noqa: ARG001
    return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": settings.service_name}


_STRIP_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
}


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy(request: Request, full_path: str) -> Response:
    request.state.auth_user_id = None
    if request.method not in settings.allowed_methods:
        raise HTTPException(405, "method not allowed")

    path = "/" + full_path
    upstream = resolve_upstream(path)
    if not upstream:
        raise HTTPException(404, "not found")

    # ---- WAF screen (path + query + body sample) --------------------------
    query_values = [v for _, v in request.query_params.multi_items()]
    if (hit := waf_scan([path, *query_values])):
        _LOG.warning("waf.blocked", path=path, hit=hit[:64])
        return JSONResponse({"detail": "blocked"}, status_code=400)

    # ---- AuthN  ----------------------------------------------------------
    headers = {k.decode(): v.decode() for k, v in request.headers.raw
               if k.decode().lower() not in _STRIP_HOP_BY_HOP}
    if requires_auth(path):
        authz = headers.get("authorization", "")
        if not authz.lower().startswith("bearer "):
            raise HTTPException(401, "missing bearer token")
        # Validate locally so we know who the user is for downstream + rate limit.
        import jwt as pyjwt
        token = authz.split(" ", 1)[1].strip()
        try:
            unv = pyjwt.get_unverified_header(token)
            jwk = await app.state.jwks.get(unv["kid"])
            pub = pyjwt.algorithms.RSAAlgorithm.from_jwk(jwk)
            claims = pyjwt.decode(
                token, pub, algorithms=["RS256"],
                issuer=settings.jwt_issuer, audience=settings.jwt_audience,
                options={"require": ["exp","iat","nbf","iss","aud","jti","sub","typ"]},
            )
        except pyjwt.PyJWTError as e:
            _LOG.warning("gateway.jwt.invalid", err=str(e))
            raise HTTPException(401, "invalid token") from e
        request.state.auth_user_id = claims["sub"]
        # Forward identity to downstream so it doesn't have to re-decode.
        headers["x-user-id"] = claims["sub"]
        if "sid" in claims:
            headers["x-session-id"] = claims["sid"]
        headers["x-mfa"] = "true" if claims.get("mfa") else "false"
        headers["x-roles"] = ",".join(claims.get("roles", []))

    # ---- Proxy ------------------------------------------------------------
    body = await request.body()
    target = upstream + path
    try:
        resp = await app.state.http.request(
            request.method, target,
            content=body,
            params=request.query_params,
            headers=headers,
        )
    except httpx.HTTPError as e:
        _LOG.error("gateway.upstream.error", err=str(e), upstream=upstream)
        return JSONResponse({"detail": "upstream unavailable"}, status_code=502)
    # Strip hop-by-hop in response too.
    out = {k: v for k, v in resp.headers.items() if k.lower() not in _STRIP_HOP_BY_HOP}
    return Response(content=resp.content, status_code=resp.status_code, headers=out,
                    media_type=resp.headers.get("content-type"))
