"""FastAPI middleware: security headers, request-id, structured access log,
Prometheus metrics, JWT auth dependency, and per-route rate limit hook.
"""
from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, make_asgi_app
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from securebank_shared.logging import get_logger

_LOG = get_logger("http")

REQ_COUNT = Counter(
    "sb_http_requests_total",
    "Total HTTP requests",
    ["service", "method", "path", "status"],
)
REQ_LAT = Histogram(
    "sb_http_request_seconds",
    "HTTP request latency",
    ["service", "method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """ASVS V14.5 — sensible default security headers on every response."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response: Response = await call_next(request)
        response.headers.setdefault("Strict-Transport-Security",
                                    "max-age=63072000; includeSubDomains; preload")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy",
                                    "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'; upgrade-insecure-requests",
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")
        response.headers.setdefault("X-XSS-Protection", "0")
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)
        return response


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Generate / propagate a Request-ID and structured access log."""

    def __init__(self, app: FastAPI, service: str) -> None:
        super().__init__(app)
        self.service = service

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        req_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        start = time.perf_counter()
        request.state.request_id = req_id
        try:
            response = await call_next(request)
        except Exception:
            _LOG.exception("http.unhandled", request_id=req_id, path=request.url.path)
            response = JSONResponse(
                {"detail": "internal_server_error", "request_id": req_id},
                status_code=500,
            )
        duration = time.perf_counter() - start
        path_template = request.scope.get("route").path if request.scope.get("route") else request.url.path
        REQ_COUNT.labels(self.service, request.method, path_template,
                         str(response.status_code)).inc()
        REQ_LAT.labels(self.service, request.method, path_template).observe(duration)
        response.headers["x-request-id"] = req_id
        _LOG.info(
            "http.access",
            request_id=req_id,
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=int(duration * 1000),
            client=request.client.host if request.client else None,
        )
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject bodies larger than ``max_bytes`` early (defense vs. DoS)."""

    def __init__(self, app: FastAPI, max_bytes: int = 256 * 1024) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > self.max_bytes:
            return JSONResponse(
                {"detail": "request body too large"},
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )
        return await call_next(request)


def install_security_middleware(
    app: FastAPI,
    *,
    service: str,
    cors_origins: list[str] | None = None,
    trusted_hosts: list[str] | None = None,
    max_body_bytes: int = 256 * 1024,
    metrics_path: str = "/metrics",
) -> None:
    """One-call installer; order matters — we want context first."""
    app.add_middleware(RequestContextMiddleware, service=service)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=max_body_bytes)
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    if trusted_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-Request-Id"],
            max_age=600,
        )
    app.mount(metrics_path, make_asgi_app())


def require_role(role: str) -> Callable[..., Any]:
    """Dependency factory enforcing role membership on a JWT-protected route."""
    def _checker(request: Request) -> None:
        claims = getattr(request.state, "claims", None)
        if not claims or role not in getattr(claims, "roles", []):
            raise HTTPException(status_code=403, detail="forbidden")
    return _checker
