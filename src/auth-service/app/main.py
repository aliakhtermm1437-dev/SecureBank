from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.responses import JSONResponse

from securebank_shared.logging import configure_logging, get_logger
from securebank_shared.middleware import install_security_middleware

from app.routes_auth import limiter, router as auth_router
from app.settings import settings
from app.state import init_state

_LOG = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    configure_logging(level=settings.log_level, json_logs=settings.log_json)
    state = await init_state()
    app.state.svc = state
    app.state.limiter = limiter
    _LOG.info("startup.complete", service=settings.service_name)
    try:
        yield
    finally:
        await state.redis.close()
        await state.engine.dispose()


app = FastAPI(
    title="SecureBank Auth Service",
    version="1.0.0",
    docs_url=None,  # disabled in prod (gateway can expose docs in dev)
    redoc_url=None,
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

install_security_middleware(
    app,
    service=settings.service_name,
    cors_origins=settings.cors_origins,
    trusted_hosts=settings.trusted_hosts,
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


@app.get("/ready")
async def ready() -> dict:
    return {"ready": True}


app.include_router(auth_router)
