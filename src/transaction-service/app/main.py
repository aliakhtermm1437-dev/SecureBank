from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from securebank_shared.logging import configure_logging, get_logger
from securebank_shared.middleware import install_security_middleware

from app.routes_transfers import router as tx_router
from app.settings import settings
from app.state import init_state, jwt_dep_factory

_LOG = get_logger("tx.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    configure_logging(level=settings.log_level, json_logs=settings.log_json)
    state = await init_state()
    app.state.svc = state
    app.state.jwt_dep = jwt_dep_factory(state)
    _LOG.info("startup.complete")
    try:
        yield
    finally:
        if state.producer:
            await state.producer.stop()
        await state.redis.close()
        await state.opa.close()
        await state.account_client.aclose()
        await state.engine.dispose()


app = FastAPI(
    title="SecureBank Transaction Service",
    version="1.0.0",
    docs_url=None, redoc_url=None,
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

install_security_middleware(app, service=settings.service_name,
                            cors_origins=["https://app.securebank.local"],
                            metrics_path=settings.metrics_path)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": settings.service_name}


@app.get("/ready")
async def ready() -> dict:
    return {"ready": True}


app.include_router(tx_router)
