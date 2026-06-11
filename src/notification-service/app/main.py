from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from securebank_shared.logging import configure_logging, get_logger
from securebank_shared.middleware import install_security_middleware

from app.routes import router
from app.settings import settings
from app.state import init_state
from app.worker import run

_LOG = get_logger("notification.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    configure_logging(level=settings.log_level, json_logs=settings.log_json)
    state = await init_state()
    app.state.svc = state
    task = asyncio.create_task(run(state))
    try:
        yield
    finally:
        task.cancel()
        if state.consumer_tx:
            await state.consumer_tx.stop()
        if state.consumer_alerts:
            await state.consumer_alerts.stop()
        await state.redis.close()


app = FastAPI(
    title="SecureBank Notifications",
    version="1.0.0",
    docs_url=None, redoc_url=None,
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

install_security_middleware(app, service=settings.service_name,
                            metrics_path=settings.metrics_path)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": settings.service_name}


@app.get("/ready")
async def ready() -> dict:
    return {"ready": True}


app.include_router(router)
