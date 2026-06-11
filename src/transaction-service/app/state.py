from __future__ import annotations

import os
from dataclasses import dataclass

import httpx
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from securebank_shared.audit import AuditLogger
from securebank_shared.db import make_async_engine, make_session_factory
from securebank_shared.jwt_dep import JWKSCache, jwt_dependency
from securebank_shared.kafka import SecureProducer
from securebank_shared.opa import OPAClient

from app.settings import settings


@dataclass
class AppState:
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    redis: Redis
    audit: AuditLogger
    opa: OPAClient
    producer: SecureProducer | None
    account_client: httpx.AsyncClient
    jwks: JWKSCache


async def init_state() -> AppState:
    dsn = settings.postgres_dsn or os.getenv("SB_POSTGRES_DSN") or \
        "postgresql+asyncpg://tx:tx@postgres:5432/tx"
    engine = make_async_engine(dsn)
    sf = make_session_factory(engine)

    redis_url = settings.redis_url or "redis://redis:6379/2"
    r = Redis.from_url(redis_url, decode_responses=False)

    hmac_hex = os.getenv("SB_KAFKA_HMAC_HEX")
    hmac_key = bytes.fromhex(hmac_hex) if hmac_hex else b"0" * 32
    bootstrap = settings.kafka_bootstrap or "kafka:9093"
    producer = SecureProducer(
        bootstrap_servers=bootstrap,
        issuer=settings.service_name,
        hmac_key=hmac_key,
        sasl_username=settings.kafka_sasl_user,
        sasl_password=settings.kafka_sasl_pass,
        ca=settings.kafka_ca, cert=settings.kafka_cert, key=settings.kafka_key,
    )
    try:
        await producer.start()
    except Exception:
        # Don't crash on startup if Kafka isn't ready in dev; consumers retry.
        producer = None

    return AppState(
        engine=engine,
        session_factory=sf,
        redis=r,
        audit=AuditLogger("transaction-service"),
        opa=OPAClient(os.getenv("SB_OPA_URL", "http://localhost:8181")),
        producer=producer,
        account_client=httpx.AsyncClient(base_url=settings.account_service_url, timeout=2.0),
        jwks=JWKSCache(settings.jwks_url),
    )


def jwt_dep_factory(state: AppState):
    return jwt_dependency(state.jwks, issuer=settings.jwt_issuer, audience=settings.jwt_audience)
