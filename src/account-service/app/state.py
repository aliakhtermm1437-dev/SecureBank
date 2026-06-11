from __future__ import annotations

import os
from dataclasses import dataclass

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from securebank_shared.audit import AuditLogger
from securebank_shared.crypto import gen_key_aes256
from securebank_shared.db import make_async_engine, make_session_factory
from securebank_shared.jwt_dep import JWKSCache, jwt_dependency
from securebank_shared.opa import OPAClient

from app.settings import settings


@dataclass
class AppState:
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    redis: Redis
    audit: AuditLogger
    opa: OPAClient
    field_enc_key: bytes
    jwks: JWKSCache


async def init_state() -> AppState:
    dsn = settings.postgres_dsn or os.getenv("SB_POSTGRES_DSN") or \
        "postgresql+asyncpg://account:account@postgres:5432/account"
    engine = make_async_engine(dsn)
    sf = make_session_factory(engine)

    redis_url = settings.redis_url or "redis://redis:6379/1"
    r = Redis.from_url(redis_url, decode_responses=False)

    # Field encryption key: from Vault in prod; here a per-pod ephemeral for dev.
    fek_hex = os.getenv("SB_FIELD_ENC_KEY_HEX")
    fek = bytes.fromhex(fek_hex) if fek_hex else gen_key_aes256()

    return AppState(
        engine=engine,
        session_factory=sf,
        redis=r,
        audit=AuditLogger("account-service"),
        opa=OPAClient(os.getenv("SB_OPA_URL", "http://localhost:8181")),
        field_enc_key=fek,
        jwks=JWKSCache(settings.jwks_url),
    )


def jwt_dep_factory(state: AppState):
    return jwt_dependency(state.jwks, issuer=settings.jwt_issuer, audience=settings.jwt_audience)
