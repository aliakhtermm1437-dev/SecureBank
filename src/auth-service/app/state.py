"""App-wide singletons (DB, Redis, keyring, session store, audit). Initialised
in :pyfunc:`app.main.lifespan` and reused by every route via dependencies.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, AsyncSession

from securebank_shared.audit import AuditLogger
from securebank_shared.crypto import gen_key_aes256
from securebank_shared.db import make_async_engine, make_session_factory
from securebank_shared.sessions import RefreshTokenStore, SessionStore

from app.keys import KeyRing, keyring_from_env
from app.settings import settings


@dataclass
class AppState:
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    redis: Redis
    keyring: KeyRing
    sessions: SessionStore
    refresh_tokens: RefreshTokenStore
    audit: AuditLogger


async def init_state() -> AppState:
    dsn = settings.postgres_dsn or os.getenv("SB_POSTGRES_DSN") or \
        "postgresql+asyncpg://auth:auth@postgres:5432/auth"
    engine = make_async_engine(dsn)
    sf = make_session_factory(engine)

    redis_url = settings.redis_url or "redis://redis:6379/0"
    r = Redis.from_url(redis_url, decode_responses=False, ssl=False)  # ssl wrapped by sidecar in k8s

    ring = keyring_from_env()

    # In production the session encryption key comes from Vault Transit.
    sess_key_hex = os.getenv("SB_SESSION_KEY_HEX")
    sess_key = bytes.fromhex(sess_key_hex) if sess_key_hex else gen_key_aes256()
    sessions = SessionStore(r, key_for_data=sess_key)
    refresh = RefreshTokenStore(r)

    audit = AuditLogger(service_name="auth-service")

    return AppState(
        engine=engine,
        session_factory=sf,
        redis=r,
        keyring=ring,
        sessions=sessions,
        refresh_tokens=refresh,
        audit=audit,
    )
