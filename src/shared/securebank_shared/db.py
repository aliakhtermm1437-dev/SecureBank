"""Async PostgreSQL helpers using SQLAlchemy 2.0.

The DSN is constructed from non-secret env vars + a dynamically-fetched
password from Vault. Connection pool is bounded to prevent neighbour
exhaustion.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def make_async_engine(dsn: str, *, echo: bool = False) -> AsyncEngine:
    return create_async_engine(
        dsn,
        echo=echo,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        pool_recycle=1800,
        connect_args={"server_settings": {"application_name": "securebank"}},
    )


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


@asynccontextmanager
async def transactional(session_factory: async_sessionmaker[AsyncSession]) -> AsyncIterator[AsyncSession]:
    async with session_factory() as s:
        async with s.begin():
            yield s


def build_dsn(host: str, port: int, db: str, user: str, password: str, sslmode: str = "require") -> str:
    from urllib.parse import quote_plus
    return (
        f"postgresql+asyncpg://{quote_plus(user)}:{quote_plus(password)}"
        f"@{host}:{port}/{db}?ssl={sslmode}"
    )


def safe_log_dsn(dsn: str) -> str:
    """Strip credentials before logging a DSN."""
    import re
    return re.sub(r"//[^/]+@", "//***:***@", dsn)


async def healthcheck(engine: AsyncEngine) -> bool:
    try:
        async with engine.connect() as c:
            await c.execute_text("SELECT 1") if hasattr(c, "execute_text") else None
            await c.exec_driver_sql("SELECT 1")
        return True
    except Exception:
        return False


def safe_in_clause(values: list[Any]) -> str:
    """Helper for places where we MUST inline values — we don't; this raises to
    discourage building raw SQL. Always use bind parameters instead.
    """
    raise RuntimeError(
        "Do not inline values into SQL. Use parameterized queries (asyncpg/SQLAlchemy)."
    )
