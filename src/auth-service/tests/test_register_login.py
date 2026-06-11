"""Smoke tests — exercise the auth service in-process via FastAPI TestClient.

These tests validate the auth service startup path and health endpoint using
an in-memory SQLite backend and a stubbed Redis engine.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from app import main


@dataclass
class DummyDatabase:
    async def dispose(self) -> None:
        return None


@dataclass
class DummyRedis:
    async def close(self) -> None:
        return None


@dataclass
class DummyState:
    engine: DummyDatabase = DummyDatabase()
    redis: DummyRedis = DummyRedis()
    session_factory: object = object()
    keyring: object = object()
    sessions: object = object()
    refresh_tokens: object = object()
    audit: object = object()


async def fake_init_state() -> DummyState:
    return DummyState()


def test_health_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify the auth service health endpoint starts and responds."""
    monkeypatch.setattr(main, "init_state", fake_init_state)

    with TestClient(main.app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "service": "auth-service"}


@pytest.mark.skip(reason="full auth integration tests require postgres + redis; covered in CI integration job")
def test_register_then_login() -> None:
    from app.main import app

    with TestClient(app) as c:
        r = c.post("/v1/auth/register", json={
            "email": "demo@securebank.local",
            "password": "Change-Me-On-First-Login!",
        })
        assert r.status_code == 202

        r = c.post("/v1/auth/login", json={
            "email": "demo@securebank.local",
            "password": "Change-Me-On-First-Login!",
        })
        assert r.status_code == 200
        body = r.json()
        assert body["access_token"]
        assert body["refresh_token"]
