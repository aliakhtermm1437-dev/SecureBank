from __future__ import annotations

import os
from dataclasses import dataclass

from redis.asyncio import Redis

from securebank_shared.audit import AuditLogger
from securebank_shared.kafka import SecureConsumer

from app.settings import settings


@dataclass
class AppState:
    redis: Redis
    audit: AuditLogger
    consumer_tx: SecureConsumer | None
    consumer_alerts: SecureConsumer | None


async def init_state() -> AppState:
    r = Redis.from_url(settings.redis_url or "redis://redis:6379/4", decode_responses=False)
    hmac_hex = os.getenv("SB_KAFKA_HMAC_HEX")
    hmac_key = bytes.fromhex(hmac_hex) if hmac_hex else b"0" * 32

    consumer_tx = SecureConsumer(
        bootstrap_servers=settings.kafka_bootstrap or "kafka:9093",
        topic=settings.kafka_topic_tx,
        group_id=settings.kafka_group_id + "-tx",
        hmac_key=hmac_key,
    )
    consumer_alerts = SecureConsumer(
        bootstrap_servers=settings.kafka_bootstrap or "kafka:9093",
        topic=settings.kafka_topic_alerts,
        group_id=settings.kafka_group_id + "-alerts",
        hmac_key=hmac_key,
    )
    try:
        await consumer_tx.start()
        await consumer_alerts.start()
    except Exception:
        consumer_tx = None
        consumer_alerts = None
    return AppState(redis=r, audit=AuditLogger("notification-service"),
                    consumer_tx=consumer_tx, consumer_alerts=consumer_alerts)
