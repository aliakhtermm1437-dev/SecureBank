from __future__ import annotations

import os
from dataclasses import dataclass

from redis.asyncio import Redis

from securebank_shared.audit import AuditLogger
from securebank_shared.kafka import SecureConsumer, SecureProducer

from app.model import FraudModel
from app.settings import settings


@dataclass
class AppState:
    redis: Redis
    audit: AuditLogger
    model: FraudModel
    consumer: SecureConsumer | None
    producer: SecureProducer | None


async def init_state() -> AppState:
    redis_url = settings.redis_url or "redis://redis:6379/3"
    r = Redis.from_url(redis_url, decode_responses=False)

    model = FraudModel.load_or_bootstrap(settings.model_path)

    hmac_hex = os.getenv("SB_KAFKA_HMAC_HEX")
    hmac_key = bytes.fromhex(hmac_hex) if hmac_hex else b"0" * 32

    consumer = SecureConsumer(
        bootstrap_servers=settings.kafka_bootstrap or "kafka:9093",
        topic=settings.kafka_topic_in,
        group_id=settings.kafka_group_id,
        hmac_key=hmac_key,
    )
    producer = SecureProducer(
        bootstrap_servers=settings.kafka_bootstrap or "kafka:9093",
        issuer=settings.service_name,
        hmac_key=hmac_key,
    )
    try:
        await consumer.start()
        await producer.start()
    except Exception:
        consumer = None
        producer = None

    return AppState(
        redis=r,
        audit=AuditLogger("fraud-detection-service"),
        model=model,
        consumer=consumer,
        producer=producer,
    )
