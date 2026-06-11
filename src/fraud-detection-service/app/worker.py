"""Long-running Kafka consumer loop.

For each transaction event:
  1. Pull velocity features from Redis (sliding windows).
  2. Score with FraudModel.
  3. If score ≥ threshold, publish a fraud alert event.
  4. Update sliding windows.
"""
from __future__ import annotations

import asyncio
import statistics
from datetime import datetime, timezone
from typing import Any

from securebank_shared.logging import get_logger

_LOG = get_logger("fraud.worker")


async def handle(state: Any, data: dict) -> None:
    tx_id = data["tx_id"]
    user_id = data["initiator_user_id"]
    amount = float(data["amount"])
    src = data["src_account_id"]
    dst = data["dst_account_id"]
    ts = datetime.now(timezone.utc)

    # Velocity windows in Redis (sorted sets keyed by user/account).
    now_ts = int(ts.timestamp())
    one_hour = now_ts - 3600
    one_day = now_ts - 86400
    key_v = f"sb:velocity:{user_id}"
    await state.redis.zadd(key_v, {tx_id: now_ts})
    await state.redis.zremrangebyscore(key_v, 0, one_day)
    velocity_1h = await state.redis.zcount(key_v, one_hour, now_ts)
    velocity_24h = await state.redis.zcount(key_v, one_day, now_ts)

    key_amts = f"sb:amounts:{user_id}"
    await state.redis.lpush(key_amts, amount)
    await state.redis.ltrim(key_amts, 0, 100)
    amts = [float(x) for x in await state.redis.lrange(key_amts, 0, -1)]
    if len(amts) >= 5:
        mean = statistics.mean(amts)
        stdev = statistics.pstdev(amts) or 1.0
        z = (amount - mean) / stdev
    else:
        z = 0.0

    # New-destination feature.
    seen_dst_key = f"sb:dst:{user_id}"
    is_new_dst = (await state.redis.sismember(seen_dst_key, dst)) is False
    await state.redis.sadd(seen_dst_key, dst)
    await state.redis.expire(seen_dst_key, 60 * 60 * 24 * 90)  # 90 days

    verdict = state.model.verdict(
        amount=amount,
        ts=ts,
        is_new_destination=is_new_dst,
        velocity_1h=int(velocity_1h),
        velocity_24h=int(velocity_24h),
        user_amount_zscore=float(z),
    )

    _LOG.info("fraud.score", tx_id=tx_id, score=verdict.score, anomaly=verdict.is_anomaly)
    if verdict.is_anomaly:
        state.audit.emit("fraud.alert", actor=user_id, resource=tx_id, outcome="alert",
                         score=verdict.score, explanation=verdict.explanation)
        if state.producer:
            from app.settings import settings
            await state.producer.send(settings.kafka_topic_out, data={
                "tx_id": tx_id,
                "user_id": user_id,
                "amount": data["amount"],
                "score": verdict.score,
                "explanation": verdict.explanation,
            }, key=tx_id)


async def run_worker(state: Any) -> None:
    if not state.consumer:
        _LOG.warning("kafka.consumer.unavailable")
        return
    _LOG.info("worker.started")
    async for data in state.consumer.stream():
        try:
            await handle(state, data)
        except Exception:  # noqa: BLE001
            _LOG.exception("worker.error")
