from __future__ import annotations

import asyncio
from typing import Any

from securebank_shared.logging import get_logger

_LOG = get_logger("notification.worker")


async def handle_tx(state: Any, data: dict) -> None:
    """Persist a notification (we'd send SMS/email here)."""
    user_id = data["initiator_user_id"]
    tx_id = data["tx_id"]
    msg = {
        "type": "transfer",
        "tx_id": tx_id,
        "amount": data["amount"],
        "currency": data["currency"],
        "memo": data.get("memo") or "",
    }
    # bleach was already applied in transaction-service; double-defense here:
    import bleach
    msg["memo"] = bleach.clean(msg["memo"], tags=[], strip=True)

    await state.redis.lpush(f"sb:notif:{user_id}", str(msg))
    await state.redis.ltrim(f"sb:notif:{user_id}", 0, 99)
    state.audit.emit("notify.transfer", actor=user_id, resource=tx_id, outcome="queued")


async def handle_alert(state: Any, data: dict) -> None:
    user_id = data["user_id"]
    state.audit.emit("notify.fraud_alert", actor=user_id, resource=data.get("tx_id"),
                     outcome="queued", score=data.get("score"))


async def run(state: Any) -> None:
    async def loop_tx() -> None:
        if state.consumer_tx:
            async for d in state.consumer_tx.stream():
                try: await handle_tx(state, d)
                except Exception: _LOG.exception("notification.tx.error")

    async def loop_alerts() -> None:
        if state.consumer_alerts:
            async for d in state.consumer_alerts.stream():
                try: await handle_alert(state, d)
                except Exception: _LOG.exception("notification.alert.error")

    await asyncio.gather(loop_tx(), loop_alerts())
