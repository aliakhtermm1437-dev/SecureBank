from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/v1/notifications", tags=["notifications"])


def _state(request: Request) -> Any:
    return request.app.state.svc


@router.get("")
async def list_mine(request: Request) -> dict:
    state = _state(request)
    user_id = request.headers.get("x-user-id")
    if not user_id:
        raise HTTPException(401, "no user context")
    items = [x.decode() for x in await state.redis.lrange(f"sb:notif:{user_id}", 0, -1)]
    return {"items": items}
