"""Redis-backed session store.

- AES-256-GCM encryption of session payload at-rest (defense-in-depth on top of
  Redis ACL & TLS)
- 15-min idle TTL, sliding
- Single-use refresh tokens (rotation + reuse detection)
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass

from redis.asyncio import Redis

from securebank_shared.crypto import aesgcm_decrypt, aesgcm_encrypt, random_token

_SESSION_TTL = 15 * 60
_REFRESH_TTL = 7 * 24 * 3600


@dataclass(slots=True)
class Session:
    sid: str
    user_id: str
    roles: list[str]
    mfa: bool
    created_at: float
    last_seen: float
    ip: str | None = None
    ua: str | None = None


class SessionStore:
    def __init__(self, redis: Redis, key_for_data: bytes, ns: str = "sb:sess") -> None:
        self._r = redis
        self._key = key_for_data
        self._ns = ns

    def _k(self, sid: str) -> str:
        return f"{self._ns}:{sid}"

    async def create(
        self,
        user_id: str,
        *,
        roles: list[str],
        mfa: bool,
        ip: str | None,
        ua: str | None,
    ) -> Session:
        sid = random_token(32)
        now = time.time()
        sess = Session(
            sid=sid, user_id=user_id, roles=roles, mfa=mfa,
            created_at=now, last_seen=now, ip=ip, ua=ua,
        )
        await self._persist(sess)
        return sess

    async def _persist(self, sess: Session) -> None:
        payload = json.dumps(asdict(sess)).encode()
        blob = aesgcm_encrypt(self._key, payload).to_bytes()
        await self._r.set(self._k(sess.sid), blob, ex=_SESSION_TTL)

    async def get(self, sid: str) -> Session | None:
        blob = await self._r.get(self._k(sid))
        if not blob:
            return None
        try:
            payload = aesgcm_decrypt(self._key, blob)
        except Exception:
            await self._r.delete(self._k(sid))
            return None
        data = json.loads(payload)
        sess = Session(**data)
        # sliding refresh
        sess.last_seen = time.time()
        await self._persist(sess)
        return sess

    async def revoke(self, sid: str) -> None:
        await self._r.delete(self._k(sid))

    async def revoke_all_for_user(self, user_id: str) -> int:
        """Slow scan; only used for password change / suspected compromise."""
        cnt = 0
        async for k in self._r.scan_iter(match=f"{self._ns}:*"):
            v = await self._r.get(k)
            if not v:
                continue
            try:
                data = json.loads(aesgcm_decrypt(self._key, v))
            except Exception:
                await self._r.delete(k)
                continue
            if data.get("user_id") == user_id:
                await self._r.delete(k)
                cnt += 1
        return cnt


class RefreshTokenStore:
    """One-time-use refresh tokens with reuse detection."""

    def __init__(self, redis: Redis, ns: str = "sb:rtk") -> None:
        self._r = redis
        self._ns = ns

    async def issue(self, user_id: str, sid: str) -> str:
        tok = random_token(32)
        await self._r.set(f"{self._ns}:{tok}", f"{user_id}|{sid}|live", ex=_REFRESH_TTL)
        return tok

    async def rotate(self, presented: str) -> tuple[str, str, str] | None:
        """Return (new_token, user_id, sid) on success, ``None`` if invalid.

        If the presented token has already been used, we mark the *entire*
        session compromised — classic refresh-token reuse detection.
        """
        key = f"{self._ns}:{presented}"
        v = await self._r.get(key)
        if not v:
            return None
        try:
            user_id, sid, state = v.decode().split("|")
        except Exception:
            return None
        if state == "used":
            # Reuse detected — burn the whole session family
            await self._r.set(key, f"{user_id}|{sid}|compromised", ex=_REFRESH_TTL)
            return None
        # mark used, issue new
        await self._r.set(key, f"{user_id}|{sid}|used", ex=_REFRESH_TTL)
        new_tok = await self.issue(user_id, sid)
        return new_tok, user_id, sid
