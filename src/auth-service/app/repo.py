from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User


class UserRepo:
    def __init__(self, session: AsyncSession) -> None:
        self.s = session

    async def by_email(self, email: str) -> User | None:
        q = select(User).where(User.email == email.lower())
        return (await self.s.execute(q)).scalar_one_or_none()

    async def by_id(self, uid: uuid.UUID | str) -> User | None:
        if isinstance(uid, str):
            uid = uuid.UUID(uid)
        return await self.s.get(User, uid)

    async def create(self, *, email: str, password_hash: str, phone: str | None) -> User:
        u = User(email=email.lower(), password_hash=password_hash, phone=phone)
        self.s.add(u)
        await self.s.flush()
        return u

    async def record_login_failure(self, user: User, *, max_fails: int = 5,
                                   lock_minutes: int = 15) -> None:
        user.failed_logins = (user.failed_logins or 0) + 1
        if user.failed_logins >= max_fails:
            user.lock_until = datetime.now(timezone.utc) + timedelta(minutes=lock_minutes)
            user.failed_logins = 0
        await self.s.flush()

    async def clear_login_failures(self, user: User) -> None:
        user.failed_logins = 0
        user.lock_until = None
        await self.s.flush()

    async def set_password(self, user: User, new_hash: str) -> None:
        user.password_hash = new_hash
        user.must_rotate_pw = False
        await self.s.flush()

    async def set_mfa(self, user: User, *, secret_enc: bytes | None, enabled: bool) -> None:
        user.mfa_enabled = enabled
        user.mfa_secret_enc = secret_enc
        await self.s.flush()

    async def deactivate(self, user_id: uuid.UUID) -> None:
        await self.s.execute(
            update(User).where(User.id == user_id).values(is_active=False)
        )
