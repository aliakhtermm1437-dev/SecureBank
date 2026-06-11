from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from securebank_shared.auth import (
    DEFAULT_ACCESS_TTL,
    hash_password,
    issue_jwt,
    needs_rehash,
    verify_password,
)
from securebank_shared.crypto import aesgcm_decrypt, aesgcm_encrypt
from securebank_shared.logging import get_logger

from app.hibp import is_pwned
from app.mfa import new_enrollment, verify as totp_verify
from app.repo import UserRepo
from app.schemas import (
    GenericOK,
    LoginIn,
    LoginOut,
    MFAEnrollOut,
    MFAVerifyIn,
    RefreshIn,
    RegisterIn,
    RegisterOut,
    TokenOut,
)
from app.settings import settings

_LOG = get_logger("auth.routes")
router = APIRouter(prefix="/v1/auth", tags=["auth"])

limiter = Limiter(key_func=get_remote_address, default_limits=[])


def _state(request: Request) -> Any:
    return request.app.state.svc  # set in lifespan


def _client_meta(request: Request) -> tuple[str | None, str | None]:
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    return ip, ua


# ---------- Register --------------------------------------------------------

@router.post("/register", response_model=RegisterOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(f"{settings.register_rate_per_min}/minute")
async def register(request: Request, payload: RegisterIn) -> RegisterOut:
    state = _state(request)
    # Reject breached passwords (ASVS V2.1.5).
    if settings.hibp_enabled and await is_pwned(payload.password):
        # Unified response — do NOT reveal whether the email already exists.
        state.audit.emit("auth.register.rejected.breached_password",
                         actor=payload.email, outcome="rejected")
        return RegisterOut()

    async with state.session_factory() as s, s.begin():
        repo = UserRepo(s)
        existing = await repo.by_email(payload.email)
        if existing:
            # Same unified 202 response (no enumeration).
            state.audit.emit("auth.register.duplicate", actor=payload.email, outcome="ignored")
            return RegisterOut()
        u = await repo.create(
            email=payload.email,
            phone=payload.phone,
            password_hash=hash_password(payload.password),
        )
        state.audit.emit("auth.register.success", actor=str(u.id), outcome="success")
    return RegisterOut()


# ---------- Login (step 1 - pwd, returns pre-auth or full token) -----------

@router.post("/login", response_model=LoginOut)
@limiter.limit(f"{settings.login_rate_per_min}/minute")
async def login(request: Request, payload: LoginIn) -> LoginOut:
    state = _state(request)
    ip, ua = _client_meta(request)
    async with state.session_factory() as s, s.begin():
        repo = UserRepo(s)
        user = await repo.by_email(payload.email)

        # Constant-time pwd verify even when user is None.
        ok = verify_password(user.password_hash if user else None, payload.password)
        if not user or not user.is_active or not ok:
            if user:
                await repo.record_login_failure(user)
            state.audit.emit("auth.login.failed", actor=payload.email,
                             ip=ip, ua=ua, outcome="failed")
            raise HTTPException(401, "invalid credentials")

        if user.lock_until and user.lock_until > datetime.now(timezone.utc):
            state.audit.emit("auth.login.locked", actor=str(user.id), outcome="rejected")
            raise HTTPException(423, "account temporarily locked")

        await repo.clear_login_failures(user)
        # Upgrade hash if Argon2 params changed.
        if needs_rehash(user.password_hash):
            await repo.set_password(user, hash_password(payload.password))

        # If MFA required, return a pre-auth JWT (typ="pre-auth", short ttl, no scope).
        if user.mfa_enabled:
            pre = issue_jwt(
                private_key_pem=state.keyring.signing_key().private_pem,
                kid=state.keyring.signing_key().kid,
                subject=str(user.id),
                issuer=settings.jwt_issuer,
                audience=settings.jwt_audience,
                ttl_seconds=300,
                typ="pre-auth",
                mfa=False,
            )
            state.audit.emit("auth.login.pwd_ok.mfa_required", actor=str(user.id),
                             ip=ip, outcome="success")
            return LoginOut(pre_auth_token=pre, mfa_required=True)

        # No MFA — issue full session + tokens.
        sess = await state.sessions.create(
            user_id=str(user.id),
            roles=["admin" if user.is_admin else "customer"],
            mfa=False,
            ip=ip, ua=ua,
        )
        access = issue_jwt(
            private_key_pem=state.keyring.signing_key().private_pem,
            kid=state.keyring.signing_key().kid,
            subject=str(user.id),
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            ttl_seconds=settings.jwt_access_ttl_s,
            typ="access",
            roles=["admin" if user.is_admin else "customer"],
            sid=sess.sid,
            mfa=False,
        )
        refresh = await state.refresh_tokens.issue(str(user.id), sess.sid)
        state.audit.emit("auth.login.success", actor=str(user.id), ip=ip, outcome="success")
        return LoginOut(
            access_token=access,
            refresh_token=refresh,
            expires_in=settings.jwt_access_ttl_s,
            mfa_required=False,
        )


# ---------- MFA verify (step 2) --------------------------------------------

@router.post("/mfa/verify", response_model=TokenOut)
async def mfa_verify(request: Request, payload: MFAVerifyIn) -> TokenOut:
    state = _state(request)
    ip, ua = _client_meta(request)

    # Throttle TOTP attempts per pre-auth token (F13 fix).
    rate_key = f"mfa:verify:{payload.pre_auth_token[:32]}"
    cnt = await state.redis.incr(rate_key)
    if cnt == 1:
        await state.redis.expire(rate_key, 15 * 60)
    if cnt > settings.mfa_verify_max_attempts:
        raise HTTPException(429, "too many attempts")

    # Verify pre-auth JWT (typ must be "pre-auth"); we can use our own active key.
    import jwt
    try:
        claims = jwt.decode(
            payload.pre_auth_token,
            state.keyring.signing_key().public_pem,
            algorithms=["RS256"],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["exp","iat","nbf","iss","aud","jti","sub","typ"]},
        )
    except jwt.PyJWTError as e:
        raise HTTPException(401, "invalid pre-auth token") from e
    if claims.get("typ") != "pre-auth":
        raise HTTPException(401, "wrong token type")

    async with state.session_factory() as s, s.begin():
        repo = UserRepo(s)
        user = await repo.by_id(claims["sub"])
        if not user or not user.mfa_enabled or not user.mfa_secret_enc:
            raise HTTPException(401, "mfa not enrolled")
        # The MFA secret is field-encrypted with the session AES key.
        secret = aesgcm_decrypt(state.sessions._key, user.mfa_secret_enc).decode()
        if not totp_verify(secret, payload.code):
            state.audit.emit("auth.mfa.failed", actor=str(user.id), ip=ip, outcome="failed")
            raise HTTPException(401, "invalid code")

        sess = await state.sessions.create(
            user_id=str(user.id),
            roles=["admin" if user.is_admin else "customer"],
            mfa=True,
            ip=ip, ua=ua,
        )
        access = issue_jwt(
            private_key_pem=state.keyring.signing_key().private_pem,
            kid=state.keyring.signing_key().kid,
            subject=str(user.id),
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            ttl_seconds=settings.jwt_access_ttl_s,
            typ="access",
            roles=["admin" if user.is_admin else "customer"],
            sid=sess.sid,
            mfa=True,
        )
        refresh = await state.refresh_tokens.issue(str(user.id), sess.sid)
        state.audit.emit("auth.mfa.success", actor=str(user.id), ip=ip, outcome="success")
        return TokenOut(
            access_token=access,
            refresh_token=refresh,
            expires_in=settings.jwt_access_ttl_s,
        )


# ---------- MFA enroll ------------------------------------------------------

@router.post("/mfa/enroll", response_model=MFAEnrollOut)
async def mfa_enroll(request: Request) -> MFAEnrollOut:
    """User must be authenticated to enroll (gateway forwards JWT)."""
    state = _state(request)
    sub = request.headers.get("x-user-id")
    if not sub:
        raise HTTPException(401, "no authenticated user")
    enroll = new_enrollment(account=sub)
    async with state.session_factory() as s, s.begin():
        repo = UserRepo(s)
        user = await repo.by_id(sub)
        if not user:
            raise HTTPException(404, "user not found")
        secret_enc = aesgcm_encrypt(state.sessions._key, enroll.secret_b32.encode()).to_bytes()
        await repo.set_mfa(user, secret_enc=secret_enc, enabled=True)
        state.audit.emit("auth.mfa.enrolled", actor=str(user.id), outcome="success")
    return MFAEnrollOut(
        otpauth_url=enroll.otpauth_url,
        qr_png_b64=enroll.qr_png_b64,
    )


# ---------- Refresh ---------------------------------------------------------

@router.post("/token/refresh", response_model=TokenOut)
async def refresh(request: Request, payload: RefreshIn) -> TokenOut:
    state = _state(request)
    rot = await state.refresh_tokens.rotate(payload.refresh_token)
    if not rot:
        # Possible reuse — revoke session
        raise HTTPException(401, "invalid refresh token")
    new_tok, user_id, sid = rot
    sess = await state.sessions.get(sid)
    if not sess:
        raise HTTPException(401, "session expired")
    access = issue_jwt(
        private_key_pem=state.keyring.signing_key().private_pem,
        kid=state.keyring.signing_key().kid,
        subject=user_id,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl_seconds=settings.jwt_access_ttl_s,
        typ="access",
        roles=sess.roles,
        sid=sid,
        mfa=sess.mfa,
    )
    state.audit.emit("auth.refresh.rotated", actor=user_id, outcome="success")
    return TokenOut(
        access_token=access,
        refresh_token=new_tok,
        expires_in=settings.jwt_access_ttl_s,
    )


# ---------- Logout ----------------------------------------------------------

@router.post("/logout", response_model=GenericOK)
async def logout(request: Request) -> GenericOK:
    state = _state(request)
    sid = request.headers.get("x-session-id")
    if sid:
        await state.sessions.revoke(sid)
        state.audit.emit("auth.logout", outcome="success", attrs={"sid": sid})
    return GenericOK()


# ---------- JWKS (public keys) ---------------------------------------------

@router.get("/.well-known/jwks.json")
async def jwks(request: Request) -> dict:
    state = _state(request)
    return state.keyring.jwks()


# ---------- OIDC discovery (minimal) ---------------------------------------

@router.get("/.well-known/openid-configuration")
async def oidc_discovery() -> dict:
    return {
        "issuer": settings.jwt_issuer,
        "jwks_uri": f"{settings.jwt_issuer}/v1/auth/.well-known/jwks.json",
        "authorization_endpoint": f"{settings.jwt_issuer}/v1/auth/authorize",
        "token_endpoint": f"{settings.jwt_issuer}/v1/auth/token",
        "userinfo_endpoint": f"{settings.jwt_issuer}/v1/auth/userinfo",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "email"],
    }
