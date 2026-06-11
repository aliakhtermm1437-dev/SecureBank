from __future__ import annotations

from decimal import Decimal
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from sqlalchemy import select

from securebank_shared.auth import JWTClaims

from app.iban import decrypt_iban, encrypt_iban, iban_hash, mask_iban, new_iban
from app.models import Account
from app.schemas import AccountListOut, AccountOut, CreateAccountIn, DebitCreditIn

router = APIRouter(prefix="/v1/accounts", tags=["accounts"])


def _state(request: Request) -> Any:
    return request.app.state.svc


async def _jwt(request: Request) -> JWTClaims:
    return await request.app.state.jwt_dep(request, request.headers.get("authorization"))


async def _opa_allow(state: Any, claims: JWTClaims, action: str, resource: dict[str, Any]) -> bool:
    return await state.opa.is_allowed({
        "subject": {"id": claims.sub, "roles": claims.roles, "mfa": claims.mfa},
        "action": action,
        "resource": resource,
    })


def _to_out(a: Account, key: bytes) -> AccountOut:
    return AccountOut(
        id=str(a.id),
        iban_masked=mask_iban(decrypt_iban(key, a.iban_enc)),
        currency=a.currency,
        balance=a.balance,
        status=a.status,
    )


@router.get("/me", response_model=AccountListOut)
async def list_mine(request: Request, claims: JWTClaims = Depends(_jwt)) -> AccountListOut:
    state = _state(request)
    async with state.session_factory() as s:
        q = select(Account).where(Account.user_id == claims.sub)
        rows = (await s.execute(q)).scalars().all()
    return AccountListOut(items=[_to_out(a, state.field_enc_key) for a in rows])


@router.post("", response_model=AccountOut, status_code=201)
async def create_account(request: Request, payload: CreateAccountIn,
                         claims: JWTClaims = Depends(_jwt)) -> AccountOut:
    state = _state(request)
    if not await _opa_allow(state, claims, "create", {"type": "account"}):
        raise HTTPException(403, "forbidden")
    iban = new_iban()
    enc = encrypt_iban(state.field_enc_key, iban)
    async with state.session_factory() as s, s.begin():
        acc = Account(
            user_id=claims.sub,
            iban_enc=enc,
            iban_hash=iban_hash(iban),
            currency=payload.currency,
            balance=Decimal("0.00"),
        )
        s.add(acc)
        await s.flush()
        state.audit.emit("account.create", actor=claims.sub, resource=str(acc.id),
                         outcome="success")
        out = _to_out(acc, state.field_enc_key)
    return out


@router.get("/{account_id}", response_model=AccountOut)
async def get_account(request: Request, account_id: str = Path(...),
                      claims: JWTClaims = Depends(_jwt)) -> AccountOut:
    state = _state(request)
    async with state.session_factory() as s:
        acc = await s.get(Account, account_id)
    if not acc:
        raise HTTPException(404, "not found")
    # Owner-check (BOLA / API1).
    if not await _opa_allow(state, claims, "read",
                            {"type": "account", "owner": str(acc.user_id), "id": account_id}):
        state.audit.emit("account.read.denied", actor=claims.sub, resource=account_id,
                         outcome="denied")
        raise HTTPException(403, "forbidden")
    return _to_out(acc, state.field_enc_key)


@router.post("/{account_id}/credit", response_model=AccountOut)
async def credit(request: Request, payload: DebitCreditIn,
                 account_id: str = Path(...),
                 claims: JWTClaims = Depends(_jwt)) -> AccountOut:
    return await _mutate(request, claims, account_id, payload, op="credit")


@router.post("/{account_id}/debit", response_model=AccountOut)
async def debit(request: Request, payload: DebitCreditIn,
                account_id: str = Path(...),
                claims: JWTClaims = Depends(_jwt)) -> AccountOut:
    return await _mutate(request, claims, account_id, payload, op="debit")


async def _mutate(request: Request, claims: JWTClaims, account_id: str,
                  payload: DebitCreditIn, op: str) -> AccountOut:
    state = _state(request)
    idemp_key = f"idemp:{op}:{account_id}:{payload.idempotency_key}"
    # Idempotency check.
    prev = await state.redis.get(idemp_key)
    if prev:
        # We already processed this — return current state.
        async with state.session_factory() as s:
            acc = await s.get(Account, account_id)
        return _to_out(acc, state.field_enc_key)

    if not await _opa_allow(state, claims, op,
                            {"type": "account", "id": account_id}):
        raise HTTPException(403, "forbidden")

    async with state.session_factory() as s, s.begin():
        acc: Account | None = await s.get(Account, account_id, with_for_update=True)
        if not acc:
            raise HTTPException(404, "not found")
        if acc.status != "active":
            raise HTTPException(409, "account not active")
        if op == "credit":
            acc.balance = acc.balance + payload.amount
        else:
            if acc.balance < payload.amount:
                # Generic message — do not leak business state.
                raise HTTPException(400, "request rejected")
            acc.balance = acc.balance - payload.amount
        acc.version = acc.version + 1
        await s.flush()
        state.audit.emit(
            f"account.{op}", actor=claims.sub, resource=account_id, outcome="success",
            amount=str(payload.amount),
        )
        out = _to_out(acc, state.field_enc_key)
    # Mark idempotency for 24h.
    await state.redis.set(idemp_key, "1", ex=24 * 3600)
    return out
