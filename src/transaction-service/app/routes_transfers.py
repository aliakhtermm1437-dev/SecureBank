from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from securebank_shared.auth import JWTClaims

from app.models import Transaction
from app.risk import fast_score, step_up_required
from app.schemas import TransferIn, TransferOut
from app.settings import settings

router = APIRouter(prefix="/v1/transactions", tags=["transactions"])


def _state(request: Request) -> Any:
    return request.app.state.svc


async def _jwt(request: Request) -> JWTClaims:
    return await request.app.state.jwt_dep(request, request.headers.get("authorization"))


@router.post("/transfer", response_model=TransferOut, status_code=202)
async def transfer(request: Request, payload: TransferIn,
                   claims: JWTClaims = Depends(_jwt)) -> TransferOut:
    state = _state(request)

    # Step-up MFA gate (ASVS V2.8). Reject if amount is over threshold and the
    # JWT was not issued via MFA.
    if step_up_required(payload.amount, settings.step_up_threshold_pkr) and not claims.mfa:
        state.audit.emit("transfer.rejected.step_up", actor=claims.sub, outcome="rejected")
        raise HTTPException(401, "step-up MFA required")

    # OPA authz — caller must own the source account.
    if not await state.opa.is_allowed({
        "subject": {"id": claims.sub, "roles": claims.roles, "mfa": claims.mfa},
        "action": "transfer",
        "resource": {"src_account_id": payload.src_account_id,
                     "dst_account_id": payload.dst_account_id,
                     "amount": str(payload.amount)},
    }):
        raise HTTPException(403, "forbidden")

    # Compute light-weight risk score.
    first_time = await state.redis.sismember(
        f"first_dst:{payload.src_account_id}", payload.dst_account_id
    ) is False
    score = fast_score(payload.amount, src_first_tx_to_dst=first_time)

    # Persist atomically; idempotency enforced by unique constraint.
    async with state.session_factory() as s, s.begin():
        tx = Transaction(
            id=uuid.uuid4(),
            idempotency_key=payload.idempotency_key,
            initiator_user_id=uuid.UUID(claims.sub),
            src_account_id=uuid.UUID(payload.src_account_id),
            dst_account_id=uuid.UUID(payload.dst_account_id),
            amount=payload.amount,
            currency=payload.currency,
            memo=payload.memo,
            risk_score=score,
            status="pending",
        )
        s.add(tx)
        try:
            await s.flush()
        except Exception:
            # Idempotent retry — fetch the prior record.
            await s.rollback()
            from sqlalchemy import select
            q = select(Transaction).where(
                Transaction.initiator_user_id == claims.sub,
                Transaction.idempotency_key == payload.idempotency_key,
            )
            res = (await s.execute(q)).scalar_one_or_none()
            if not res:
                raise HTTPException(409, "duplicate idempotency key")
            tx = res

        state.audit.emit("transfer.accepted", actor=claims.sub, resource=str(tx.id),
                         outcome="accepted", amount=str(payload.amount), risk=score)

    # Publish event to Kafka (signed, idempotent, acks=all).
    if state.producer:
        await state.producer.send(
            settings.kafka_topic_tx,
            data={
                "tx_id": str(tx.id),
                "initiator_user_id": claims.sub,
                "src_account_id": payload.src_account_id,
                "dst_account_id": payload.dst_account_id,
                "amount": str(payload.amount),
                "currency": payload.currency,
                "memo": payload.memo,
                "risk_score": score,
                "mfa": claims.mfa,
            },
            key=str(tx.id),
        )

    return TransferOut(
        id=str(tx.id),
        status=tx.status,
        amount=tx.amount,
        currency=tx.currency,
        src_account_id=str(tx.src_account_id),
        dst_account_id=str(tx.dst_account_id),
        risk_score=tx.risk_score,
    )


@router.get("/{tx_id}", response_model=TransferOut)
async def get_tx(request: Request, tx_id: str,
                 claims: JWTClaims = Depends(_jwt)) -> TransferOut:
    state = _state(request)
    async with state.session_factory() as s:
        tx = await s.get(Transaction, tx_id)
    if not tx:
        raise HTTPException(404, "not found")
    if str(tx.initiator_user_id) != claims.sub:
        raise HTTPException(403, "forbidden")
    return TransferOut(
        id=str(tx.id), status=tx.status, amount=tx.amount, currency=tx.currency,
        src_account_id=str(tx.src_account_id),
        dst_account_id=str(tx.dst_account_id),
        risk_score=tx.risk_score,
    )
