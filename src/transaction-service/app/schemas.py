from __future__ import annotations

from decimal import Decimal
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from securebank_shared.validation import Amount, SafeMemo


IdempotencyKey = Annotated[str, StringConstraints(min_length=8, max_length=64)]


class TransferIn(BaseModel):
    src_account_id: str
    dst_account_id: str
    amount: Amount
    currency: Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")] = "PKR"
    memo: SafeMemo | None = None
    idempotency_key: IdempotencyKey


class TransferOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    status: str
    amount: Decimal
    currency: str
    src_account_id: str
    dst_account_id: str
    risk_score: float
