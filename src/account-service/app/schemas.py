from __future__ import annotations

from decimal import Decimal
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from securebank_shared.validation import Amount


Currency = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]


class AccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    iban_masked: str
    currency: Currency
    balance: Decimal
    status: str


class AccountListOut(BaseModel):
    items: list[AccountOut]


class CreateAccountIn(BaseModel):
    currency: Currency = "PKR"


class DebitCreditIn(BaseModel):
    amount: Amount
    memo: str | None = Field(default=None, max_length=140)
    idempotency_key: Annotated[str, StringConstraints(min_length=8, max_length=64)]
