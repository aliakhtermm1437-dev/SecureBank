"""Strict Pydantic-based input validation primitives.

Every API request shape is built from these types so we get input validation
"for free" (ASVS V5). Output models in services should also reference these
types to prevent BOPLA (API3) leakage.
"""
from __future__ import annotations

import re
from decimal import Decimal
from typing import Annotated

import bleach
from email_validator import EmailNotValidError, validate_email
from pydantic import (
    AfterValidator,
    BeforeValidator,
    Field,
    StringConstraints,
)

# --- Email -----------------------------------------------------------------

def _validate_email(value: str) -> str:
    try:
        info = validate_email(value, check_deliverability=False)
    except EmailNotValidError as e:
        raise ValueError(str(e)) from e
    return info.normalized.lower()


SafeEmail = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=5, max_length=254),
    AfterValidator(_validate_email),
]

# --- Phone (Pakistani format, +92xxxxxxxxxx) -------------------------------

_PHONE_RE = re.compile(r"^\+92\d{10}$")


def _validate_phone(value: str) -> str:
    v = value.strip().replace(" ", "").replace("-", "")
    if not _PHONE_RE.match(v):
        raise ValueError("phone must match +92XXXXXXXXXX")
    return v


SafePhoneNumber = Annotated[str, AfterValidator(_validate_phone)]


# --- Account number (UUID hex, no PII) --------------------------------------

_ACCT_RE = re.compile(r"^[0-9a-f]{32}$")


def _validate_acct(value: str) -> str:
    v = value.strip().lower()
    if not _ACCT_RE.match(v):
        raise ValueError("invalid account number")
    return v


AccountNumber = Annotated[str, AfterValidator(_validate_acct)]


# --- Amount (positive decimal up to 999_999_999.99) -------------------------

def _validate_amount(value: Decimal) -> Decimal:
    if value <= 0:
        raise ValueError("amount must be positive")
    if value.as_tuple().exponent < -2:
        raise ValueError("amount cannot have more than 2 decimal places")
    if value > Decimal("999999999.99"):
        raise ValueError("amount too large")
    return value


Amount = Annotated[Decimal, Field(gt=0, max_digits=11, decimal_places=2),
                   AfterValidator(_validate_amount)]


# --- Free-text memo (sanitised; no HTML) ------------------------------------

_ALLOWED_MEMO_CHARS = re.compile(r"[\w\s.,!?@#\-:'/]+")


def _sanitise_memo(value: str) -> str:
    v = value.strip()
    v = bleach.clean(v, tags=[], strip=True)
    if not _ALLOWED_MEMO_CHARS.fullmatch(v):
        raise ValueError("memo contains disallowed characters")
    return v


SafeMemo = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=140),
    BeforeValidator(_sanitise_memo),
]
