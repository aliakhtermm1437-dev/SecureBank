"""Generate valid Pakistani IBANs and perform IBAN masking/hashing."""
from __future__ import annotations

import hashlib
import secrets

from securebank_shared.crypto import aesgcm_decrypt, aesgcm_encrypt


LETTER_VALUES = {chr(code): str(10 + code - 65) for code in range(ord("A"), ord("Z") + 1)}


def _iban_numeric_value(iban: str) -> str:
    result = []
    for ch in iban:
        if ch.isalpha():
            result.append(LETTER_VALUES[ch])
        else:
            result.append(ch)
    return "".join(result)


def _compute_iban_check_digits(country_code: str, bban: str) -> str:
    rearranged = f"{bban}{country_code}00"
    numeric = _iban_numeric_value(rearranged)
    remainder = int(numeric) % 97
    check = 98 - remainder
    return f"{check:02d}"


def new_iban() -> str:
    # PK 2-check 4-bank-code 16-account-no
    country_code = "PK"
    bank_code = "SCBL"
    acct_no = "".join(secrets.choice("0123456789") for _ in range(16))
    bban = f"{bank_code}{acct_no}"
    check = _compute_iban_check_digits(country_code, bban)
    return f"{country_code}{check}{bban}"


def mask_iban(iban: str) -> str:
    return iban[:4] + "********" + iban[-4:]


def iban_hash(iban: str) -> str:
    return hashlib.sha256(b"sb-iban:" + iban.encode()).hexdigest()


def encrypt_iban(key: bytes, iban: str) -> bytes:
    return aesgcm_encrypt(key, iban.encode()).to_bytes()


def decrypt_iban(key: bytes, blob: bytes) -> str:
    return aesgcm_decrypt(key, blob).decode()
