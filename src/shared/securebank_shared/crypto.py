"""Cryptographic primitives — opinionated, approved-algorithms-only.

ASVS V6 alignment:
- AES-256-GCM for symmetric encryption (authenticated)
- HMAC-SHA256 for message authentication
- ``secrets`` / ``os.urandom`` for randomness
- Constant-time comparison for any secret check

This module is **stateless** — keys are passed in. Real key material is supplied
by :class:`securebank_shared.vault.VaultClient`.
"""
from __future__ import annotations

import hmac
import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_LEN = 12  # GCM standard


@dataclass(frozen=True, slots=True)
class CipherText:
    """Wraps the 3-tuple (nonce, ciphertext, associated_data) and exposes a
    compact binary serialisation: ``nonce || ciphertext``.
    """

    nonce: bytes
    ct: bytes
    aad: bytes | None = None

    def to_bytes(self) -> bytes:
        return self.nonce + self.ct


def gen_key_aes256() -> bytes:
    """Return 32 random bytes — for use in tests/seeding, NOT in prod (use Vault)."""
    return AESGCM.generate_key(bit_length=256)


def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> CipherText:
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = os.urandom(_NONCE_LEN)
    aead = AESGCM(key)
    ct = aead.encrypt(nonce, plaintext, aad)
    return CipherText(nonce=nonce, ct=ct, aad=aad)


def aesgcm_decrypt(key: bytes, blob: bytes, aad: bytes | None = None) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    if len(blob) <= _NONCE_LEN:
        raise ValueError("ciphertext too short")
    nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, aad)


def hmac_sign(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, "sha256").digest()


def hmac_verify(key: bytes, data: bytes, signature: bytes) -> bool:
    return hmac.compare_digest(hmac_sign(key, data), signature)


def constant_time_eq(a: bytes | str, b: bytes | str) -> bool:
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    return hmac.compare_digest(a, b)


def random_token(nbytes: int = 32) -> str:
    """URL-safe random token; default 256 bits."""
    return secrets.token_urlsafe(nbytes)
