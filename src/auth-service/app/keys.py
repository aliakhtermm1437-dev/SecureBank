"""JWT signing key management.

Active key & previous key are stored in Vault KV v2 under ``auth/keys``. The
``kid`` is the SHA-256 fingerprint of the public key DER. Rotation is
zero-downtime: a new key is added as ``next``, after one TTL it becomes
``active``, the previous active becomes ``rollback`` for 1×TTL.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from securebank_shared.vault import VaultClient


@dataclass(slots=True)
class KeyPair:
    kid: str
    private_pem: bytes
    public_pem: bytes


def _fingerprint(pub_der: bytes) -> str:
    return hashlib.sha256(pub_der).hexdigest()[:32]


def generate_keypair() -> KeyPair:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return KeyPair(kid=_fingerprint(pub_der), private_pem=priv_pem, public_pem=pub_pem)


def to_jwk(public_pem: bytes, kid: str) -> dict[str, Any]:
    from jwt.algorithms import RSAAlgorithm
    pub = serialization.load_pem_public_key(public_pem)
    jwk = json.loads(RSAAlgorithm.to_jwk(pub))
    jwk["kid"] = kid
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return jwk


class KeyRing:
    """In-memory ring with at most two active keys (active + previous).

    For an academic demo the keyring is bootstrapped at startup. In production
    you would back it with Vault Transit or KMS.
    """

    def __init__(self, vault: VaultClient | None = None, kv_path: str = "auth/keys") -> None:
        self._vault = vault
        self._kv_path = kv_path
        self.active: KeyPair | None = None
        self.previous: KeyPair | None = None

    def bootstrap_local(self) -> None:
        """Generate an ephemeral keypair (dev/test only)."""
        self.active = generate_keypair()

    def load_from_vault(self) -> None:
        if not self._vault:
            raise RuntimeError("vault client not provided")
        data = self._vault.kv_get(self._kv_path)
        self.active = KeyPair(
            kid=data["active_kid"],
            private_pem=data["active_priv"].encode(),
            public_pem=data["active_pub"].encode(),
        )
        if "prev_kid" in data:
            self.previous = KeyPair(
                kid=data["prev_kid"],
                private_pem=data["prev_priv"].encode(),
                public_pem=data["prev_pub"].encode(),
            )

    def jwks(self) -> dict[str, list[dict[str, Any]]]:
        keys = []
        if self.active:
            keys.append(to_jwk(self.active.public_pem, self.active.kid))
        if self.previous:
            keys.append(to_jwk(self.previous.public_pem, self.previous.kid))
        return {"keys": keys}

    def signing_key(self) -> KeyPair:
        if not self.active:
            raise RuntimeError("keyring not initialised")
        return self.active


def keyring_from_env() -> KeyRing:
    """Factory used at app startup. Uses Vault if VAULT_ADDR is set, else local."""
    addr = os.getenv("VAULT_ADDR")
    if addr:
        try:
            v = VaultClient(addr=addr)
            ring = KeyRing(vault=v)
            ring.load_from_vault()
            return ring
        except Exception:
            pass
    ring = KeyRing()
    ring.bootstrap_local()
    return ring
