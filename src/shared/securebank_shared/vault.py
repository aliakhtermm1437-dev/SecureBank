"""Thin wrapper around HashiCorp Vault using AppRole + dynamic secrets.

In production, the Vault Agent injector populates these — we ALSO expose this
client so services can refresh dynamic creds on lease expiry.
"""
from __future__ import annotations

import os
from contextlib import suppress
from typing import Any

import hvac
from tenacity import retry, stop_after_attempt, wait_exponential

from securebank_shared.logging import get_logger

_LOG = get_logger("vault")


class VaultClient:
    def __init__(
        self,
        addr: str,
        role_id: str | None = None,
        secret_id: str | None = None,
        namespace: str | None = None,
        token: str | None = None,
        verify: str | bool = True,
    ) -> None:
        self._addr = addr
        self._role_id = role_id or os.getenv("VAULT_ROLE_ID")
        self._secret_id = secret_id or os.getenv("VAULT_SECRET_ID")
        self._namespace = namespace
        self.client = hvac.Client(url=addr, namespace=namespace, verify=verify)
        if token:
            self.client.token = token
        elif self._role_id and self._secret_id:
            self.login_approle()
        elif os.path.exists("/var/run/secrets/vault-token"):
            with open("/var/run/secrets/vault-token", encoding="utf-8") as f:
                self.client.token = f.read().strip()

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=0.5, max=10))
    def login_approle(self) -> None:
        if not (self._role_id and self._secret_id):
            raise RuntimeError("AppRole role_id/secret_id not provided")
        resp = self.client.auth.approle.login(
            role_id=self._role_id, secret_id=self._secret_id
        )
        self.client.token = resp["auth"]["client_token"]
        _LOG.info("vault.login.success", role=self._role_id)

    # ---- KV v2 ------------------------------------------------------------

    def kv_get(self, path: str, mount: str = "secret") -> dict[str, Any]:
        resp = self.client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount)
        return resp["data"]["data"]

    # ---- Transit (envelope encryption / sign-verify) ---------------------

    def transit_encrypt(self, key_name: str, plaintext: bytes) -> str:
        import base64
        b64 = base64.b64encode(plaintext).decode()
        resp = self.client.secrets.transit.encrypt_data(name=key_name, plaintext=b64)
        return resp["data"]["ciphertext"]

    def transit_decrypt(self, key_name: str, ciphertext: str) -> bytes:
        import base64
        resp = self.client.secrets.transit.decrypt_data(name=key_name, ciphertext=ciphertext)
        return base64.b64decode(resp["data"]["plaintext"])

    # ---- Database dynamic creds ------------------------------------------

    def db_creds(self, role: str) -> tuple[str, str, int]:
        """Return (username, password, lease_seconds) for a dynamic DB role."""
        resp = self.client.secrets.database.generate_credentials(name=role)
        return resp["data"]["username"], resp["data"]["password"], resp["lease_duration"]

    # ---- PKI -------------------------------------------------------------

    def pki_issue(self, role: str, common_name: str, ttl: str = "24h") -> dict[str, Any]:
        resp = self.client.secrets.pki.generate_certificate(
            name=role,
            common_name=common_name,
            extra_params={"ttl": ttl},
        )
        return resp["data"]

    def close(self) -> None:
        with suppress(Exception):
            self.client.adapter.close()
