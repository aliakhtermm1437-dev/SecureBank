"""Minimal OPA client — talks to a local OPA sidecar via HTTP.

REGO policies are bundled and loaded by OPA from the bundle server. Each
service evaluates :pyfunc:`is_allowed` per request after JWT verification.
"""
from __future__ import annotations

from typing import Any

import httpx

from securebank_shared.logging import get_logger

_LOG = get_logger("opa")


class OPAClient:
    def __init__(self, base_url: str = "http://localhost:8181", timeout: float = 0.5) -> None:
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout)

    async def query(self, path: str, input_: dict[str, Any]) -> dict[str, Any]:
        """``path`` is the dotted REGO rule path, e.g. ``"securebank/authz/allow"``."""
        url = "/v1/data/" + path.replace(".", "/")
        resp = await self._client.post(url, json={"input": input_})
        resp.raise_for_status()
        return resp.json().get("result", {})

    async def is_allowed(self, input_: dict[str, Any], rule: str = "securebank/authz/allow") -> bool:
        try:
            result = await self.query(rule, input_)
            if isinstance(result, bool):
                return result
            if isinstance(result, dict):
                return bool(result.get("allow", False))
            return False
        except Exception as e:  # fail-closed
            _LOG.error("opa.query.failed", err=str(e), rule=rule)
            return False

    async def close(self) -> None:
        await self._client.aclose()
