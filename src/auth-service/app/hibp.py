"""HIBP (Have I Been Pwned) range-API client.

We send only the first 5 SHA-1 chars and check the returned list locally — the
remote service never sees the full hash. ASVS V2.1.5.
"""
from __future__ import annotations

import hashlib

import httpx

from securebank_shared.logging import get_logger

_LOG = get_logger("hibp")
_API = "https://api.pwnedpasswords.com/range/{prefix}"


async def is_pwned(password: str, *, timeout_s: float = 1.5) -> bool:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()  # noqa: S324 — required by HIBP
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            r = await client.get(
                _API.format(prefix=prefix),
                headers={"Add-Padding": "true", "User-Agent": "SecureBank-auth/1.0"},
            )
            r.raise_for_status()
    except Exception as e:
        # Fail-open is acceptable here — registration still requires complexity policy.
        _LOG.warning("hibp.unavailable", err=str(e))
        return False
    for line in r.text.splitlines():
        if ":" in line:
            h, _count = line.split(":", 1)
            if h.strip() == suffix:
                return True
    return False
