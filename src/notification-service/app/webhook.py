"""Outbound webhook helper that re-validates URLs at call-time (defense vs.
DNS rebinding) and refuses redirects to private networks.
"""
from __future__ import annotations

import httpx

from securebank_shared.url_safety import UnsafeUrlError, validate_webhook_url


async def post_webhook(url: str, json_body: dict, timeout_s: float = 3.0) -> int:
    validate_webhook_url(url)
    transport = httpx.AsyncHTTPTransport(retries=0)
    async with httpx.AsyncClient(
        timeout=timeout_s,
        transport=transport,
        follow_redirects=False,        # never auto-follow
    ) as client:
        r = await client.post(url, json=json_body)
        return r.status_code
