"""Hardened Kafka producer/consumer helpers (TLS + SASL + per-msg HMAC).

Every message is wrapped in a JSON envelope:
    {"v":1, "ts": <epoch>, "iss": "<service>", "sig": "<hex-hmac>", "data": {...}}

The HMAC key is fetched once from Vault at startup. Consumers verify the
signature before handing the payload to the business handler — this defends
against a topic-write capability being abused to inject malicious events.
"""
from __future__ import annotations

import json
import os
import ssl
import time
from collections.abc import AsyncIterator, Callable
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.helpers import create_ssl_context

from securebank_shared.crypto import hmac_sign, hmac_verify
from securebank_shared.logging import get_logger

_LOG = get_logger("kafka")
_ENVELOPE_VERSION = 1


def _ssl_ctx(ca: str | None, cert: str | None, key: str | None) -> ssl.SSLContext | None:
    if not (ca and cert and key):
        return None
    return create_ssl_context(cafile=ca, certfile=cert, keyfile=key)


def envelope(issuer: str, hmac_key: bytes, data: dict[str, Any]) -> bytes:
    payload = {
        "v": _ENVELOPE_VERSION,
        "ts": time.time(),
        "iss": issuer,
        "data": data,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac_sign(hmac_key, raw).hex()
    payload["sig"] = sig
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def open_envelope(hmac_key: bytes, raw: bytes) -> dict[str, Any]:
    msg = json.loads(raw)
    sig = msg.pop("sig", "")
    if not sig:
        raise ValueError("missing signature")
    recomputed = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()
    if not hmac_verify(hmac_key, recomputed, bytes.fromhex(sig)):
        raise ValueError("invalid signature")
    if msg.get("v") != _ENVELOPE_VERSION:
        raise ValueError("unsupported envelope version")
    return msg["data"]


class SecureProducer:
    def __init__(
        self,
        bootstrap_servers: str,
        *,
        issuer: str,
        hmac_key: bytes,
        sasl_username: str | None = None,
        sasl_password: str | None = None,
        ca: str | None = None,
        cert: str | None = None,
        key: str | None = None,
    ) -> None:
        self._issuer = issuer
        self._key = hmac_key
        self._producer = AIOKafkaProducer(
            bootstrap_servers=bootstrap_servers,
            enable_idempotence=True,
            acks="all",
            compression_type="gzip",
            security_protocol="SASL_SSL" if sasl_username else "SSL",
            sasl_mechanism="SCRAM-SHA-512" if sasl_username else None,
            sasl_plain_username=sasl_username,
            sasl_plain_password=sasl_password,
            ssl_context=_ssl_ctx(ca, cert, key),
            request_timeout_ms=15_000,
            metadata_max_age_ms=60_000,
        )

    async def start(self) -> None:
        await self._producer.start()

    async def stop(self) -> None:
        await self._producer.stop()

    async def send(self, topic: str, data: dict[str, Any], key: str | None = None) -> None:
        body = envelope(self._issuer, self._key, data)
        await self._producer.send_and_wait(topic, body, key=key.encode() if key else None)
        _LOG.info("kafka.produced", topic=topic, key=key)


class SecureConsumer:
    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        group_id: str,
        *,
        hmac_key: bytes,
        sasl_username: str | None = None,
        sasl_password: str | None = None,
        ca: str | None = None,
        cert: str | None = None,
        key: str | None = None,
    ) -> None:
        self._key = hmac_key
        self._topic = topic
        self._consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
            security_protocol="SASL_SSL" if sasl_username else "SSL",
            sasl_mechanism="SCRAM-SHA-512" if sasl_username else None,
            sasl_plain_username=sasl_username,
            sasl_plain_password=sasl_password,
            ssl_context=_ssl_ctx(ca, cert, key),
        )

    async def start(self) -> None:
        await self._consumer.start()

    async def stop(self) -> None:
        await self._consumer.stop()

    async def stream(self) -> AsyncIterator[dict[str, Any]]:
        try:
            async for msg in self._consumer:
                try:
                    data = open_envelope(self._key, msg.value)
                except Exception as e:
                    _LOG.warning("kafka.envelope.invalid", err=str(e), topic=msg.topic)
                    await self._consumer.commit()
                    continue
                yield data
                await self._consumer.commit()
        finally:
            pass

    async def run(self, handler: Callable[[dict[str, Any]], Any]) -> None:
        import inspect

        async for data in self.stream():
            try:
                r = handler(data)
                if inspect.isawaitable(r):
                    await r
            except Exception as e:  # noqa: BLE001
                _LOG.exception("kafka.handler.error", err=str(e), topic=self._topic)
