"""Append-only audit logger.

Every audit event is a JSON object emitted via the standard logger pipeline
(thus picked up by Loki + QRadar). Records are *hash-chained* per service so
tampering is detectable.

This file deliberately avoids any direct DB calls — audit must work even when
the DB is unreachable. Long-term storage is the SIEM's responsibility.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from securebank_shared.logging import get_logger

_LOG = get_logger("audit")


@dataclass(slots=True)
class AuditRecord:
    ts: float
    service: str
    event: str
    actor: str | None
    resource: str | None
    outcome: str
    request_id: str | None
    attrs: dict[str, Any]
    prev_hash: str
    hash: str = field(default="")


class AuditLogger:
    """Hash-chained audit emitter. One instance per service."""

    def __init__(self, service_name: str) -> None:
        self._service = service_name
        self._lock = threading.Lock()
        # Per-pod chain init — seeded with hostname + pid + start ts so chains
        # from restarts are distinct. The previous chain's last hash is
        # archived in storage (QRadar/Loki) for forensic continuity.
        seed = f"{os.uname().nodename}:{os.getpid()}:{time.time_ns()}".encode()
        self._prev_hash = hashlib.sha256(seed).hexdigest()

    def emit(
        self,
        event: str,
        *,
        outcome: str = "success",
        actor: str | None = None,
        resource: str | None = None,
        request_id: str | None = None,
        **attrs: Any,
    ) -> AuditRecord:
        with self._lock:
            rec = AuditRecord(
                ts=time.time(),
                service=self._service,
                event=event,
                actor=actor,
                resource=resource,
                outcome=outcome,
                request_id=request_id,
                attrs=attrs,
                prev_hash=self._prev_hash,
            )
            body = json.dumps(asdict(rec), sort_keys=True, separators=(",", ":")).encode()
            rec.hash = hashlib.sha256(body).hexdigest()
            self._prev_hash = rec.hash
            _LOG.info("audit", **asdict(rec))
            return rec
