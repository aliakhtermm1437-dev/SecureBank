"""Structured JSON logging with redaction of PII / secrets.

All services share this configuration so QRadar/Loki can parse one schema.
Redaction is **defense-in-depth** — the application is also obliged not to log
sensitive material in the first place, but if it slips through we mask it.
"""
from __future__ import annotations

import logging
import re
import sys
from typing import Any

import structlog
from pythonjsonlogger import jsonlogger

# Patterns we always redact, even if a dev accidentally logs them.
_REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?<!\d)\d{13}(?!\d)"), "<CNIC_REDACTED>"),
    (re.compile(r"(?<!\d)\d{16}(?!\d)"), "<PAN_REDACTED>"),
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "<EMAIL_REDACTED>"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "<JWT_REDACTED>"),
    (re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*\S+"), r"\1=<REDACTED>"),
]


class RedactingFilter(logging.Filter):
    """Apply :data:`_REDACT_PATTERNS` to every log record's message + args."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        for pat, repl in _REDACT_PATTERNS:
            msg = pat.sub(repl, msg)
        record.msg = msg
        record.args = ()
        return True


def configure_logging(level: str = "INFO", json_logs: bool = True) -> None:
    """Idempotent global logging setup."""
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.addFilter(RedactingFilter())
    if json_logs:
        fmt = jsonlogger.JsonFormatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            rename_fields={"asctime": "ts", "levelname": "level", "name": "logger"},
        )
    else:
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s — %(message)s")
    handler.setFormatter(fmt)
    root.addHandler(handler)

    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level)),
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None, **bind: Any) -> structlog.stdlib.BoundLogger:
    logger = structlog.get_logger(name)
    if bind:
        logger = logger.bind(**bind)
    return logger
