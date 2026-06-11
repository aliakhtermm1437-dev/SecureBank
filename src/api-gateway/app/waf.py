"""Tiny in-process WAF — pattern-based deny-list. NOT a substitute for a real
WAF (Modsecurity / Cloudflare) but adds a defense-in-depth layer.
"""
from __future__ import annotations

import re

# Common, cheap detections. Real WAFs use OWASP CRS — see Cloudflare/modsec rules.
_PATTERNS = [
    re.compile(r"(?i)\b(union|select|insert|update|delete|drop)\b\s+\b(from|into|table)\b"),
    re.compile(r"(?i)<\s*script\b[^>]*>"),
    re.compile(r"(?i)javascript:"),
    re.compile(r"(?i)\bor\s+1\s*=\s*1\b"),
    re.compile(r"(?i)\.\./\.\."),
    re.compile(r"\x00"),  # null byte
    re.compile(r"(?i)\bxp_cmdshell\b"),
    re.compile(r"(?i)<\s*iframe\b"),
    re.compile(r"(?i)on(load|error|click)\s*="),
]


def looks_malicious(s: str) -> bool:
    if not s:
        return False
    for p in _PATTERNS:
        if p.search(s):
            return True
    return False


def scan(values: list[str]) -> str | None:
    for v in values:
        if looks_malicious(v):
            return v
    return None
