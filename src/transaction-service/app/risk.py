"""Cheap, deterministic in-line risk score.

A real model lives in fraud-detection-service; this one is a fast cheap gate
applied before we publish to Kafka, so we can require step-up MFA up-front for
risky moves (amount > threshold, new destination, off-hours, etc.).
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal


def step_up_required(amount: Decimal, threshold: int) -> bool:
    return amount >= Decimal(threshold)


def fast_score(amount: Decimal, src_first_tx_to_dst: bool, ts: datetime | None = None) -> float:
    score = 0.0
    if amount >= 10_000:
        score += 0.3
    if amount >= 100_000:
        score += 0.4
    if src_first_tx_to_dst:
        score += 0.2
    t = (ts or datetime.now(timezone.utc)).hour
    if t >= 0 and t < 5:
        score += 0.1
    return min(score, 1.0)
