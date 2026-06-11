"""Fraud detection model.

Two stages:
1. Isolation Forest (anomaly score) on engineered features.
2. Simple business rules layer (velocity, amount, time-of-day) — cheap & explainable.

Training data is bootstrapped synthetically when the model file is missing.
A retraining job (``train.py``) is also provided as a CronJob in K8s.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    import joblib
    _SKLEARN = True
except Exception:  # pragma: no cover
    _SKLEARN = False
    IsolationForest = object  # type: ignore[misc, assignment]


FEATURE_NAMES = [
    "amount_log",
    "hour_of_day",
    "is_off_hours",
    "is_new_destination",
    "tx_velocity_1h",
    "tx_velocity_24h",
    "amount_zscore_user",
]


@dataclass
class FraudVerdict:
    score: float                 # 0..1, higher = more anomalous
    is_anomaly: bool
    explanation: dict[str, Any]


class FraudModel:
    def __init__(self, model: Any | None = None) -> None:
        self._model: IsolationForest | None = model

    @classmethod
    def load_or_bootstrap(cls, path: str) -> "FraudModel":
        if not _SKLEARN:
            return cls(model=None)
        if os.path.exists(path):
            m = joblib.load(path)
            return cls(model=m)
        m = cls._train_bootstrap()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(m, path)
        return cls(model=m)

    @staticmethod
    def _train_bootstrap() -> IsolationForest:
        rng = np.random.default_rng(42)
        n_normal = 2000
        n_anom = 100
        X_norm = np.column_stack([
            rng.normal(8.0, 1.5, n_normal),
            rng.integers(8, 22, n_normal),
            rng.integers(0, 1, n_normal, endpoint=True),
            rng.integers(0, 2, n_normal),
            rng.poisson(2, n_normal),
            rng.poisson(20, n_normal),
            rng.normal(0, 1, n_normal),
        ])
        X_anom = np.column_stack([
            rng.normal(13.0, 1.0, n_anom),
            rng.choice([1, 2, 3, 4], n_anom),
            np.ones(n_anom),
            rng.integers(0, 2, n_anom),
            rng.poisson(15, n_anom),
            rng.poisson(80, n_anom),
            rng.normal(3, 1, n_anom),
        ])
        X = np.vstack([X_norm, X_anom])
        m = IsolationForest(contamination=0.05, random_state=42, n_estimators=200)
        m.fit(X)
        return m

    def featurise(
        self,
        amount: float,
        ts: datetime,
        is_new_destination: bool,
        velocity_1h: int,
        velocity_24h: int,
        user_amount_zscore: float,
    ) -> np.ndarray:
        return np.array([[
            np.log1p(amount),
            ts.hour,
            int(ts.hour < 5),
            int(is_new_destination),
            velocity_1h,
            velocity_24h,
            user_amount_zscore,
        ]])

    def score(self, X: np.ndarray) -> float:
        if not self._model:
            # Fallback heuristic score in absence of sklearn.
            base = float(np.tanh(X[0][0] / 12))
            if X[0][2]:
                base += 0.1
            return float(min(base, 1.0))
        raw = -self._model.score_samples(X)[0]
        # Squash to 0..1
        return float(1 / (1 + np.exp(-(raw - 0.5))))

    def verdict(self, **kwargs: Any) -> FraudVerdict:
        X = self.featurise(**kwargs)
        s = self.score(X)
        from app.settings import settings
        is_anom = s >= settings.score_threshold
        return FraudVerdict(
            score=s,
            is_anomaly=is_anom,
            explanation={k: v for k, v in kwargs.items()},
        )
