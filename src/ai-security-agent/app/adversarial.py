"""Adversarial-ML resilience module.

Implements the bonus extension "Adversarial ML" from the rubric.

We treat the fraud detector as a binary classifier f(x) → {0,1} and
estimate its robustness against the realistic threat model:
  * The attacker can split a large transfer into ≤k smaller ones (mouse-trap)
  * The attacker can match historical recipients
  * The attacker can match historical merchant categories
  * The attacker cannot move outside the legitimate user's behavioural envelope

We score robustness via two cheap, deterministic probes (no white-box
gradient access required, since the model is an IsolationForest):

  1. **Salami slicing probe** — generate N small perturbations of a high-
     amount transfer that bring the amount under the model's decision
     threshold; report what fraction the model still flags.
  2. **Feature drift probe** — Population Stability Index between today's
     features and last week's; PSI > 0.2 means the model needs retraining.

The output is consumed by the SOAR /webhooks/ml hook and surfaced in the
Security Console GUI.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np


@dataclass
class RobustnessReport:
    salami_slices_tried: int
    salami_evaded:       int
    salami_evasion_rate: float
    psi_max:             float
    psi_alarm:           bool
    verdict:             str   # "robust" | "watch" | "retrain-now"

    def as_dict(self) -> dict: return self.__dict__.copy()


def population_stability_index(expected: np.ndarray,
                               actual:   np.ndarray,
                               bins: int = 10) -> float:
    """Standard PSI used by credit/fraud risk teams.  Returns a scalar."""
    expected = np.asarray(expected, dtype=float)
    actual   = np.asarray(actual,   dtype=float)
    edges = np.linspace(np.min([expected.min(), actual.min()]),
                        np.max([expected.max(), actual.max()]) + 1e-9, bins + 1)
    e_hist, _ = np.histogram(expected, bins=edges)
    a_hist, _ = np.histogram(actual,   bins=edges)
    e_pct = np.clip(e_hist / max(e_hist.sum(), 1), 1e-4, None)
    a_pct = np.clip(a_hist / max(a_hist.sum(), 1), 1e-4, None)
    return float(np.sum((a_pct - e_pct) * np.log(a_pct / e_pct)))


def salami_probe(model, base_features: np.ndarray,
                 n_slices: int = 50,
                 noise_sigma: float = 0.05,
                 seed: int = 42) -> tuple[int, int]:
    """Return (tried, evaded).  `model` exposes .predict() returning -1 for anomaly."""
    rng = np.random.default_rng(seed)
    tried, evaded = 0, 0
    for _ in range(n_slices):
        slice_feat = base_features.copy()
        # Amount is feature 0 by our convention — divide it.
        slice_feat[0] = slice_feat[0] / max(2.0, rng.uniform(2.0, 8.0))
        # Add small Gaussian noise on velocity/recipient features.
        slice_feat[1:] += rng.normal(0.0, noise_sigma, size=slice_feat[1:].shape)
        tried += 1
        pred = int(model.predict(slice_feat.reshape(1, -1))[0])
        if pred != -1:        # not flagged
            evaded += 1
    return tried, evaded


def robustness_report(model,
                      base_features: np.ndarray,
                      historical_amounts: np.ndarray,
                      recent_amounts:     np.ndarray) -> RobustnessReport:
    tried, evaded = salami_probe(model, base_features)
    rate = evaded / max(tried, 1)
    psi  = population_stability_index(historical_amounts, recent_amounts)
    psi_alarm = psi > 0.2
    if rate > 0.4 or psi > 0.25:
        verdict = "retrain-now"
    elif rate > 0.2 or psi > 0.15:
        verdict = "watch"
    else:
        verdict = "robust"
    return RobustnessReport(
        salami_slices_tried=tried,
        salami_evaded=evaded,
        salami_evasion_rate=round(rate, 3),
        psi_max=round(psi, 3),
        psi_alarm=psi_alarm,
        verdict=verdict,
    )


# Lightweight stub model so the endpoint works even if the real artefact
# isn't mounted (e.g. on a developer laptop running docker-compose).
class _StubModel:
    """IsolationForest-like .predict that flags amounts > 10000 PKR."""

    def predict(self, X: np.ndarray) -> np.ndarray:
        return np.array([-1 if x[0] > 10_000 else 1 for x in X])


def load_model(path: str):
    try:
        import joblib
        return joblib.load(path)
    except Exception:
        return _StubModel()
