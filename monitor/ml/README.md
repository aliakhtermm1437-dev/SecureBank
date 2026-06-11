# AI/ML — SecureBank Anomaly Detection

Two models work together:

1. **Transaction-level anomaly** (already in `src/fraud-detection-service`) —
   Isolation Forest on engineered features (amount, velocity, time-of-day,
   recipient novelty, z-score).
2. **Log-stream anomaly** (this folder) — Autoencoder over rolling-window
   counts of (service, event, status) tuples drawn from Loki.

## Files

- `train_log_anomaly.py` — fits the autoencoder from a Loki time range.
- `serve_log_anomaly.py` — minimal FastAPI service exposing `/score`.
- `Dockerfile` — distroless ML server (CPU only).
- `model_registry.md` — versioning policy.

## Pipeline

```
Loki → daily export (JSON) → feature extractor → autoencoder fit → joblib + sha256
                                                           ↓
                                                   model_registry.md update
                                                           ↓
                                                   Helm value bump → rollout
```

## Drift / Evasion Notes (MITRE T1485)

The transaction model now incorporates rolling 24h velocity and recipient
diversity (added after observing the "mouse-trap" evasion pattern documented
in `docs/06_red_blue_team.md` §2.11). Population stability index (PSI) is
computed over the last 7-day feature distribution; alert on PSI > 0.2.
