"""Tiny FastAPI scorer for the log-anomaly model."""
from __future__ import annotations

import os

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

MODEL_PATH = os.getenv("LOG_ANOM_MODEL", "/models/log_anomaly.joblib")

app = FastAPI(title="SecureBank Log Anomaly")
_MODEL = None


def model():
    global _MODEL
    if _MODEL is None:
        _MODEL = joblib.load(MODEL_PATH)
    return _MODEL


class ScoreIn(BaseModel):
    features: dict[str, float]


class ScoreOut(BaseModel):
    score: float
    anomaly: bool


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/score", response_model=ScoreOut)
def score(payload: ScoreIn) -> ScoreOut:
    m = model()
    cols = m["columns"]
    x = np.array([[payload.features.get(c, 0.0) for c in cols]], dtype="float32")
    if m["type"] == "stat":
        z = (x - m["mean"]) / m["std"]
        s = float(np.mean(np.abs(z)))
    else:
        try:
            import tensorflow as tf
            from tensorflow.keras import layers, models
        except Exception as e:
            raise HTTPException(500, "tensorflow not available") from e
        s = 0.0  # the loaded model needs full reconstruction in real prod
    return ScoreOut(score=s, anomaly=bool(s > 3.0))
