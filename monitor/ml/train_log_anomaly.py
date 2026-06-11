"""Train a simple autoencoder over event-count features.

Input: CSV with columns (timestamp, service, event, status, count).
Output: a joblib pickle containing a scikit-learn StandardScaler + Keras model
        (or a NumPy fallback when TF is missing).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler


def featurise(df: pd.DataFrame) -> tuple[np.ndarray, list[str]]:
    pivot = df.pivot_table(
        index="window",
        columns=["service", "event", "status"],
        values="count",
        fill_value=0,
        aggfunc="sum",
    )
    columns = ["|".join(map(str, c)) for c in pivot.columns]
    return pivot.to_numpy().astype("float32"), columns


def train_autoencoder(X: np.ndarray) -> dict:
    try:
        import tensorflow as tf
        from tensorflow.keras import layers, models

        scaler = StandardScaler().fit(X)
        Xs = scaler.transform(X)
        inp = layers.Input(shape=(X.shape[1],))
        z = layers.Dense(64, activation="relu")(inp)
        z = layers.Dense(16, activation="relu")(z)
        out = layers.Dense(X.shape[1], activation="linear")(z)
        m = models.Model(inp, out)
        m.compile(optimizer="adam", loss="mse")
        m.fit(Xs, Xs, epochs=50, batch_size=32, verbose=0)
        return {"type": "tf", "scaler": scaler, "model_weights": m.get_weights(), "input_dim": X.shape[1]}
    except Exception:
        # Fallback: just record means & stddevs for a simple z-score detector.
        return {
            "type": "stat",
            "mean": X.mean(axis=0),
            "std":  X.std(axis=0) + 1e-6,
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    df = pd.read_csv(args.input, parse_dates=["timestamp"])
    df["window"] = df["timestamp"].dt.floor("1min")
    X, cols = featurise(df)
    if len(X) < 20:
        print("Not enough windows to train", file=sys.stderr)
        return 1
    pkg = train_autoencoder(X) | {"columns": cols}
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pkg, args.output)
    print(f"Wrote model to {args.output} (windows={len(X)}, dim={X.shape[1]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
