"""CLI entrypoint used by the K8s CronJob ``fraud-retrain`` (nightly).

Reads labeled feedback from Postgres (or a CSV in dev) and refits the model.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="CSV with labeled features")
    ap.add_argument("--output", required=True, help="output joblib path")
    args = ap.parse_args()

    df = pd.read_csv(args.input)
    X = df[[
        "amount_log", "hour_of_day", "is_off_hours",
        "is_new_destination", "tx_velocity_1h",
        "tx_velocity_24h", "amount_zscore_user",
    ]].to_numpy()
    m = IsolationForest(contamination=0.05, random_state=42, n_estimators=200)
    m.fit(X)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(m, args.output)
    print(f"trained model on {len(df)} rows; saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
