"""Train IsolationForest on synthetic normal traffic and save the model."""
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_PATH = "/data/model.joblib"


def generate_normal(n: int = 2000) -> np.ndarray:
    rng = np.random.default_rng(42)
    rows = []
    for _ in range(n):
        method   = rng.choice([0, 1, 2, 3], p=[0.60, 0.25, 0.10, 0.05])
        depth    = rng.integers(1, 4)
        has_auth = rng.choice([0, 1], p=[0.20, 0.80])
        status   = rng.choice([200, 201, 400, 401, 404, 422],
                               p=[0.70, 0.10, 0.05, 0.05, 0.05, 0.05])
        resp_ms  = float(rng.exponential(80))
        hour     = int(rng.integers(0, 24))
        # normal traffic never hits /admin or /debug and has no bola_suspected
        rows.append([method, depth, has_auth, status, resp_ms, hour, 0, 0,
                     1 if status >= 400 else 0, 0])
    return np.array(rows, dtype=float)


if __name__ == "__main__":
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    print("Generating synthetic normal traffic…")
    X = generate_normal(2000)
    print(f"Training IsolationForest on {len(X)} samples…")
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X)
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved → {MODEL_PATH}")
