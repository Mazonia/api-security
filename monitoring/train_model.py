"""Train IsolationForest + RandomForestClassifier on labelled synthetic traffic.

Feature vector (10 dimensions):
  0  method          0=GET 1=POST 2=PUT 3=DELETE 4=PATCH
  1  path_depth      number of non-empty path segments
  2  has_auth        0/1
  3  status_code     integer HTTP status
  4  response_ms     float milliseconds
  5  hour            0-23
  6  is_admin_path   0/1
  7  is_debug_path   0/1
  8  is_error        0/1 (status >= 400)
  9  bola_suspected  0/1

Two models are produced:
  /data/model.joblib      IsolationForest  (unsupervised, trained on normal only)
  /data/rf_model.joblib   RandomForest     (supervised,   trained on labelled data)

A human-readable labelled dataset is saved to:
  /data/training_dataset.csv
"""
import csv
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

IF_MODEL_PATH = "/data/model.joblib"
RF_MODEL_PATH = "/data/rf_model.joblib"
DATASET_PATH  = "/data/training_dataset.csv"

FEATURE_NAMES = [
    "method", "path_depth", "has_auth", "status_code",
    "response_ms", "hour", "is_admin_path", "is_debug_path",
    "is_error", "bola_suspected",
]

ATTACK_LABELS = {
    0: "normal",
    1: "bola",
    2: "jwt_bypass",
    3: "admin_access",
    4: "debug_access",
    5: "sql_injection",
    6: "rate_abuse",
    7: "path_traversal",
}


# ── Sample generators ──────────────────────────────────────────────────────────

def _normal(rng, n=2000):
    rows = []
    for _ in range(n):
        method   = int(rng.choice([0, 1, 2, 3, 4], p=[0.55, 0.25, 0.10, 0.07, 0.03]))
        depth    = int(rng.integers(1, 5))
        has_auth = int(rng.choice([0, 1], p=[0.25, 0.75]))
        status   = int(rng.choice([200, 201, 204, 400, 401, 404, 422],
                                   p=[0.65, 0.08, 0.05, 0.06, 0.05, 0.06, 0.05]))
        resp_ms  = float(rng.exponential(90))
        hour     = int(rng.integers(0, 24))
        rows.append((
            [method, depth, has_auth, status, resp_ms, hour, 0, 0,
             1 if status >= 400 else 0, 0],
            0, "normal",
        ))
    return rows


def _attacks(rng):
    rows = []

    # BOLA — authenticated request to another user's resource
    for _ in range(250):
        rows.append((
            [0, int(rng.integers(2, 4)), 1,
             int(rng.choice([200, 403], p=[0.65, 0.35])),
             float(rng.exponential(80)), int(rng.integers(0, 24)),
             0, 0, 0, 1],
            1, "bola",
        ))

    # JWT bypass — repeated unauthenticated probes to protected endpoints
    for _ in range(200):
        rows.append((
            [1, 2, 0,
             int(rng.choice([200, 401, 403], p=[0.35, 0.40, 0.25])),
             float(rng.uniform(10, 120)), int(rng.integers(0, 24)),
             0, 0, 1, 0],
            2, "jwt_bypass",
        ))

    # Admin path probing — accessing /admin/* without privilege
    for _ in range(200):
        rows.append((
            [0, int(rng.integers(2, 4)), int(rng.choice([0, 1])),
             int(rng.choice([401, 403, 200], p=[0.40, 0.40, 0.20])),
             float(rng.exponential(70)), int(rng.integers(0, 24)),
             1, 0, 1, 0],
            3, "admin_access",
        ))

    # Debug endpoint access — /debug/config, /config, /env
    for _ in range(150):
        rows.append((
            [0, 2, 0,
             int(rng.choice([200, 404], p=[0.55, 0.45])),
             float(rng.exponential(60)), int(rng.integers(0, 24)),
             0, 1, 0, 0],
            4, "debug_access",
        ))

    # SQL injection — malformed input causing 400/500 responses
    for _ in range(200):
        rows.append((
            [int(rng.choice([0, 1])), int(rng.integers(1, 4)),
             int(rng.choice([0, 1])),
             int(rng.choice([400, 500, 200], p=[0.45, 0.30, 0.25])),
             float(rng.exponential(120)), int(rng.integers(0, 24)),
             0, 0, 1, 0],
            5, "sql_injection",
        ))

    # Rate-limit abuse — burst of rapid repeated requests
    for _ in range(250):
        rows.append((
            [1, 2, 0,
             int(rng.choice([429, 401, 200], p=[0.55, 0.25, 0.20])),
             float(rng.uniform(5, 40)), int(rng.integers(0, 24)),
             0, 0, 1, 0],
            6, "rate_abuse",
        ))

    # Path traversal — deep path attempts with error responses
    for _ in range(150):
        rows.append((
            [0, int(rng.integers(4, 9)), int(rng.choice([0, 1])),
             int(rng.choice([404, 400, 200], p=[0.55, 0.25, 0.20])),
             float(rng.exponential(80)), int(rng.integers(0, 24)),
             0, 0, 1, 0],
            7, "path_traversal",
        ))

    return rows


# ── Dataset export ─────────────────────────────────────────────────────────────

def save_csv(normal_rows, attack_rows, path):
    header = FEATURE_NAMES + ["label_id", "label_name"]
    all_rows = normal_rows + attack_rows
    rng2 = np.random.default_rng(99)
    idx = rng2.permutation(len(all_rows))  # shuffle for presentation

    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for i in idx:
            features, label_id, label_name = all_rows[i]
            writer.writerow([round(v, 3) for v in features] + [label_id, label_name])

    print(f"\nDataset saved  → {path}")
    print(f"  Normal rows  : {len(normal_rows)}")
    print(f"  Attack rows  : {len(attack_rows)}")
    label_counts = {}
    for _, lid, lname in attack_rows:
        label_counts[lname] = label_counts.get(lname, 0) + 1
    for lname, cnt in label_counts.items():
        print(f"    {lname:<20} {cnt}")
    print(f"  Total rows   : {len(all_rows)}")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs(os.path.dirname(IF_MODEL_PATH), exist_ok=True)
    rng = np.random.default_rng(42)

    normal_rows = _normal(rng, 2000)
    attack_rows = _attacks(rng)

    # Save labelled CSV (for supervisor review)
    save_csv(normal_rows, attack_rows, DATASET_PATH)

    normal_X = np.array([r[0] for r in normal_rows], dtype=float)
    attack_X = np.array([r[0] for r in attack_rows], dtype=float)
    X_all    = np.vstack([normal_X, attack_X])
    y_all    = np.array([0] * len(normal_rows) + [1] * len(attack_rows))

    # ── IsolationForest (anomaly detection — trained on normal traffic only) ───
    print(f"\nTraining IsolationForest on {len(normal_X)} normal samples…")
    iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
    iso.fit(normal_X)
    joblib.dump(iso, IF_MODEL_PATH)
    print(f"IsolationForest saved  → {IF_MODEL_PATH}")

    # ── RandomForestClassifier (supervised — trained on full labelled set) ─────
    print(f"\nTraining RandomForestClassifier on {len(X_all)} labelled samples…")
    X_tr, X_te, y_tr, y_te = train_test_split(
        X_all, y_all, test_size=0.20, random_state=42, stratify=y_all
    )
    rf = RandomForestClassifier(
        n_estimators=200, random_state=42, class_weight="balanced"
    )
    rf.fit(X_tr, y_tr)
    joblib.dump(rf, RF_MODEL_PATH)
    print(f"RandomForest saved     → {RF_MODEL_PATH}")

    y_pred = rf.predict(X_te)

    print("\n── Classification Report ──────────────────────────────────────────")
    print(classification_report(y_te, y_pred, target_names=["Normal", "Attack"],
                                 digits=4))

    cm = confusion_matrix(y_te, y_pred)
    print("── Confusion Matrix ───────────────────────────────────────────────")
    print(f"          Predicted Normal   Predicted Attack")
    print(f"  Actual Normal    TN={cm[0,0]:<6}  FP={cm[0,1]}")
    print(f"  Actual Attack    FN={cm[1,0]:<6}  TP={cm[1,1]}")
    accuracy = (cm[0, 0] + cm[1, 1]) / cm.sum()
    print(f"\n  Accuracy : {accuracy:.4f}")
    print(f"  False Positive Rate : {cm[0,1] / (cm[0,0]+cm[0,1]):.4f}")
    print(f"  False Negative Rate : {cm[1,0] / (cm[1,0]+cm[1,1]):.4f}")

    feat_imp = sorted(zip(FEATURE_NAMES, rf.feature_importances_), key=lambda x: -x[1])
    print("\n── Feature Importance (RandomForest) ──────────────────────────────")
    for fname, imp in feat_imp:
        bar = "█" * int(imp * 50)
        print(f"  {fname:<22} {bar:<50} {imp:.4f}")
    print("──────────────────────────────────────────────────────────────────")
