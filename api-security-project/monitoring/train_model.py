"""Train IsolationForest + RandomForestClassifier on labelled synthetic traffic.

Feature vector (13 dimensions):
  0  method           0=GET 1=POST 2=PUT 3=DELETE 4=PATCH
  1  path_depth       number of non-empty path segments
  2  has_auth         0/1
  3  status_code      integer HTTP status
  4  response_ms      float milliseconds
  5  hour             0-23
  6  is_admin_path    0/1
  7  is_debug_path    0/1
  8  is_4xx           0/1 (client error)
  9  bola_suspected   0/1
  10 path_length      number of characters in the path
  11 has_special_chars 0/1 (path contains ; | < > ' " % .. $ ` — injection signals)
  12 is_5xx           0/1 (server error — often indicates a payload broke something)

Two models are produced:
  /data/model.joblib      IsolationForest  (unsupervised, trained on normal only)
  /data/rf_model.joblib   RandomForest     (supervised,   trained on labelled data)

Labelled dataset saved (for review) to:
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
    "method", "path_depth", "has_auth", "status_code", "response_ms", "hour",
    "is_admin_path", "is_debug_path", "is_4xx", "bola_suspected",
    "path_length", "has_special_chars", "is_5xx",
]

ATTACK_LABELS = {
    0:  "normal",
    1:  "bola",
    2:  "jwt_bypass",
    3:  "admin_access",
    4:  "debug_access",
    5:  "sql_injection",
    6:  "rate_abuse",
    7:  "path_traversal",
    8:  "ssrf",
    9:  "command_injection",
    10: "xxe",
    11: "shadow_api",
}


def _row(method, depth, has_auth, status, resp_ms, hour,
         is_admin, is_debug, bola, path_len, special):
    """Build a 13-feature row, deriving is_4xx / is_5xx from status."""
    is_4xx = 1 if 400 <= status < 500 else 0
    is_5xx = 1 if status >= 500 else 0
    return [method, depth, has_auth, status, resp_ms, hour,
            is_admin, is_debug, is_4xx, bola, path_len, special, is_5xx]


# ── Sample generators ──────────────────────────────────────────────────────────

def _normal(rng, n=3000):
    rows = []
    for _ in range(n):
        method   = int(rng.choice([0, 1, 2, 3, 4], p=[0.55, 0.25, 0.10, 0.07, 0.03]))
        depth    = int(rng.integers(1, 5))
        has_auth = int(rng.choice([0, 1], p=[0.25, 0.75]))
        status   = int(rng.choice([200, 201, 204, 400, 401, 404, 422],
                                   p=[0.66, 0.08, 0.05, 0.05, 0.05, 0.06, 0.05]))
        resp_ms  = float(rng.exponential(90))
        hour     = int(rng.integers(0, 24))
        path_len = int(depth * rng.integers(5, 12))
        rows.append((_row(method, depth, has_auth, status, resp_ms, hour,
                           0, 0, 0, path_len, 0), 0, "normal"))
    return rows


def _attacks(rng):
    rows = []

    def add(n, label_id, label_name, fn):
        for _ in range(n):
            rows.append((fn(), label_id, label_name))

    # 1 BOLA — authenticated request to another user's resource (looks normal)
    add(280, 1, "bola", lambda: _row(
        0, int(rng.integers(2, 4)), 1,
        int(rng.choice([200, 403], p=[0.65, 0.35])),
        float(rng.exponential(80)), int(rng.integers(0, 24)),
        0, 0, 1, int(rng.integers(8, 20)), 0))

    # 2 JWT bypass — unauthenticated probes of protected endpoints
    add(240, 2, "jwt_bypass", lambda: _row(
        int(rng.choice([0, 1])), 2, 0,
        int(rng.choice([200, 401, 403], p=[0.35, 0.40, 0.25])),
        float(rng.uniform(10, 120)), int(rng.integers(0, 24)),
        0, 0, 0, int(rng.integers(10, 30)), 0))

    # 3 Admin path probing
    add(240, 3, "admin_access", lambda: _row(
        0, int(rng.integers(2, 4)), int(rng.choice([0, 1])),
        int(rng.choice([401, 403, 200], p=[0.40, 0.40, 0.20])),
        float(rng.exponential(70)), int(rng.integers(0, 24)),
        1, 0, 0, int(rng.integers(10, 25)), 0))

    # 4 Debug endpoint access
    add(180, 4, "debug_access", lambda: _row(
        0, 2, 0,
        int(rng.choice([200, 404], p=[0.55, 0.45])),
        float(rng.exponential(60)), int(rng.integers(0, 24)),
        0, 1, 0, int(rng.integers(8, 18)), 0))

    # 5 SQL injection — special chars, 400/500 responses
    add(260, 5, "sql_injection", lambda: _row(
        int(rng.choice([0, 1])), int(rng.integers(1, 4)), int(rng.choice([0, 1])),
        int(rng.choice([400, 500, 200], p=[0.45, 0.30, 0.25])),
        float(rng.exponential(120)), int(rng.integers(0, 24)),
        0, 0, 0, int(rng.integers(25, 70)), 1))

    # 6 Rate abuse — burst of rapid requests, many 429
    add(280, 6, "rate_abuse", lambda: _row(
        1, 2, 0,
        int(rng.choice([429, 401, 200], p=[0.55, 0.25, 0.20])),
        float(rng.uniform(3, 35)), int(rng.integers(0, 24)),
        0, 0, 0, int(rng.integers(8, 18)), 0))

    # 7 Path traversal — long paths, special chars, 404/400
    add(200, 7, "path_traversal", lambda: _row(
        0, int(rng.integers(4, 9)), int(rng.choice([0, 1])),
        int(rng.choice([404, 400, 200], p=[0.55, 0.25, 0.20])),
        float(rng.exponential(80)), int(rng.integers(0, 24)),
        0, 0, 0, int(rng.integers(30, 90)), 1))

    # 8 SSRF — URL in params, longer path, 200/500
    add(180, 8, "ssrf", lambda: _row(
        int(rng.choice([0, 1])), int(rng.integers(1, 4)), int(rng.choice([0, 1])),
        int(rng.choice([200, 500, 400], p=[0.45, 0.35, 0.20])),
        float(rng.uniform(50, 400)), int(rng.integers(0, 24)),
        0, 0, 0, int(rng.integers(40, 110)), 1))

    # 9 Command injection — shell metachars, 500/400
    add(180, 9, "command_injection", lambda: _row(
        int(rng.choice([0, 1])), int(rng.integers(1, 4)), int(rng.choice([0, 1])),
        int(rng.choice([500, 400, 200], p=[0.45, 0.35, 0.20])),
        float(rng.exponential(140)), int(rng.integers(0, 24)),
        0, 0, 0, int(rng.integers(20, 60)), 1))

    # 10 XXE — POST XML, 200/400/500, special chars (<)
    add(150, 10, "xxe", lambda: _row(
        1, int(rng.integers(1, 4)), int(rng.choice([0, 1])),
        int(rng.choice([200, 400, 500], p=[0.35, 0.35, 0.30])),
        float(rng.uniform(40, 300)), int(rng.integers(0, 24)),
        0, 0, 0, int(rng.integers(30, 80)), 1))

    # 11 Shadow API — undocumented endpoints, 200, looks almost normal
    add(160, 11, "shadow_api", lambda: _row(
        int(rng.choice([0, 1])), int(rng.integers(2, 4)), int(rng.choice([0, 1])),
        int(rng.choice([200, 403], p=[0.70, 0.30])),
        float(rng.exponential(85)), int(rng.integers(0, 24)),
        0, 0, 0, int(rng.integers(8, 22)), 0))

    return rows


# ── Dataset export ─────────────────────────────────────────────────────────────

def save_csv(normal_rows, attack_rows, path):
    header   = FEATURE_NAMES + ["label_id", "label_name"]
    all_rows = normal_rows + attack_rows
    idx      = np.random.default_rng(99).permutation(len(all_rows))
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for i in idx:
            feats, lid, lname = all_rows[i]
            w.writerow([round(v, 3) for v in feats] + [lid, lname])
    print(f"\nDataset saved  → {path}")
    print(f"  Normal rows  : {len(normal_rows)}")
    counts = {}
    for _, _, lname in attack_rows:
        counts[lname] = counts.get(lname, 0) + 1
    print(f"  Attack rows  : {len(attack_rows)}  across {len(counts)} categories")
    for lname, cnt in sorted(counts.items()):
        print(f"    {lname:<20} {cnt}")
    print(f"  Total rows   : {len(all_rows)}")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs(os.path.dirname(IF_MODEL_PATH), exist_ok=True)
    rng = np.random.default_rng(42)

    normal_rows = _normal(rng, 3000)
    attack_rows = _attacks(rng)
    save_csv(normal_rows, attack_rows, DATASET_PATH)

    normal_X = np.array([r[0] for r in normal_rows], dtype=float)
    attack_X = np.array([r[0] for r in attack_rows], dtype=float)
    X_all    = np.vstack([normal_X, attack_X])
    y_all    = np.array([0] * len(normal_rows) + [1] * len(attack_rows))

    # ── IsolationForest (unsupervised — normal traffic only) ───────────────────
    print(f"\nTraining IsolationForest on {len(normal_X)} normal samples…")
    iso = IsolationForest(n_estimators=250, contamination=0.04, random_state=42)
    iso.fit(normal_X)
    joblib.dump(iso, IF_MODEL_PATH)
    print(f"IsolationForest saved  → {IF_MODEL_PATH}")

    # ── RandomForestClassifier (supervised — full labelled set) ────────────────
    print(f"\nTraining RandomForestClassifier on {len(X_all)} labelled samples…")
    X_tr, X_te, y_tr, y_te = train_test_split(
        X_all, y_all, test_size=0.20, random_state=42, stratify=y_all
    )
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=None, min_samples_leaf=2,
        random_state=42, class_weight="balanced", n_jobs=-1
    )
    rf.fit(X_tr, y_tr)
    joblib.dump(rf, RF_MODEL_PATH)
    print(f"RandomForest saved     → {RF_MODEL_PATH}")

    y_pred = rf.predict(X_te)
    print("\n── Classification Report ──────────────────────────────────────────")
    print(classification_report(y_te, y_pred, target_names=["Normal", "Attack"], digits=4))

    cm = confusion_matrix(y_te, y_pred)
    print("── Confusion Matrix ───────────────────────────────────────────────")
    print(f"          Predicted Normal   Predicted Attack")
    print(f"  Actual Normal    TN={cm[0,0]:<6}  FP={cm[0,1]}")
    print(f"  Actual Attack    FN={cm[1,0]:<6}  TP={cm[1,1]}")
    acc = (cm[0, 0] + cm[1, 1]) / cm.sum()
    print(f"\n  Accuracy            : {acc:.4f}")
    print(f"  False Positive Rate : {cm[0,1] / (cm[0,0]+cm[0,1]):.4f}")
    print(f"  False Negative Rate : {cm[1,0] / (cm[1,0]+cm[1,1]):.4f}")

    print("\n── Feature Importance ──────────────────────────────────────────────")
    for fname, imp in sorted(zip(FEATURE_NAMES, rf.feature_importances_), key=lambda x: -x[1]):
        print(f"  {fname:<20} {'█' * int(imp * 50):<50} {imp:.4f}")
    print("──────────────────────────────────────────────────────────────────")
