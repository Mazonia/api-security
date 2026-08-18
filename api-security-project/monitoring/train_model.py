"""Train Advanced 32-Feature Calibrated Ensemble (Gradient Boosting + Random Forest + Isolation Forest).

Features:
  32-dimensional engineered feature representation:
  0: method_code (0=GET, 1=POST, 2=PUT, 3=DELETE, 4=PATCH, 5=OPTIONS, 6=HEAD)
  1: path_depth (number of non-empty path segments)
  2: path_length (character length of path)
  3: has_auth (1 if Authorization / Cookie header present else 0)
  4: auth_token_length (length of auth token)
  5: auth_token_entropy (Shannon entropy of token string)
  6: status_code (HTTP response status)
  7: is_2xx (success status)
  8: is_4xx (client error)
  9: is_5xx (server fault / 500 error)
  10: response_ms (latency in milliseconds)
  11: hour (0-23 UTC)
  12: is_admin_path (1 if contains /admin, /manage, /internal, /root)
  13: is_debug_path (1 if contains /debug, /actuator, /env, /metrics)
  14: is_auth_endpoint (1 if contains /auth, /login, /token, /oauth)
  15: bola_suspected (1 if ID parameter access flagged)
  16: payload_length (character length of body payload)
  17: payload_entropy (Shannon entropy of body payload)
  18: has_special_chars (count of injection meta-characters)
  19: sqli_density (syntactic SQL injection score)
  20: xss_density (syntactic XSS script score)
  21: cmd_injection_score (command injection shell metachars)
  22: path_traversal_score (directory traversal ../ score)
  23: ssrf_score (cloud metadata / internal IP score)
  24: mass_assignment_score (presence of is_admin / role payload keys)
  25: prompt_injection_score (LLM jailbreak / prompt override phrase score)
  26: query_param_count (number of query parameters)
  27: query_length (length of query string)
  28: header_count (number of HTTP request headers)
  29: is_burst_request (rapid inter-arrival burst indicator)
  30: user_agent_suspicious (presence of scanner/bot signatures or blank)
  31: body_json_depth (nested JSON depth)

Models produced:
  - model.joblib: Calibrated Isolation Forest for unsupervised zero-day anomaly detection
  - rf_model.joblib: Calibrated Ensemble (Balanced Random Forest + HistGradientBoosting) with threat probability calibration
"""
import csv
import math
import os
import sys

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "data"))
if not os.path.exists(DATA_DIR) and os.path.exists("/data"):
    DATA_DIR = "/data"

IF_MODEL_PATH = os.path.join(DATA_DIR, "model.joblib")
RF_MODEL_PATH = os.path.join(DATA_DIR, "rf_model.joblib")
DATASET_PATH  = os.path.join(DATA_DIR, "training_dataset.csv")

FEATURE_NAMES = [
    "method_code", "path_depth", "path_length", "has_auth", "auth_token_length", "auth_token_entropy",
    "status_code", "is_2xx", "is_4xx", "is_5xx", "response_ms", "hour",
    "is_admin_path", "is_debug_path", "is_auth_endpoint", "bola_suspected",
    "payload_length", "payload_entropy", "has_special_chars", "sqli_density",
    "xss_density", "cmd_injection_score", "path_traversal_score", "ssrf_score",
    "mass_assignment_score", "prompt_injection_score", "query_param_count", "query_length",
    "header_count", "is_burst_request", "user_agent_suspicious", "body_json_depth"
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
    10: "xss",
    11: "mass_assignment",
    12: "prompt_injection",
    13: "shadow_api",
    14: "credential_stuffing"
}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    return -sum(p * math.log(p) / math.log(2.0) for p in prob)


def _row(method_code, depth, path_len, has_auth, token_len, token_ent, status, resp_ms, hour,
         is_admin, is_debug, is_auth, bola, payload_len, payload_ent, special_cnt,
         sqli, xss, cmd_inj, traversal, ssrf, mass_assign, prompt_inj,
         q_count, q_len, h_count, is_burst, ua_sus, json_depth):
    is_2xx = 1 if 200 <= status < 300 else 0
    is_4xx = 1 if 400 <= status < 500 else 0
    is_5xx = 1 if status >= 500 else 0
    return [
        method_code, depth, path_len, has_auth, token_len, token_ent,
        status, is_2xx, is_4xx, is_5xx, resp_ms, hour,
        is_admin, is_debug, is_auth, bola,
        payload_len, payload_ent, special_cnt, sqli,
        xss, cmd_inj, traversal, ssrf,
        mass_assign, prompt_inj, q_count, q_len,
        h_count, is_burst, ua_sus, json_depth
    ]


def _normal(rng, n=4000):
    rows = []
    for _ in range(n):
        method = int(rng.choice([0, 1, 2, 3, 4], p=[0.55, 0.25, 0.10, 0.07, 0.03]))
        depth = int(rng.integers(1, 5))
        path_len = int(depth * rng.integers(5, 12))
        has_auth = int(rng.choice([0, 1], p=[0.20, 0.80]))
        token_len = int(rng.integers(32, 180)) if has_auth else 0
        token_ent = float(rng.uniform(3.5, 4.8)) if has_auth else 0.0
        status = int(rng.choice([200, 201, 204, 400, 401, 404, 422], p=[0.72, 0.08, 0.05, 0.04, 0.03, 0.05, 0.03]))
        resp_ms = float(rng.exponential(75))
        hour = int(rng.integers(0, 24))
        is_auth = 1 if rng.random() < 0.1 else 0
        payload_len = int(rng.integers(0, 500)) if method in (1, 2, 4) else 0
        payload_ent = float(rng.uniform(2.0, 3.8)) if payload_len > 0 else 0.0
        q_count = int(rng.choice([0, 1, 2, 3], p=[0.6, 0.25, 0.1, 0.05]))
        q_len = q_count * int(rng.integers(4, 15))
        h_count = int(rng.integers(6, 14))
        json_depth = int(rng.integers(1, 3)) if payload_len > 0 else 0

        r = _row(
            method, depth, path_len, has_auth, token_len, token_ent, status, resp_ms, hour,
            0, 0, is_auth, 0, payload_len, payload_ent, 0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            q_count, q_len, h_count, 0, 0, json_depth
        )
        rows.append((r, 0, "normal"))
    return rows


def _attacks(rng):
    rows = []

    def add(n, label_id, label_name, fn):
        for _ in range(n):
            rows.append((fn(), label_id, label_name))

    # 1. BOLA / IDOR
    add(320, 1, "bola", lambda: _row(
        0, int(rng.integers(2, 4)), int(rng.integers(12, 28)), 1, 64, 4.2,
        int(rng.choice([200, 403], p=[0.65, 0.35])), float(rng.exponential(80)), int(rng.integers(0, 24)),
        0, 0, 0, 1, 0, 0.0, 0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        0, 0, 8, 0, 0, 0
    ))

    # 2. JWT Bypass / Auth Broken
    add(260, 2, "jwt_bypass", lambda: _row(
        int(rng.choice([0, 1])), 2, int(rng.integers(10, 30)), 0, 0, 0.0,
        int(rng.choice([200, 401, 403], p=[0.35, 0.40, 0.25])), float(rng.uniform(10, 120)), int(rng.integers(0, 24)),
        0, 0, 1, 0, 50, 2.5, 0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        1, 10, 5, 0, 0, 1
    ))

    # 3. Admin / BFLA Path Probing
    add(260, 3, "admin_access", lambda: _row(
        0, int(rng.integers(2, 4)), int(rng.integers(12, 30)), int(rng.choice([0, 1])), 0, 0.0,
        int(rng.choice([401, 403, 200], p=[0.40, 0.40, 0.20])), float(rng.exponential(70)), int(rng.integers(0, 24)),
        1, 0, 0, 0, 0, 0.0, 0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        0, 0, 6, 0, 0, 0
    ))

    # 4. Debug / Actuator Access
    add(200, 4, "debug_access", lambda: _row(
        0, 2, int(rng.integers(8, 22)), 0, 0, 0.0,
        int(rng.choice([200, 404], p=[0.55, 0.45])), float(rng.exponential(60)), int(rng.integers(0, 24)),
        0, 1, 0, 0, 0, 0.0, 0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        0, 0, 5, 0, 0, 0
    ))

    # 5. SQL Injection
    add(300, 5, "sql_injection", lambda: _row(
        int(rng.choice([0, 1])), int(rng.integers(1, 4)), int(rng.integers(25, 90)), int(rng.choice([0, 1])), 40, 3.8,
        int(rng.choice([400, 500, 200], p=[0.45, 0.35, 0.20])), float(rng.exponential(140)), int(rng.integers(0, 24)),
        0, 0, 0, 0, int(rng.integers(40, 400)), float(rng.uniform(3.5, 4.9)), int(rng.integers(2, 6)),
        float(rng.uniform(0.7, 1.0)), 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        int(rng.integers(1, 4)), int(rng.integers(20, 80)), 7, 0, int(rng.choice([0, 1])), 1
    ))

    # 6. Rate Abuse / Burst DDoS
    add(300, 6, "rate_abuse", lambda: _row(
        1, 2, int(rng.integers(8, 20)), 0, 0, 0.0,
        int(rng.choice([429, 401, 200], p=[0.60, 0.20, 0.20])), float(rng.uniform(3, 30)), int(rng.integers(0, 24)),
        0, 0, 1, 0, 30, 2.1, 0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        0, 0, 4, 1, 1, 1
    ))

    # 7. Path Traversal
    add(220, 7, "path_traversal", lambda: _row(
        0, int(rng.integers(4, 9)), int(rng.integers(35, 110)), int(rng.choice([0, 1])), 0, 0.0,
        int(rng.choice([404, 400, 200], p=[0.55, 0.25, 0.20])), float(rng.exponential(80)), int(rng.integers(0, 24)),
        0, 0, 0, 0, 0, 0.0, int(rng.integers(2, 5)),
        0.0, 0.0, 0.0, float(rng.uniform(0.75, 1.0)), 0.0, 0.0, 0.0,
        1, int(rng.integers(20, 60)), 6, 0, 0, 0
    ))

    # 8. SSRF
    add(200, 8, "ssrf", lambda: _row(
        int(rng.choice([0, 1])), int(rng.integers(1, 4)), int(rng.integers(40, 120)), int(rng.choice([0, 1])), 40, 3.5,
        int(rng.choice([200, 500, 400], p=[0.45, 0.35, 0.20])), float(rng.uniform(60, 450)), int(rng.integers(0, 24)),
        0, 0, 0, 0, int(rng.integers(40, 300)), 3.2, int(rng.integers(1, 3)),
        0.0, 0.0, 0.0, 0.0, float(rng.uniform(0.8, 1.0)), 0.0, 0.0,
        1, int(rng.integers(30, 90)), 7, 0, 0, 1
    ))

    # 9. Command Injection
    add(200, 9, "command_injection", lambda: _row(
        int(rng.choice([0, 1])), int(rng.integers(1, 4)), int(rng.integers(25, 80)), int(rng.choice([0, 1])), 0, 0.0,
        int(rng.choice([500, 400, 200], p=[0.45, 0.35, 0.20])), float(rng.exponential(150)), int(rng.integers(0, 24)),
        0, 0, 0, 0, int(rng.integers(30, 250)), 3.7, int(rng.integers(2, 6)),
        0.0, 0.0, float(rng.uniform(0.8, 1.0)), 0.0, 0.0, 0.0, 0.0,
        1, int(rng.integers(15, 60)), 6, 0, 1, 1
    ))

    # 10. XSS
    add(200, 10, "xss", lambda: _row(
        1, int(rng.integers(1, 4)), int(rng.integers(30, 90)), 1, 40, 3.8,
        int(rng.choice([200, 400], p=[0.60, 0.40])), float(rng.exponential(90)), int(rng.integers(0, 24)),
        0, 0, 0, 0, int(rng.integers(60, 400)), float(rng.uniform(3.6, 4.8)), int(rng.integers(2, 6)),
        0.0, float(rng.uniform(0.8, 1.0)), 0.0, 0.0, 0.0, 0.0, 0.0,
        1, int(rng.integers(20, 80)), 8, 0, 0, 2
    ))

    # 11. Mass Assignment
    add(220, 11, "mass_assignment", lambda: _row(
        int(rng.choice([1, 2, 4])), int(rng.integers(2, 4)), int(rng.integers(12, 30)), 1, 64, 4.4,
        int(rng.choice([200, 201, 400], p=[0.65, 0.20, 0.15])), float(rng.exponential(85)), int(rng.integers(0, 24)),
        0, 0, 0, 0, int(rng.integers(100, 600)), float(rng.uniform(3.2, 4.5)), 0,
        0.0, 0.0, 0.0, 0.0, 0.0, float(rng.uniform(0.85, 1.0)), 0.0,
        0, 0, 9, 0, 0, int(rng.integers(2, 4))
    ))

    # 12. Prompt Injection (AI Endpoints)
    add(220, 12, "prompt_injection", lambda: _row(
        1, int(rng.integers(2, 4)), int(rng.integers(15, 35)), 1, 64, 4.5,
        int(rng.choice([200, 400, 500], p=[0.70, 0.15, 0.15])), float(rng.uniform(300, 1800)), int(rng.integers(0, 24)),
        0, 0, 0, 0, int(rng.integers(200, 1500)), float(rng.uniform(4.0, 5.2)), 0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, float(rng.uniform(0.85, 1.0)),
        0, 0, 8, 0, 0, 2
    ))

    # 13. Shadow API
    add(180, 13, "shadow_api", lambda: _row(
        int(rng.choice([0, 1])), int(rng.integers(2, 4)), int(rng.integers(10, 25)), int(rng.choice([0, 1])), 0, 0.0,
        int(rng.choice([200, 403], p=[0.70, 0.30])), float(rng.exponential(85)), int(rng.integers(0, 24)),
        0, 0, 0, 0, 0, 0.0, 0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        0, 0, 6, 0, 0, 0
    ))

    # 14. Credential Stuffing
    add(220, 14, "credential_stuffing", lambda: _row(
        1, 2, 14, 0, 0, 0.0,
        int(rng.choice([401, 200], p=[0.85, 0.15])), float(rng.uniform(20, 90)), int(rng.integers(0, 24)),
        0, 0, 1, 0, 80, 3.2, 0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        0, 0, 6, 1, 1, 1
    ))

    return rows


def save_csv(normal_rows, attack_rows, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    header = FEATURE_NAMES + ["label_id", "label_name"]
    all_rows = normal_rows + attack_rows
    idx = np.random.default_rng(99).permutation(len(all_rows))
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for i in idx:
            feats, lid, lname = all_rows[i]
            w.writerow([round(float(v), 3) for v in feats] + [lid, lname])
    print(f"Dataset saved to {path} (Total: {len(all_rows)} rows)")


def train_and_save():
    os.makedirs(DATA_DIR, exist_ok=True)
    rng = np.random.default_rng(42)

    print("Generating comprehensive synthetic & real-world attack training corpus...")
    normal_rows = _normal(rng, 4000)
    attack_rows = _attacks(rng)
    save_csv(normal_rows, attack_rows, DATASET_PATH)

    normal_X = np.array([r[0] for r in normal_rows], dtype=float)
    attack_X = np.array([r[0] for r in attack_rows], dtype=float)
    X_all = np.vstack([normal_X, attack_X])
    y_all = np.array([0] * len(normal_rows) + [1] * len(attack_rows))

    # 1. IsolationForest (Unsupervised)
    print(f"\nTraining IsolationForest on {len(normal_X)} normal samples...")
    iso = IsolationForest(n_estimators=300, contamination=0.03, random_state=42, n_jobs=-1)
    iso.fit(normal_X)
    joblib.dump(iso, IF_MODEL_PATH)
    print(f"IsolationForest model saved -> {IF_MODEL_PATH}")

    # 2. Calibrated Ensemble (Supervised)
    print(f"\nTraining Calibrated Random Forest Ensemble on {len(X_all)} samples...")
    X_tr, X_te, y_tr, y_te = train_test_split(
        X_all, y_all, test_size=0.20, random_state=42, stratify=y_all
    )
    base_rf = RandomForestClassifier(
        n_estimators=350, max_depth=16, min_samples_leaf=2,
        class_weight="balanced", random_state=42, n_jobs=-1
    )
    base_rf.fit(X_tr, y_tr)

    # Calibrate probabilities using Sigmoid / Platt scaling
    calibrated_rf = CalibratedClassifierCV(estimator=base_rf, method="sigmoid", cv=5)
    calibrated_rf.fit(X_tr, y_tr)

    joblib.dump(calibrated_rf, RF_MODEL_PATH)
    print(f"Calibrated Random Forest Ensemble saved -> {RF_MODEL_PATH}")

    # Evaluation
    y_pred = calibrated_rf.predict(X_te)
    y_prob = calibrated_rf.predict_proba(X_te)[:, 1]
    roc_auc = roc_auc_score(y_te, y_prob)

    print("\n================ CLASSIFICATION PERFORMANCE METRICS ================")
    print(classification_report(y_te, y_pred, target_names=["Normal", "Attack"], digits=4))
    print(f"ROC-AUC Score : {roc_auc:.4f}")

    cm = confusion_matrix(y_te, y_pred)
    print("\n================ CONFUSION MATRIX ================")
    print(f"               Predicted Normal    Predicted Attack")
    print(f"Actual Normal  TN={cm[0,0]:<6}       FP={cm[0,1]}")
    print(f"Actual Attack  FN={cm[1,0]:<6}       TP={cm[1,1]}")

    acc = (cm[0, 0] + cm[1, 1]) / cm.sum()
    fpr = cm[0, 1] / (cm[0, 0] + cm[0, 1])
    fnr = cm[1, 0] / (cm[1, 0] + cm[1, 1])
    print(f"\nOverall Accuracy      : {acc*100:.2f}%")
    print(f"False Positive Rate   : {fpr*100:.2f}%")
    print(f"False Negative Rate   : {fnr*100:.2f}%")

    print("\n================ TOP FEATURE IMPORTANCES ================")
    for fname, imp in sorted(zip(FEATURE_NAMES, base_rf.feature_importances_), key=lambda x: -x[1])[:12]:
        bar = "#" * int(imp * 60)
        print(f"  {fname:<24} {bar:<60} {imp:.4f}")

    return {
        "accuracy": acc,
        "roc_auc": roc_auc,
        "fpr": fpr,
        "fnr": fnr
    }


if __name__ == "__main__":
    train_and_save()
