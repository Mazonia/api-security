"""IsolationForest + RandomForest ensemble anomaly detector for API traffic."""
import os
from datetime import datetime

import joblib
import numpy as np

IF_MODEL_PATH = "/data/model.joblib"
RF_MODEL_PATH = "/data/rf_model.joblib"


_SPECIAL_CHARS = (";", "|", "<", ">", "'", '"', "%2f", "%2e", "..", "$", "`", "&&")


def _extract(record: dict) -> np.ndarray:
    """Extract a 13-feature vector from a traffic record dict.

    Must stay in lockstep with FEATURE_NAMES in train_model.py.
    """
    method_map = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "PATCH": 4}
    path     = record.get("path", "/")
    status   = record.get("status_code", 200)
    raw_path = (record.get("raw_path") or path or "").lower()
    has_special = 1 if any(c in raw_path for c in _SPECIAL_CHARS) else 0
    return np.array([[
        method_map.get(record.get("method", "GET"), 4),       # 0 method
        len([p for p in path.split("/") if p]),               # 1 path_depth
        1 if record.get("has_auth") else 0,                   # 2 has_auth
        status,                                               # 3 status_code
        float(record.get("response_time_ms", 0)),             # 4 response_ms
        datetime.utcnow().hour,                               # 5 hour
        1 if "/admin" in path else 0,                         # 6 is_admin_path
        1 if "/debug" in path else 0,                         # 7 is_debug_path
        1 if 400 <= status < 500 else 0,                      # 8 is_4xx
        1 if record.get("bola_suspected") else 0,             # 9 bola_suspected
        len(path),                                            # 10 path_length
        has_special,                                          # 11 has_special_chars
        1 if status >= 500 else 0,                            # 12 is_5xx
    ]])


class AnomalyDetector:
    def __init__(self) -> None:
        self._iso = None
        self._rf  = None
        self._load()

    def _load(self) -> None:
        if os.path.exists(IF_MODEL_PATH):
            try:
                self._iso = joblib.load(IF_MODEL_PATH)
            except Exception:
                self._iso = None
        if os.path.exists(RF_MODEL_PATH):
            try:
                self._rf = joblib.load(RF_MODEL_PATH)
            except Exception:
                self._rf = None

    def reload(self) -> None:
        self._load()

    def predict(self, record: dict) -> dict:
        path   = record.get("path", "")
        status = record.get("status_code", 200)

        # Rule-based layer — fires first for unambiguous patterns
        if record.get("bola_suspected"):
            reason = "bola_object_accessed" if status == 200 else "bola_attempt_detected"
            return {"anomaly": True, "score": -0.8, "reason": reason, "model": "rule"}
        if "/debug" in path:
            return {"anomaly": True, "score": -0.9, "reason": "debug_endpoint_access", "model": "rule"}
        if "/admin" in path:
            return {"anomaly": True, "score": -0.7, "reason": "admin_endpoint_access", "model": "rule"}
        if status == 429:
            return {"anomaly": True, "score": -0.5, "reason": "rate_limit_triggered", "model": "rule"}

        features = _extract(record)

        # IsolationForest score
        iso_anomaly = False
        iso_score   = 0.0
        if self._iso is not None:
            try:
                iso_score   = float(self._iso.decision_function(features)[0])
                iso_anomaly = int(self._iso.predict(features)[0]) == -1
            except Exception:
                pass

        # RandomForest classification (supervised)
        rf_anomaly = False
        if self._rf is not None:
            try:
                rf_anomaly = bool(self._rf.predict(features)[0] == 1)
            except Exception:
                pass

        # Ensemble: anomaly if either model flags it
        anomaly = iso_anomaly or rf_anomaly
        model_used = (
            "if+rf" if (iso_anomaly and rf_anomaly)
            else ("rf" if rf_anomaly else ("if" if iso_anomaly else "none"))
        )

        reason = "normal"
        if anomaly:
            if status == 500:
                reason = "server_error_response"
            elif status >= 400:
                reason = "elevated_error_rate"
            elif record.get("response_time_ms", 0) > 2000:
                reason = "slow_response"
            elif rf_anomaly and not iso_anomaly:
                reason = "ml_classified_attack"
            else:
                reason = "unusual_pattern"

        return {
            "anomaly":  anomaly,
            "score":    round(iso_score, 4),
            "reason":   reason,
            "model":    model_used,
        }


detector = AnomalyDetector()
