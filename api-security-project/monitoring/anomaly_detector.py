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


# Only surface ML-driven anomalies at or above this confidence. Rule-based hits
# (BOLA, /debug, /admin, 429) are always surfaced — they are deterministic, not probabilistic.
MIN_CONFIDENCE = 0.7


class AnomalyDetector:
    def __init__(self, min_confidence: float = MIN_CONFIDENCE) -> None:
        self._iso = None
        self._rf  = None
        self.min_confidence = min_confidence
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

        # Rule-based layer — fires first for unambiguous patterns. These are deterministic,
        # so they carry confidence 1.0 and are always surfaced regardless of min_confidence.
        if record.get("bola_suspected"):
            reason = "bola_object_accessed" if status == 200 else "bola_attempt_detected"
            return {"anomaly": True, "score": -0.8, "confidence": 1.0, "reason": reason, "model": "rule"}
        if "/debug" in path:
            return {"anomaly": True, "score": -0.9, "confidence": 1.0, "reason": "debug_endpoint_access", "model": "rule"}
        if "/admin" in path:
            return {"anomaly": True, "score": -0.7, "confidence": 1.0, "reason": "admin_endpoint_access", "model": "rule"}
        if status == 429:
            return {"anomaly": True, "score": -0.5, "confidence": 1.0, "reason": "rate_limit_triggered", "model": "rule"}

        features = _extract(record)

        # IsolationForest score + anomaly flag
        iso_anomaly = False
        iso_score   = 0.0
        if self._iso is not None:
            try:
                iso_score   = float(self._iso.decision_function(features)[0])
                iso_anomaly = int(self._iso.predict(features)[0]) == -1
            except Exception:
                pass

        # RandomForest classification + probability (supervised)
        rf_anomaly = False
        rf_proba   = 0.0
        if self._rf is not None:
            try:
                rf_anomaly = bool(self._rf.predict(features)[0] == 1)
                if hasattr(self._rf, "predict_proba"):
                    proba = self._rf.predict_proba(features)[0]
                    # P(attack): index of class label 1 if available, else last column
                    classes = list(getattr(self._rf, "classes_", [0, 1]))
                    idx = classes.index(1) if 1 in classes else len(proba) - 1
                    rf_proba = float(proba[idx])
            except Exception:
                pass

        # ── Confidence (0..1) ────────────────────────────────────────────────────
        # RandomForest contributes its calibrated P(attack). IsolationForest's
        # decision_function is unbounded around 0 (negative = more anomalous); squash
        # it to 0..1 with a logistic so the two models combine on the same scale.
        iso_conf = 1.0 / (1.0 + np.exp(8.0 * iso_score)) if self._iso is not None else 0.0
        if self._rf is not None and self._iso is not None:
            confidence = 0.65 * rf_proba + 0.35 * iso_conf     # supervised weighted higher
        elif self._rf is not None:
            confidence = rf_proba
        else:
            confidence = iso_conf
        confidence = float(max(0.0, min(1.0, confidence)))

        ml_anomaly = iso_anomaly or rf_anomaly
        # Gate: only surface ML anomalies we are confident about; below the threshold we
        # report normal to keep false positives down (the whole point of the gate).
        anomaly = ml_anomaly and confidence >= self.min_confidence

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
        elif ml_anomaly:
            # flagged by a model but below threshold — record why it was suppressed
            reason = "low_confidence_suppressed"

        return {
            "anomaly":    anomaly,
            "score":      round(iso_score, 4),
            "confidence": round(confidence, 4),
            "reason":     reason,
            "model":      model_used,
        }


detector = AnomalyDetector()
