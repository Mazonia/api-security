"""IsolationForest-based ML anomaly detector for API traffic."""
import os
from datetime import datetime

import joblib
import numpy as np

MODEL_PATH = "/data/model.joblib"


def _extract(record: dict) -> np.ndarray:
    method_map = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3}
    path   = record.get("path", "/")
    status = record.get("status_code", 200)
    return np.array([[
        method_map.get(record.get("method", "GET"), 4),
        len([p for p in path.split("/") if p]),
        1 if record.get("has_auth") else 0,
        status,
        float(record.get("response_time_ms", 0)),
        datetime.utcnow().hour,
        1 if "/admin" in path else 0,
        1 if "/debug" in path else 0,
        1 if status >= 400 else 0,
        1 if record.get("bola_suspected") else 0,
    ]])


class AnomalyDetector:
    def __init__(self) -> None:
        self._model = None
        if os.path.exists(MODEL_PATH):
            self._model = joblib.load(MODEL_PATH)

    def reload(self) -> None:
        if os.path.exists(MODEL_PATH):
            self._model = joblib.load(MODEL_PATH)

    def predict(self, record: dict) -> dict:
        path   = record.get("path", "")
        status = record.get("status_code", 200)

        # Rule-based detection fires before ML for unambiguous attack patterns
        if record.get("bola_suspected"):
            reason = "bola_object_accessed" if status == 200 else "bola_attempt_detected"
            return {"anomaly": True, "score": -0.8, "reason": reason}
        if "/debug" in path:
            return {"anomaly": True, "score": -0.9, "reason": "debug_endpoint_access"}
        if "/admin" in path:
            return {"anomaly": True, "score": -0.7, "reason": "admin_endpoint_access"}
        if status == 429:
            return {"anomaly": True, "score": -0.5, "reason": "rate_limit_triggered"}

        if self._model is None:
            return {"anomaly": False, "score": 0.0, "reason": "model_not_trained"}

        features = _extract(record)
        score    = float(self._model.decision_function(features)[0])
        anomaly  = int(self._model.predict(features)[0]) == -1

        reason = "normal"
        if anomaly:
            if status >= 400:
                reason = "elevated_error_rate"
            elif record.get("response_time_ms", 0) > 2000:
                reason = "slow_response"
            else:
                reason = "unusual_pattern"

        return {"anomaly": anomaly, "score": round(score, 4), "reason": reason}


detector = AnomalyDetector()
