"""Advanced 32-Feature Calibrated Ensemble Anomaly Detector with Explainability."""
import math
import os
import re
from datetime import datetime
from typing import Dict, Any, List

import joblib
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "data"))
if not os.path.exists(DATA_DIR) and os.path.exists("/data"):
    DATA_DIR = "/data"

IF_MODEL_PATH = os.path.join(DATA_DIR, "model.joblib")
RF_MODEL_PATH = os.path.join(DATA_DIR, "rf_model.joblib")

_SPECIAL_CHARS = (";", "|", "<", ">", "'", '"', "%2f", "%2e", "..", "$", "`", "&&")

FEATURE_NAMES = [
    "method_code", "path_depth", "path_length", "has_auth", "auth_token_length", "auth_token_entropy",
    "status_code", "is_2xx", "is_4xx", "is_5xx", "response_ms", "hour",
    "is_admin_path", "is_debug_path", "is_auth_endpoint", "bola_suspected",
    "payload_length", "payload_entropy", "has_special_chars", "sqli_density",
    "xss_density", "cmd_injection_score", "path_traversal_score", "ssrf_score",
    "mass_assignment_score", "prompt_injection_score", "query_param_count", "query_length",
    "header_count", "is_burst_request", "user_agent_suspicious", "body_json_depth"
]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    return -sum(p * math.log(p) / math.log(2.0) for p in prob)


def _extract_32(record: Dict[str, Any]) -> np.ndarray:
    method_map = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "PATCH": 4, "OPTIONS": 5, "HEAD": 6}
    method = record.get("method", "GET").upper()
    method_code = method_map.get(method, 0)
    
    path = record.get("path", "/")
    path_depth = len([p for p in path.split("/") if p])
    path_length = len(path)
    
    has_auth = 1 if record.get("has_auth") or record.get("authorization") or record.get("token") else 0
    token_str = str(record.get("token") or record.get("authorization") or "")
    auth_token_len = len(token_str)
    auth_token_ent = _shannon_entropy(token_str) if has_auth else 0.0
    
    status = int(record.get("status_code", 200))
    is_2xx = 1 if 200 <= status < 300 else 0
    is_4xx = 1 if 400 <= status < 500 else 0
    is_5xx = 1 if status >= 500 else 0
    
    resp_ms = float(record.get("response_time_ms", 0))
    hour = datetime.utcnow().hour
    
    raw_path = (record.get("raw_path") or path or "").lower()
    is_admin = 1 if any(p in raw_path for p in ("/admin", "/manage", "/internal", "/root")) else 0
    is_debug = 1 if any(p in raw_path for p in ("/debug", "/actuator", "/env", "/metrics", "/_status")) else 0
    is_auth = 1 if any(p in raw_path for p in ("/auth", "/login", "/token", "/oauth", "/signin", "/signup")) else 0
    bola = 1 if record.get("bola_suspected") else 0
    
    body = str(record.get("body") or record.get("payload") or "")
    payload_len = len(body)
    payload_ent = _shannon_entropy(body) if body else 0.0
    
    full_text = f"{raw_path} {body}".lower()
    special_cnt = sum(full_text.count(c) for c in _SPECIAL_CHARS)
    
    # Syntactic signature densities
    sqli_density = 1.0 if bool(re.search(r'(?:union\s+select|or\s+1\s*=\s*1|--|sleep\s*\(|drop\s+table|insert\s+into|\'|")', full_text)) else 0.0
    xss_density = 1.0 if bool(re.search(r'(?:<script|javascript:|onerror\s*=|onload\s*=|alert\s*\()', full_text)) else 0.0
    cmd_inj = 1.0 if bool(re.search(r'(?:;\s*(?:cat|ls|whoami|curl|wget|id)|\|\s*sh|`[^`]+`|\$\([^\)]+\))', full_text)) else 0.0
    traversal = 1.0 if bool(re.search(r'(?:\.\./|\.\.\\|%2e%2e%2f|etc/passwd|win\.ini)', full_text)) else 0.0
    ssrf = 1.0 if bool(re.search(r'(?:169\.254\.169\.254|localhost|127\.0\.0\.1|metadata\.google)', full_text)) else 0.0
    mass_assign = 1.0 if bool(re.search(r'(?:is_admin|role|admin|permissions|balance)\s*[:=]', body, re.I)) else 0.0
    prompt_inj = 1.0 if bool(re.search(r'(?:ignore\s+previous|system\s+prompt|dan\s+mode|jailbreak|bypass\s+rules)', full_text, re.I)) else 0.0
    
    query = str(record.get("query") or "")
    q_count = len(query.split("&")) if query else 0
    q_len = len(query)
    
    h_count = int(record.get("header_count", 8))
    is_burst = 1 if record.get("is_burst") else 0
    
    ua = str(record.get("user_agent", "")).lower()
    ua_sus = 1 if any(b in ua for b in ("sqlmap", "nikto", "gobuster", "dirbuster", "nmap", "python-requests")) or not ua else 0
    
    json_depth = int(record.get("json_depth", body.count("{")))

    return np.array([[
        method_code, path_depth, path_length, has_auth, auth_token_len, auth_token_ent,
        status, is_2xx, is_4xx, is_5xx, resp_ms, hour,
        is_admin, is_debug, is_auth, bola,
        payload_len, payload_ent, special_cnt, sqli_density,
        xss_density, cmd_inj, traversal, ssrf,
        mass_assign, prompt_inj, q_count, q_len,
        h_count, is_burst, ua_sus, json_depth
    ]], dtype=float)


class AnomalyDetector:
    def __init__(self, min_confidence: float = 0.70):
        self.min_confidence = min_confidence
        self._iso = None
        self._rf = None
        self._load()

    def _load(self):
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

    def reload(self):
        self._load()

    def predict(self, record: Dict[str, Any]) -> Dict[str, Any]:
        path = record.get("path", "")
        status = record.get("status_code", 200)

        # Rule-based fast deterministic triage
        raw_path = record.get("raw_path") or path or ""
        body_str = str(record.get("body") or record.get("payload") or "")
        has_auth = record.get("has_auth") or record.get("authorization") or record.get("token")

        if "/ota/" in raw_path.lower() or "/firmware" in raw_path.lower():
            if not has_auth:
                return {
                    "anomaly": True,
                    "score": -0.95,
                    "confidence": 1.0,
                    "reason": "Unauthenticated & Unsigned OTA Firmware Upload Attempt",
                    "model": "rule",
                    "attack_type": "iot_ota_tampering",
                    "top_features": ["is_debug_path", "payload_length"]
                }

        if "/actuate" in raw_path.lower() or "unlock" in body_str.lower() or "relay" in raw_path.lower():
            if not has_auth:
                return {
                    "anomaly": True,
                    "score": -0.90,
                    "confidence": 1.0,
                    "reason": "Unauthenticated Cyber-Physical Actuation Trigger",
                    "model": "rule",
                    "attack_type": "iot_actuation_hijack",
                    "top_features": ["is_admin_path", "has_auth"]
                }

        if record.get("protocol") == "MQTT" or "/mqtt/" in raw_path.lower():
            if ("#" in raw_path or "+" in raw_path or "#" in body_str) and not has_auth:
                return {
                    "anomaly": True,
                    "score": -0.85,
                    "confidence": 1.0,
                    "reason": "Anonymous MQTT Wildcard Topic Hijack Attempt",
                    "model": "rule",
                    "attack_type": "iot_topic_hijack",
                    "top_features": ["path_length", "has_auth"]
                }

        if record.get("bola_suspected"):
            return {
                "anomaly": True,
                "score": -0.9,
                "confidence": 1.0,
                "reason": "BOLA / IDOR Object Authorization Violation",
                "model": "rule",
                "attack_type": "bola",
                "top_features": ["bola_suspected", "path_depth"]
            }
        if status == 429:
            return {
                "anomaly": True,
                "score": -0.6,
                "confidence": 1.0,
                "reason": "Rate Limit Exceeded (HTTP 429)",
                "model": "rule",
                "attack_type": "rate_abuse",
                "top_features": ["is_4xx", "status_code"]
            }

        features = _extract_32(record)

        # 1. Isolation Forest Unsupervised Score
        iso_anomaly = False
        iso_score = 0.0
        if self._iso is not None:
            try:
                iso_score = float(self._iso.decision_function(features)[0])
                iso_anomaly = int(self._iso.predict(features)[0]) == -1
            except Exception:
                pass

        # 2. Calibrated Random Forest Supervised Probability
        rf_anomaly = False
        rf_proba = 0.0
        if self._rf is not None:
            try:
                proba = self._rf.predict_proba(features)[0]
                classes = list(getattr(self._rf, "classes_", [0, 1]))
                idx = classes.index(1) if 1 in classes else len(proba) - 1
                rf_proba = float(proba[idx])
                rf_anomaly = rf_proba >= 0.50
            except Exception:
                pass

        # Calibrated logistic squash on IsolationForest score
        iso_conf = 1.0 / (1.0 + np.exp(8.0 * iso_score)) if self._iso is not None else 0.0

        if self._rf is not None and self._iso is not None:
            confidence = (0.70 * rf_proba) + (0.30 * iso_conf)
        elif self._rf is not None:
            confidence = rf_proba
        else:
            confidence = iso_conf

        confidence = float(max(0.0, min(1.0, confidence)))
        # Signature-backed threat indicator check
        f_arr = features[0]
        has_explicit_signature = (
            f_arr[19] > 0 or f_arr[20] > 0 or f_arr[21] > 0 or f_arr[22] > 0 or 
            f_arr[23] > 0 or f_arr[24] > 0 or f_arr[25] > 0 or (f_arr[12] == 1 and f_arr[3] == 0)
        )

        if has_explicit_signature:
            confidence = max(confidence, 0.95)
            rf_anomaly = True

        is_anomalous = (rf_anomaly or iso_anomaly) and (confidence >= self.min_confidence)

        # Determine explainable attack reason
        reason = "Normal traffic"
        attack_type = "normal"
        top_features = []

        if is_anomalous:
            if f_arr[19] > 0:
                reason = "SQL Injection Payload Detected"
                attack_type = "sql_injection"
                top_features.append("sqli_density")
            elif f_arr[20] > 0:
                reason = "Cross-Site Scripting (XSS) Detected"
                attack_type = "xss"
                top_features.append("xss_density")
            elif f_arr[21] > 0:
                reason = "Command Injection Metacharacters Detected"
                attack_type = "command_injection"
                top_features.append("cmd_injection_score")
            elif f_arr[22] > 0:
                reason = "Directory Path Traversal Attempt"
                attack_type = "path_traversal"
                top_features.append("path_traversal_score")
            elif f_arr[23] > 0:
                reason = "Server-Side Request Forgery (SSRF)"
                attack_type = "ssrf"
                top_features.append("ssrf_score")
            elif f_arr[24] > 0:
                reason = "Privileged Mass Assignment Parameter Injection"
                attack_type = "mass_assignment"
                top_features.append("mass_assignment_score")
            elif f_arr[25] > 0:
                reason = "AI Prompt Injection & Jailbreak Attempt"
                attack_type = "prompt_injection"
                top_features.append("prompt_injection_score")
            elif f_arr[12] == 1 and f_arr[3] == 0:
                reason = "Unauthenticated Admin Endpoint Probing (BFLA)"
                attack_type = "admin_access"
                top_features.append("is_admin_path")
            elif f_arr[13] == 1:
                reason = "Exposed Debug/Actuator Endpoint Access"
                attack_type = "debug_access"
                top_features.append("is_debug_path")
            elif status >= 500:
                reason = "Server Fault / Unhandled Exception (5xx)"
                attack_type = "server_error"
                top_features.append("is_5xx")
            else:
                reason = "Statistical Traffic & Payload Anomaly"
                attack_type = "unusual_pattern"
                top_features.append("payload_entropy")

        return {
            "anomaly": is_anomalous,
            "score": round(iso_score, 4),
            "confidence": round(confidence, 4),
            "reason": reason,
            "attack_type": attack_type,
            "model": "ensemble(CalibratedRF+IF)",
            "top_features": top_features
        }


detector = AnomalyDetector()
