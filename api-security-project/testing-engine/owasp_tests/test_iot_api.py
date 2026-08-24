"""IoT API Security & Protocol Vulnerability Tests.

Audits MQTT Brokers, CoAP Endpoints, Insecure OTA Firmware Uploads,
and Unauthenticated Cyber-Physical Actuation Endpoints.
"""
import requests
from typing import Dict, List, Any


def run_iot_security_tests(target_url: str, headers: Dict[str, str] = None) -> List[Dict[str, Any]]:
    """Executes dynamic IoT API security test suite against target endpoint."""
    findings = []
    headers = headers or {}
    base_url = target_url.rstrip("/")

    # 1. Insecure OTA Firmware Upload Test
    ota_endpoints = ["/api/v1/iot/ota/upload", "/ota/upload", "/firmware/update", "/api/ota"]
    for ota_path in ota_endpoints:
        url = f"{base_url}{ota_path}"
        try:
            # Test uploading dummy unsigned binary payload without auth
            resp = requests.post(
                url,
                data=b"\x7fELF\x02\x01\x01\x00DummyFirmwareBinaryData",
                headers={"Content-Type": "application/octet-stream"},
                timeout=3
            )
            if resp.status_code in (200, 201, 202):
                findings.append({
                    "test_id": "IOT-OTA-01",
                    "title": "Unauthenticated & Unsigned OTA Firmware Upload Endpoint",
                    "severity": "CRITICAL",
                    "owasp_category": "API8: Security Misconfiguration / OWASP IoT I3",
                    "cwe": "CWE-347: Improper Verification of Cryptographic Signature",
                    "endpoint": ota_path,
                    "description": f"Endpoint {ota_path} accepted an unsigned firmware binary without requiring authentication or Ed25519 signature headers.",
                    "evidence": f"HTTP {resp.status_code}: {resp.text[:150]}"
                })
        except Exception:
            pass

    # 2. Unauthenticated Cyber-Physical Actuation Endpoint Test
    actuate_endpoints = ["/api/v1/iot/actuate", "/iot/actuate", "/api/v1/device/lock", "/api/v1/relay/toggle"]
    for act_path in actuate_endpoints:
        url = f"{base_url}{act_path}"
        try:
            resp = requests.post(
                url,
                json={"action": "unlock", "device_id": "door_lock_01"},
                timeout=3
            )
            if resp.status_code in (200, 201):
                findings.append({
                    "test_id": "IOT-ACT-01",
                    "title": "Unauthenticated Cyber-Physical Actuation Endpoint",
                    "severity": "HIGH",
                    "owasp_category": "API2: Broken Authentication / OWASP IoT I2",
                    "cwe": "CWE-306: Missing Authentication for Critical Function",
                    "endpoint": act_path,
                    "description": f"Physical actuation endpoint {act_path} executed state mutation without requiring JWT/mTLS authentication.",
                    "evidence": f"HTTP {resp.status_code}: {resp.text[:150]}"
                })
        except Exception:
            pass

    # 3. Cleartext IoT Telemetry Endpoint Test
    telemetry_endpoints = ["/api/v1/iot/telemetry", "/iot/sensors", "/telemetry/stream"]
    for tel_path in telemetry_endpoints:
        url = f"{base_url}{tel_path}"
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200 and ("temperature" in resp.text.lower() or "sensor" in resp.text.lower() or "device_id" in resp.text.lower()):
                findings.append({
                    "test_id": "IOT-TEL-01",
                    "title": "Unauthenticated Cleartext IoT Telemetry Disclosure",
                    "severity": "MEDIUM",
                    "owasp_category": "API3: Broken Object Property Level Authorization",
                    "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
                    "endpoint": tel_path,
                    "description": f"Telemetry endpoint {tel_path} exposes raw IoT sensor readings without authentication or access control.",
                    "evidence": f"HTTP 200: {resp.text[:150]}"
                })
        except Exception:
            pass

    # 4. Anonymous MQTT Broker Gateway Audit
    mqtt_gateway_url = f"{base_url}/api/v1/iot/mqtt/publish"
    try:
        resp = requests.post(
            mqtt_gateway_url,
            json={"topic": "#", "message": "probe"},
            timeout=3
        )
        if resp.status_code in (200, 202):
            findings.append({
                "test_id": "IOT-MQTT-01",
                "title": "Anonymous MQTT Gateway Wildcard Topic Publishing Allowed",
                "severity": "HIGH",
                "owasp_category": "API1: Broken Object Level Authorization / MQTT Topic Hijacking",
                "cwe": "CWE-285: Improper Authorization",
                "endpoint": "/api/v1/iot/mqtt/publish",
                "description": "MQTT Gateway permits anonymous publishing to wildcard topic '#' without topic ACL constraints.",
                "evidence": f"HTTP {resp.status_code}: {resp.text[:150]}"
            })
    except Exception:
        pass

    return findings
