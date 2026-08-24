"""C/C++ Embedded Microcontroller REST, OTA, MQTT, & CoAP Route Parser.

Extracts endpoints, HTTP/MQTT/CoAP methods, topics, auth status, and security risk indicators
from C/C++ source code (.c, .cpp, .h, .hpp, .ino) targeting microcontrollers (ESP-IDF, Arduino, FreeRTOS).
"""
import re
from typing import Dict, List, Any


class CppRouteParser:
    name = "C/C++ Embedded IoT (ESP-IDF, Arduino, FreeRTOS, MicroREST)"
    extensions = [".c", ".cpp", ".h", ".hpp", ".ino"]

    def __init__(self):
        # ESP-IDF httpd_register_uri_handler style:
        # httpd_uri_t uri_get = { .uri = "/api/v1/telemetry", .method = HTTP_GET, .handler = get_handler };
        self.esp_uri_re = re.compile(
            r'\.uri\s*=\s*["\']([^"\'\n]+)["\'].*?\.method\s*=\s*(HTTP_[A-Z]+|\d+)',
            re.DOTALL | re.IGNORECASE
        )

        # Arduino WebServer style:
        # server.on("/api/v1/actuate", HTTP_POST, handleActuate);
        # server.on("/api/v1/status", handleStatus);
        self.arduino_on_re = re.compile(
            r'(?:server|webServer|httpServer)\.on\s*\(\s*["\']([^"\'\n]+)["\']\s*(?:,\s*(HTTP_[A-Z]+)\s*)?(?:,\s*([a-zA-Z0-9_]+))?\s*\)',
            re.IGNORECASE
        )

        # ESP-IDF / FreeRTOS / Paho MQTT Subscriptions:
        # esp_mqtt_client_subscribe(client, "/devices/telemetry", 0);
        # mqttClient.subscribe("home/actuator/lock");
        self.mqtt_sub_re = re.compile(
            r'(?:esp_mqtt_client_subscribe|mqtt_client\.subscribe|mqttClient\.subscribe)\s*\(\s*(?:[a-zA-Z0-9_]+\s*,\s*)?["\']([^"\'\n]+)["\']',
            re.IGNORECASE
        )

        # CoAP Resource Registrations:
        # coap_register_handler(resource, COAP_REQUEST_GET, handle_coap_get);
        self.coap_res_re = re.compile(
            r'coap_(?:register_handler|new_resource)\s*\(\s*(?:[a-zA-Z0-9_]+\s*,\s*)?["\']?([^"\'\n,\)]+)["\']?\s*(?:,\s*(COAP_REQUEST_[A-Z]+|COAP_PERM_[A-Z]+))?',
            re.IGNORECASE
        )

        # OTA Firmware Update triggers in C/C++:
        self.ota_re = re.compile(
            r'(?:httpUpdate|ESPhttpUpdate|esp_ota_begin|esp_ota_write|esp_https_ota|/ota|/update|firmware)',
            re.IGNORECASE
        )

        # Basic Auth / Security indicators in C/C++
        self.auth_re = re.compile(
            r'(?:authenticate|check_auth|verify_token|jwt|api_key|tls|ssl|https|mTLS|verify_signature)',
            re.IGNORECASE
        )

    def parse_file(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        endpoints = []

        # 1. Extract ESP-IDF HTTP URIs
        for m in self.esp_uri_re.finditer(content):
            raw_path = m.group(1)
            raw_method = m.group(2).upper().replace("HTTP_", "")
            
            is_authenticated = bool(self.auth_re.search(content[max(0, m.start()-100):min(len(content), m.end()+200)]))
            is_ota = bool(self.ota_re.search(raw_path))

            endpoints.append({
                "path": raw_path,
                "method": raw_method if raw_method in ["GET", "POST", "PUT", "DELETE", "PATCH"] else "POST",
                "framework": "ESP-IDF httpd",
                "file_path": file_path,
                "line_number": content[:m.start()].count("\n") + 1,
                "is_authenticated": is_authenticated,
                "auth_details": "Signature/Token Header" if is_authenticated else "Unauthenticated embedded HTTP",
                "protocol": "HTTP",
                "parameters": self._extract_cpp_params(raw_path),
                "risk_factors": self._assess_risk(raw_path, is_authenticated, is_ota, "HTTP")
            })

        # 2. Extract Arduino WebServer endpoints
        for m in self.arduino_on_re.finditer(content):
            raw_path = m.group(1)
            raw_method = m.group(2)
            method = raw_method.upper().replace("HTTP_", "") if raw_method else "GET"
            
            context_window = content[max(0, m.start()-150):min(len(content), m.end()+150)]
            is_authenticated = bool(self.auth_re.search(context_window))
            is_ota = bool(self.ota_re.search(raw_path))

            endpoints.append({
                "path": raw_path,
                "method": method,
                "framework": "Arduino WebServer",
                "file_path": file_path,
                "line_number": content[:m.start()].count("\n") + 1,
                "is_authenticated": is_authenticated,
                "auth_details": "Authenticated" if is_authenticated else "Missing authentication check",
                "protocol": "HTTP",
                "parameters": self._extract_cpp_params(raw_path),
                "risk_factors": self._assess_risk(raw_path, is_authenticated, is_ota, "HTTP")
            })

        # 3. Extract MQTT topic subscriptions
        for m in self.mqtt_sub_re.finditer(content):
            topic = m.group(1)
            context_window = content[max(0, m.start()-150):min(len(content), m.end()+150)]
            is_authenticated = bool(self.auth_re.search(context_window))

            endpoints.append({
                "path": topic,
                "method": "SUBSCRIBE",
                "framework": "Embedded MQTT Client",
                "file_path": file_path,
                "line_number": content[:m.start()].count("\n") + 1,
                "is_authenticated": is_authenticated,
                "auth_details": "MQTT ACL/TLS" if is_authenticated else "Anonymous MQTT Subscription",
                "protocol": "MQTT",
                "parameters": [],
                "risk_factors": self._assess_risk(topic, is_authenticated, False, "MQTT")
            })

        # 4. Extract CoAP resource endpoints
        for m in self.coap_res_re.finditer(content):
            raw_path = m.group(1).strip('"\'')
            if not raw_path or raw_path.startswith("COAP_"):
                continue
            
            raw_method = m.group(2) if m.group(2) else "GET"
            method = raw_method.replace("COAP_REQUEST_", "").replace("COAP_PERM_", "")
            context_window = content[max(0, m.start()-150):min(len(content), m.end()+150)]
            is_authenticated = bool(self.auth_re.search(context_window))

            endpoints.append({
                "path": "/" + raw_path.lstrip("/"),
                "method": method if method in ["GET", "POST", "PUT", "DELETE"] else "GET",
                "framework": "Embedded CoAP Server",
                "file_path": file_path,
                "line_number": content[:m.start()].count("\n") + 1,
                "is_authenticated": is_authenticated,
                "auth_details": "CoAP DTLS/PSK" if is_authenticated else "Unauthenticated CoAP (UDP)",
                "protocol": "CoAP",
                "parameters": [],
                "risk_factors": self._assess_risk(raw_path, is_authenticated, False, "CoAP")
            })

        return endpoints

    def _extract_cpp_params(self, path: str) -> List[Dict[str, str]]:
        params = []
        matches = re.findall(r'\{([a-zA-Z0-9_]+)\}', path)
        for p in matches:
            params.append({"name": p, "type": "path", "data_type": "string"})
        return params

    def _assess_risk(self, path: str, is_auth: bool, is_ota: bool, protocol: str) -> List[str]:
        risks = []
        if not is_auth:
            risks.append("Unauthenticated IoT Endpoint")
        if is_ota:
            risks.append("OTA Firmware Update Surface")
            if not is_auth:
                risks.append("Unsigned/Unauthenticated OTA Firmware Vulnerability")
        if "#" in path or "+" in path:
            risks.append("MQTT Wildcard Topic Subscription (Potential Hijack)")
        if protocol == "CoAP" and not is_auth:
            risks.append("Unencrypted CoAP over UDP (Amplification / Tampering Risk)")
        if "actuate" in path.lower() or "lock" in path.lower() or "relay" in path.lower() or "motor" in path.lower():
            risks.append("Physical Actuation Control Endpoint")
        return risks
