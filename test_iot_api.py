"""Unit and Integration Tests for MazAPI IoT API Security Module."""
import os
import sys
import unittest

# Ensure api-security-project is on path
PROJECT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api-security-project")
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from app_surface.parsers.cpp_parser import CppRouteParser
from app_surface.parsers.python_parser import PythonRouteParser
from app_surface.parsers.node_parser import NodeRouteParser
from app_surface.asyncapi_generator import AsyncAPIGenerator
from agent_audit.rules.iot_actuation import IoTActuationRule
import importlib
test_iot_module = importlib.import_module("testing-engine.owasp_tests.test_iot_api")
run_iot_security_tests = test_iot_module.run_iot_security_tests


class TestIoTAPISecurity(unittest.TestCase):

    def test_cpp_embedded_parser(self):
        sample_cpp = """
        #include <esp_http_server.h>
        
        static esp_err_t get_handler(httpd_req_t *req) { return ESP_OK; }
        httpd_uri_t uri_get = {
            .uri      = "/api/v1/telemetry",
            .method   = HTTP_GET,
            .handler  = get_handler
        };

        void setup_mqtt() {
            esp_mqtt_client_subscribe(client, "/devices/actuator/door", 0);
            mqttClient.subscribe("factory/#");
        }

        void setup_coap() {
            coap_register_handler(resource, COAP_REQUEST_GET, handle_get);
        }
        """
        parser = CppRouteParser()
        endpoints = parser.parse_file("main.cpp", sample_cpp)
        
        paths = [ep["path"] for ep in endpoints]
        self.assertIn("/api/v1/telemetry", paths)
        self.assertIn("/devices/actuator/door", paths)
        self.assertIn("factory/#", paths)
        
        # Check risk flag for wildcard MQTT topic
        wildcard_ep = next(ep for ep in endpoints if ep["path"] == "factory/#")
        self.assertIn("MQTT Wildcard Topic Subscription (Potential Hijack)", wildcard_ep["risk_factors"])

    def test_python_mqtt_and_coap_parser(self):
        sample_py = """
        from fastapi import FastAPI
        import paho.mqtt.client as mqtt

        app = FastAPI()

        @mqtt.subscribe("home/sensors/temp")
        def handle_temp(client, userdata, message):
            pass

        @app.get("/api/v1/iot/actuate")
        def actuate():
            pass
        """
        parser = PythonRouteParser()
        endpoints = parser.parse_file("iot_app.py", sample_py)
        
        paths = [ep["path"] for ep in endpoints]
        self.assertIn("home/sensors/temp", paths)

    def test_asyncapi_generator(self):
        endpoints = [
            {"path": "/sensors/temperature", "protocol": "MQTT", "method": "SUBSCRIBE", "framework": "Paho MQTT"},
            {"path": "/actuator/lock", "protocol": "CoAP", "method": "POST", "framework": "CoAP"}
        ]
        gen = AsyncAPIGenerator(title="Test AsyncAPI Spec")
        spec = gen.generate_spec(endpoints)
        
        self.assertEqual(spec["asyncapi"], "3.0.0")
        self.assertIn("channels", spec)
        self.assertIn("operations", spec)

    def test_iot_agent_actuation_rule(self):
        sample_agent = """
        from langchain.tools import tool

        @tool
        def unlock_door_tool(device_id: str):
            \"\"\"Unlocks physical building door lock directly.\"\"\"
            return execute_actuator_unlock(device_id)

        @tool
        def flash_firmware_tool(binary_url: str):
            \"\"\"Triggers microcontroller OTA update.\"\"\"
            return esp_ota_begin(binary_url)
        """
        rule = IoTActuationRule()
        findings = rule.audit("iot_agent.py", sample_agent)
        
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("cyber-physical-actuation-tool", rule_ids)
        self.assertIn("unsigned-ota-firmware-tool", rule_ids)


if __name__ == "__main__":
    unittest.main()
