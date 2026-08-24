"""Cyber-Physical IoT Actuation & Edge AI Guardrails Audit Rule."""
import re
from typing import Dict, List, Any
from ..governance import get_governance_mapping


IOT_ACTUATION_PATTERNS = [
    (
        "cyber-physical-actuation-tool",
        "HIGH",
        re.compile(r'(?:unlock_door|lock_door|set_thermostat|turn_on_relay|toggle_switch|move_motor|open_valve|close_valve|override_breaker|actuate_device|publish_actuator|trigger_relay|hvac_control|robot_step)', re.I),
        "Tool exposes direct cyber-physical actuation (locks, motors, relays, valves) to autonomous AI agent execution without Human-in-the-Loop (HITL) authorization or safety range enforcement."
    ),
    (
        "unencrypted-iot-telemetry-tool",
        "MEDIUM",
        re.compile(r'(?:mqtt:\/\/|coap:\/\/|1883|5683|read_raw_sensor|subscribe_unencrypted|publish_cleartext)', re.I),
        "Tool interacts with unencrypted IoT protocols (MQTT over cleartext 1883 or CoAP over UDP 5683) exposing sensor data and control messages to eavesdropping and MitM tampering."
    ),
    (
        "unsigned-ota-firmware-tool",
        "HIGH",
        re.compile(r'(?:trigger_ota_update|flash_firmware|esp_ota_begin|upload_firmware_binary|microcontroller_update|update_bin)', re.I),
        "Tool provides capability to dispatch OTA firmware binary updates to edge IoT devices without validating cryptographic Ed25519/ECDSA signature headers."
    )
]


class IoTActuationRule:
    def audit(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        is_tool_file = bool(re.search(r'(?:@tool|BaseTool|StructuredTool|tool\s*\(|AgentExecutor|Crew|Agent|create_react_agent|Tool\(|mcpServers|server\.tool)', content, re.I))

        for rule_id, severity, pattern, desc in IOT_ACTUATION_PATTERNS:
            for m in pattern.finditer(content):
                line_no = content[:m.start()].count("\n") + 1
                snippet = content[max(0, m.start() - 60):min(len(content), m.end() + 80)].strip()
                
                gov = get_governance_mapping(rule_id)
                findings.append({
                    "rule_id": rule_id,
                    "title": gov.get("title", "Cyber-Physical IoT Actuation Risk"),
                    "severity": severity,
                    "file": file_path,
                    "line": line_no,
                    "snippet": snippet,
                    "description": desc,
                    "in_tool_context": is_tool_file,
                    "governance": gov
                })

        return findings
