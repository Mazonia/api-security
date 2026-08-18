"""Excessive Agency & Dangerous Tool Sinks Audit Rule."""
import re
from typing import Dict, List, Any
from ..governance import get_governance_mapping


DANGEROUS_TOOL_PATTERNS = [
    (
        "shell-injection-in-tool",
        "CRITICAL",
        re.compile(r'(?:subprocess\.(?:run|Popen|check_output|call)|os\.(?:system|popen)|child_process\.(?:exec|spawn|execSync)|execSync|execFile)\s*\(', re.I),
        "Tool executes arbitrary operating system shell commands. Untrusted prompt injection can lead to remote code execution."
    ),
    (
        "financial-action-tool",
        "HIGH",
        re.compile(r'(?:stripe\.(?:Refund|Charge|Customer|PaymentIntent|charges|refunds|payouts|transfers|payment_intents)|paypal|square|braintree|authorize_net|send_payment|transfer_funds|create_charge|issue_refund)', re.I),
        "Tool exposes financial transactions or payment mutations (refund, charge, payout) to autonomous model execution."
    ),
    (
        "database-admin-tool",
        "HIGH",
        re.compile(r'(?:execute_raw_sql|execute_query|cursor\.execute\s*\(\s*f[\'"]|DROP\s+TABLE|ALTER\s+TABLE|TRUNCATE\s+TABLE|db_admin|grant_permissions)', re.I),
        "Tool allows unrestricted or raw database administrative operations without query sanitization or parameterized constraints."
    ),
    (
        "filesystem-destructive-tool",
        "HIGH",
        re.compile(r'(?:shutil\.rmtree|os\.remove|os\.unlink|fs\.rmdir|fs\.unlink|fs\.rmSync|rmdirSync|rm_rf|delete_file_system)\s*\(', re.I),
        "Tool exposes destructive filesystem write or deletion capabilities."
    ),
    (
        "cloud-iam-mutation-tool",
        "HIGH",
        re.compile(r'(?:boto3\.client\s*\(\s*[\'"]iam[\'"]|iam\.attach_user_policy|iam\.create_access_key|k8s\.create_namespaced_deployment|aws_iam_role)', re.I),
        "Tool mutates cloud IAM credentials, cluster roles, or sensitive infrastructure."
    )
]


class ExcessiveAgencyRule:
    def audit(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        is_tool_file = bool(re.search(r'(?:@tool|BaseTool|StructuredTool|tool\s*\(|AgentExecutor|Crew|Agent|create_react_agent|Tool\(|mcpServers|server\.tool)', content, re.I))

        for rule_id, severity, pattern, desc in DANGEROUS_TOOL_PATTERNS:
            for m in pattern.finditer(content):
                line_no = content[:m.start()].count("\n") + 1
                snippet = content[max(0, m.start() - 60):min(len(content), m.end() + 80)].strip()
                
                # If found in a tool context, elevate confidence
                gov = get_governance_mapping(rule_id)
                findings.append({
                    "rule_id": rule_id,
                    "title": gov["title"],
                    "severity": severity,
                    "file": file_path,
                    "line": line_no,
                    "snippet": snippet,
                    "description": desc,
                    "in_tool_context": is_tool_file,
                    "governance": gov
                })

        return findings
