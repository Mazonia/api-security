"""Agent Identity & Authorization Gaps Audit Rule."""
import re
from typing import Dict, List, Any
from ..governance import get_governance_mapping


class AuthorizationGapsRule:
    def __init__(self):
        self.wildcard_re = re.compile(
            r'(?:tools\s*=\s*\[\s*[\'"]\*[\'"]|allow_all_tools\s*=\s*True|dangerously_allow_all_tools|unrestricted_tools\s*=\s*True|allow_delegation\s*=\s*True)',
            re.IGNORECASE
        )
        self.confused_deputy_re = re.compile(
            r'(?:@tool|def [a-zA-Z0-9_]+_tool|server\.tool)\s*(?:\([^\)]*\))?(?:\s*\ndef\s+[a-zA-Z0-9_]+\s*\([^\)]*\))?:(?:\s*\n[^\n]+){1,25}(?:requests\.|httpx\.|db\.|client\.)',
            re.IGNORECASE
        )
        self.auth_check_re = re.compile(
            r'\b(?:check_permission|has_permission|current_user|auth_user|caller_user|context\.user|verify_token|require_auth|session\[|is_admin|permission)\b',
            re.IGNORECASE
        )

    def audit(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []

        # 1. Wildcard / unrestricted tool permissions
        for m in self.wildcard_re.finditer(content):
            line_no = content[:m.start()].count("\n") + 1
            snippet = content[max(0, m.start() - 50):min(len(content), m.end() + 60)].strip()
            gov = get_governance_mapping("wildcard-tool-permissions")
            findings.append({
                "rule_id": "wildcard-tool-permissions",
                "title": gov["title"],
                "severity": "HIGH",
                "file": file_path,
                "line": line_no,
                "snippet": snippet,
                "description": "Agent configuration grants unrestricted or wildcard tool permissions without scoping.",
                "governance": gov
            })

        # 2. Confused Deputy: Tool executes mutations or network calls without checking the calling user's identity/scope
        for m in self.confused_deputy_re.finditer(content):
            block = m.group(0)
            if not self.auth_check_re.search(block):
                line_no = content[:m.start()].count("\n") + 1
                snippet = block[:120].strip()
                gov = get_governance_mapping("confused-deputy-missing-authz")
                findings.append({
                    "rule_id": "confused-deputy-missing-authz",
                    "title": gov["title"],
                    "severity": "HIGH",
                    "file": file_path,
                    "line": line_no,
                    "snippet": snippet,
                    "description": "Agent tool makes backend state or external API calls without checking calling user authorization (Confused Deputy risk).",
                    "governance": gov
                })

        return findings
