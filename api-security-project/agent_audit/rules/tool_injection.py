"""Tool Parameter & Prompt Injection Audit Rule."""
import re
from typing import Dict, List, Any
from ..governance import get_governance_mapping


class ToolInjectionRule:
    def __init__(self):
        self.injection_sink_re = re.compile(
            r'(?:os\.system|subprocess\.run|subprocess\.Popen|child_process\.exec|execSync)\s*\(\s*(?:f[\'"][^\'"]*\{[^\}]+\}|[^\)]*\+\s*[a-zA-Z0-9_]+)',
            re.IGNORECASE
        )
        self.raw_eval_re = re.compile(
            r'(?:eval|exec)\s*\(\s*(?:f[\'"][^\'"]*\{|response|model_output|llm_output|tool_input|args)',
            re.IGNORECASE
        )

    def audit(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []

        for m in self.injection_sink_re.finditer(content):
            line_no = content[:m.start()].count("\n") + 1
            snippet = content[max(0, m.start() - 40):min(len(content), m.end() + 60)].strip()
            gov = get_governance_mapping("prompt-injection-sink")
            findings.append({
                "rule_id": "prompt-injection-sink",
                "title": gov["title"],
                "severity": "CRITICAL",
                "file": file_path,
                "line": line_no,
                "snippet": snippet,
                "description": "Dynamic variable/prompt interpolated directly into OS command execution sink without shell token escaping.",
                "governance": gov
            })

        for m in self.raw_eval_re.finditer(content):
            line_no = content[:m.start()].count("\n") + 1
            snippet = content[max(0, m.start() - 40):min(len(content), m.end() + 60)].strip()
            gov = get_governance_mapping("prompt-injection-sink")
            findings.append({
                "rule_id": "prompt-injection-sink",
                "title": "Raw Model Output Passed to Code Evaluator (eval/exec)",
                "severity": "CRITICAL",
                "file": file_path,
                "line": line_no,
                "snippet": snippet,
                "description": "Unsandboxed eval/exec called on model output or dynamic tool arguments.",
                "governance": gov
            })

        return findings
