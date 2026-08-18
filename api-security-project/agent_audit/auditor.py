"""Agent Audit & AI Surface Scanner.

Audits AI agents for exploitable authorization and access-control gaps across agent
identities, tool calls, RAG pipelines, and MCP servers before they ship.
"""
import os
import re
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .rules import ALL_AGENT_RULES
from .governance import get_governance_mapping
from .ai_bom import AIBOMGenerator

console = Console()

AGENT_FRAMEWORK_PATTERNS = {
    "LangChain / LangGraph": re.compile(r'from langchain|import langchain|from langgraph|import langgraph|@langchain', re.I),
    "CrewAI": re.compile(r'from crewai|import crewai|Crew\(|Agent\(|Task\(', re.I),
    "AutoGen": re.compile(r'from autogen|import autogen|ConversableAgent|AssistantAgent|UserProxyAgent', re.I),
    "LlamaIndex": re.compile(r'from llama_index|import llama_index|VectorStoreIndex|SimpleDirectoryReader', re.I),
    "PydanticAI": re.compile(r'from pydantic_ai|import pydantic_ai|Agent\s*\(|@agent\.', re.I),
    "Semantic Kernel": re.compile(r'semantic_kernel|Kernel\(|sk\.Kernel', re.I),
    "OpenAI Agents SDK": re.compile(r'from openai\.types\.beta|openai\.beta\.assistants|from openai import OpenAI', re.I),
    "Claude Agent SDK / Anthropic": re.compile(r'from anthropic|import anthropic|Anthropic\(|tool_choice', re.I),
    "Vercel AI SDK (JS/TS)": re.compile(r'ai/react|generateText|streamText|createDataStreamResponse', re.I),
    "Mastra (JS/TS)": re.compile(r'@mastra/core|new Agent\(|createMastra', re.I),
    "AWS Strands / Bedrock": re.compile(r'bedrock-runtime|boto3\.client\s*\(\s*[\'"]bedrock', re.I),
    "Haystack": re.compile(r'haystack\.(?:components|pipelines|document_stores)', re.I)
}

LLM_MODEL_PATTERNS = {
    "Claude 3.5 Sonnet / Haiku / Opus": re.compile(r'claude-3-5-(?:sonnet|haiku)|claude-3-(?:opus|sonnet|haiku)', re.I),
    "OpenAI GPT-4o / GPT-4 Turbo / o1 / o3": re.compile(r'gpt-4o(?:-mini)?|gpt-4-turbo|gpt-4|o1-preview|o1-mini|o3-mini', re.I),
    "Google Gemini 1.5 / 2.0 (Flash/Pro)": re.compile(r'gemini-1\.5-(?:flash|pro)|gemini-2\.0-(?:flash|pro)|gemini-pro', re.I),
    "Meta Llama 3 / 3.1 / 3.2 / 3.3": re.compile(r'llama-3(?:\.[123])?-(?:70b|8b|405b|instruct)', re.I),
    "Mistral Large / Codestral / Mixtral": re.compile(r'mistral-large|codestral|mixtral-8x7b|mistral-small', re.I),
    "DeepSeek V3 / R1": re.compile(r'deepseek-chat|deepseek-reasoner|deepseek-r1|deepseek-v3', re.I),
    "Cohere Command R+": re.compile(r'command-r-plus|command-r', re.I),
    "AWS Bedrock / Titan": re.compile(r'amazon\.titan|anthropic\.claude-v2', re.I)
}

IGNORE_DIRS = {
    "node_modules", ".git", ".github", ".venv", "venv", "env", "__pycache__",
    ".pytest_cache", "dist", "build", "target", "bin", "obj", "vendor"
}


class AgentAuditor:
    def __init__(self, target_dir: str = "."):
        self.target_dir = os.path.abspath(target_dir)
        self.rules = ALL_AGENT_RULES
        self.ai_bom_gen = AIBOMGenerator()

    def audit(self) -> Dict[str, Any]:
        """Perform comprehensive AI Agent authorization, tool calls, and surface audit."""
        frameworks_found = set()
        models_found = set()
        tools_found = set()
        vector_stores_found = set()
        all_findings = []
        scanned_files = 0

        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext not in (".py", ".js", ".ts", ".mjs", ".json", ".yaml", ".yml", ".env"):
                    continue

                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, self.target_dir)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    scanned_files += 1

                    # 1. Framework discovery
                    for fw, pat in AGENT_FRAMEWORK_PATTERNS.items():
                        if pat.search(content):
                            frameworks_found.add(fw)

                    # 2. Model discovery
                    for model_name, pat in LLM_MODEL_PATTERNS.items():
                        if pat.search(content):
                            models_found.add(model_name)

                    # 3. Tool naming discovery
                    for tm in re.finditer(r'@tool(?:\s*\([^\)]*\))?\s*\ndef\s+([a-zA-Z0-9_]+)|name\s*=\s*[\'"]([a-zA-Z0-9_-]+)[\'"]\s*,\s*description', content):
                        tool_name = tm.group(1) or tm.group(2)
                        if tool_name:
                            tools_found.add(tool_name)

                    # 4. Vector store discovery
                    from .rules.rag_security import VECTOR_STORE_PATTERNS
                    for vs_name, pat in VECTOR_STORE_PATTERNS.items():
                        if pat.search(content):
                            vector_stores_found.add(vs_name)

                    # 5. Run deep audit rules
                    for rule in self.rules:
                        findings = rule.audit(rel_path, content)
                        all_findings.extend(findings)

                except Exception:
                    pass

        critical_count = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in all_findings if f.get("severity") == "HIGH")
        medium_count = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")
        low_count = sum(1 for f in all_findings if f.get("severity") == "LOW")

        # Score formula (100 is pristine)
        penalty = (critical_count * 30) + (high_count * 15) + (medium_count * 5)
        score = max(0, 100 - penalty)

        return {
            "target_dir": self.target_dir,
            "scanned_files": scanned_files,
            "score": score,
            "frameworks": sorted(list(frameworks_found)),
            "models": sorted(list(models_found)),
            "tools": sorted(list(tools_found)),
            "vector_stores": sorted(list(vector_stores_found)),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "findings": all_findings
        }

    def print_report(self, results: Dict[str, Any], show_governance: bool = True) -> None:
        """Render a rich terminal report of AI Agent findings and scorecard."""
        score = results.get("score", 100)
        grade = "A" if score >= 90 else ("B" if score >= 80 else ("C" if score >= 70 else ("D" if score >= 60 else "F")))
        grade_color = "green" if grade in ("A", "B") else ("yellow" if grade == "C" else "red")

        fw_str = ", ".join(results.get("frameworks", [])) or "None detected"
        models_str = ", ".join(results.get("models", [])) or "None detected"
        vs_str = ", ".join(results.get("vector_stores", [])) or "None detected"

        summary_text = (
            f"[bold {grade_color}]AI Agent Scorecard: Grade {grade} ({score}/100)[/]\n"
            f"[bold cyan]Frameworks:[/] {fw_str}\n"
            f"[bold cyan]Models:[/] {models_str}\n"
            f"[bold cyan]Vector Stores / RAG:[/] {vs_str}\n"
            f"[bold cyan]Identified Tools:[/] {len(results.get('tools', []))} active tools\n"
            f"Findings: [red bold]{results['critical_count']} Critical[/] | "
            f"[orange3]{results['high_count']} High[/] | "
            f"[yellow]{results['medium_count']} Medium[/] | "
            f"[blue]{results['low_count']} Low[/]"
        )
        console.print(Panel(summary_text, title="[bold]MazAPI Agent Audit ? AI Trust & Access Control Map[/]", border_style=grade_color))

        if results.get("findings"):
            table = Table(title="AI Agent Security & Authorization Findings", show_header=True, header_style="bold magenta")
            table.add_column("Severity", style="bold", width=10)
            table.add_column("Finding / Title", style="cyan", width=32)
            table.add_column("Location", style="dim", width=25)
            table.add_column("OWASP LLM (2025)", style="yellow", width=20)
            table.add_column("EU AI Act / NIST", style="green", width=25)

            for f in results["findings"][:25]:
                sev = f.get("severity", "MEDIUM")
                s_color = "red" if sev in ("CRITICAL", "HIGH") else "yellow"
                loc = f"{os.path.basename(f.get('file', ''))}:{f.get('line', 1)}"
                gov = f.get("governance", {})
                owasp = gov.get("owasp_llm", "LLM06")[:20]
                eu_nist = gov.get("eu_ai_act", "Art. 9/14")[:25]

                table.add_row(f"[{s_color}]{sev}[/]", f.get("title", "")[:32], loc, owasp, eu_nist)

            console.print(table)
            if len(results["findings"]) > 25:
                console.print(f"[dim]... and {len(results['findings']) - 25} more findings.[/]")
        else:
            console.print("[green]? No AI agent authorization or access-control vulnerabilities detected.[/]")

    def export_ai_bom(self, results: Dict[str, Any], output_path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        bom_json = self.ai_bom_gen.to_json(
            results.get("frameworks", []),
            results.get("models", []),
            results.get("tools", []),
            results.get("vector_stores", []),
            results.get("findings", [])
        )
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(bom_json)

    def export_sarif(self, results: Dict[str, Any], output_path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        sarif_payload = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "MazAPI Agent Audit",
                            "version": "2.0.0",
                            "informationUri": "https://github.com/apisec-inc/mcp-audit",
                            "rules": [
                                {
                                    "id": f.get("rule_id", "MAZ-AGENT-001"),
                                    "name": f.get("title", ""),
                                    "shortDescription": {"text": f.get("title", "")},
                                    "fullDescription": {"text": f.get("description", "")},
                                    "defaultConfiguration": {"level": "error" if f.get("severity") in ("CRITICAL", "HIGH") else "warning"}
                                }
                                for f in results.get("findings", [])
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.get("rule_id", "MAZ-AGENT-001"),
                            "message": {"text": f.get("title", "") + ": " + f.get("description", "")},
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.get("file", "code")},
                                    "region": {"startLine": f.get("line", 1)}
                                }
                            }]
                        }
                        for f in results.get("findings", [])
                    ]
                }
            ]
        }
        with open(output_path, "w", encoding="utf-8") as f:
            import json
            json.dump(sarif_payload, f, indent=2)
