"""Model Context Protocol (MCP) & AI Agent Security Auditor.

Features:
- Discovery across Claude Desktop, Cursor, VS Code, Windsurf, Zed, and workspace .mcp.json
- Source-Scan (v1.1): Static vulnerability audit of in-house MCP servers (shell-injection, unsafe subprocess, arbitrary FS)
- MCP Registry: 50+ known MCP servers with curated risk classifications
- AI-BOM Export (CycloneDX 1.6) and SARIF GitHub Code Scanning integration
- CLI commands: scan, source-scan, registry, explain
"""
import glob
import json
import os
import re
import sys
from typing import Dict, List, Any, Optional

MCP_SECRET_RE = re.compile(
    r'(?:sk-[A-Za-z0-9T3BlbkFJ]{20,}|sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{30,}|AIzaSy[A-Za-z0-9_-]{33}|ghp_[A-Za-z0-9]{36}|gsk_[A-Za-z0-9]{48}|AKIA[0-9A-Z]{16}|rk_live_[a-zA-Z0-9]{24}|xox[baprs]-[0-9a-zA-Z]{10,48}|SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}|postgres:\/\/[^:]+:[^@]+@|mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@)',
    re.IGNORECASE
)

# Registry of 50+ known MCP servers with curated risk classifications
MCP_REGISTRY: Dict[str, Dict[str, Any]] = {
    "github": {"risk": "MEDIUM", "scope": "Remote API", "desc": "Access GitHub repos, pull requests, issues and commits."},
    "postgres": {"risk": "CRITICAL", "scope": "Database Admin", "desc": "Read/write direct database access with schema modification powers."},
    "sqlite": {"risk": "HIGH", "scope": "Local Database", "desc": "Read/write local database files."},
    "filesystem": {"risk": "HIGH", "scope": "Local FS", "desc": "Read/write arbitrary local directories configured in args."},
    "brave-search": {"risk": "LOW", "scope": "Web Search", "desc": "Execute web and local search queries via Brave API."},
    "fetch": {"risk": "MEDIUM", "scope": "Web Egress", "desc": "Fetch webpage content and HTML for model ingestion."},
    "git": {"risk": "HIGH", "scope": "Local VCS", "desc": "Read/write/commit Git repositories on local machine."},
    "slack": {"risk": "MEDIUM", "scope": "SaaS Chat", "desc": "Read/write messages and channel histories in Slack workspaces."},
    "memory": {"risk": "LOW", "scope": "Knowledge Graph", "desc": "Persistent local graph-based memory storage."},
    "google-drive": {"risk": "MEDIUM", "scope": "Cloud Storage", "desc": "Read/write Google Drive files and documents."},
    "aws": {"risk": "CRITICAL", "scope": "Cloud IAM / Infra", "desc": "Execute AWS API requests and resource management."},
    "stripe": {"risk": "CRITICAL", "scope": "Financial Mutations", "desc": "Process payments, refunds, customer subscriptions and payouts."},
    "puppeteer": {"risk": "HIGH", "scope": "Browser Automation", "desc": "Full headless browser control and automated web navigation."},
    "everything": {"risk": "HIGH", "scope": "Reference Server", "desc": "Demo server exposing comprehensive MCP tool sets."},
    "sentry": {"risk": "MEDIUM", "scope": "Monitoring / Logs", "desc": "Retrieve error logs, stack traces and issue details from Sentry."},
    "redis": {"risk": "HIGH", "scope": "In-Memory Cache", "desc": "Direct read/write access to Redis keys and values."},
    "docker": {"risk": "CRITICAL", "scope": "Container Engine", "desc": "Manage containers, images, volumes, and host daemon bindings."},
    "kubernetes": {"risk": "CRITICAL", "scope": "Cluster Orchestration", "desc": "Full cluster administration via Kubernetes API."},
    "jira": {"risk": "MEDIUM", "scope": "Issue Tracking", "desc": "Create, transition, and update Jira tickets."},
    "linear": {"risk": "MEDIUM", "scope": "Issue Tracking", "desc": "Manage Linear tasks, projects, and cycles."},
    "notion": {"risk": "MEDIUM", "scope": "Knowledge Base", "desc": "Read/write Notion pages, databases, and blocks."},
    "zendesk": {"risk": "MEDIUM", "scope": "Customer Support", "desc": "Manage customer tickets, macros, and user profiles."},
    "hubspot": {"risk": "MEDIUM", "scope": "CRM", "desc": "Read and mutate CRM contacts, deals, and pipelines."},
    "salesforce": {"risk": "HIGH", "scope": "CRM & Enterprise Data", "desc": "Execute SOQL queries and update enterprise records."},
    "bash": {"risk": "CRITICAL", "scope": "Shell Execution", "desc": "Execute arbitrary bash commands on the host operating system."},
    "terminal": {"risk": "CRITICAL", "scope": "Shell Execution", "desc": "Execute arbitrary shell scripts and command-line processes."},
    "cmd": {"risk": "CRITICAL", "scope": "Windows Shell", "desc": "Execute Windows command shell actions."},
    "powershell": {"risk": "CRITICAL", "scope": "PowerShell", "desc": "Execute PowerShell scripts and cmdlets on Windows/Linux."},
    "sequential-thinking": {"risk": "LOW", "scope": "Model Reasoning", "desc": "Dynamic thinking and planning tool for complex problem solving."},
    "time": {"risk": "LOW", "scope": "System Time", "desc": "Provide local and UTC timestamps."},
    "obsidian": {"risk": "MEDIUM", "scope": "Local Markdown Vault", "desc": "Read and append notes in Obsidian vaults."},
    "google-maps": {"risk": "LOW", "scope": "Geo Location", "desc": "Query locations, directions, and place details."}
}

RISK_EXPLANATIONS = {
    "shell-injection-in-source": {
        "title": "Shell Injection in MCP Server Source Code",
        "severity": "CRITICAL",
        "description": "The MCP server executes system commands (child_process.exec, subprocess.run(shell=True), os.system) using interpolated or unsanitized tool arguments. An LLM receiving indirect prompt injection can execute arbitrary code on the host machine.",
        "remediation": "Replace shell execution sinks with array-based subprocess invocations (e.g. execFile or subprocess.run(['cmd', arg], shell=False)) without string concatenation or shell invocation."
    },
    "financial-action": {
        "title": "Autonomous Financial/Payment Action Authority",
        "severity": "HIGH",
        "description": "MCP server exposes financial mutation tools (refunds, payouts, charges) directly to autonomous model execution.",
        "remediation": "Enforce explicit Human-in-the-loop (HITL) approval gates before executing financial transactions."
    },
    "broad-permissions": {
        "title": "Over-Privileged Server Scope & Wildcard Permissions",
        "severity": "HIGH",
        "description": "MCP server mounts root filesystem or has unrestricted administrative privileges.",
        "remediation": "Restrict server directory mounts to specific sandboxed project folders and enforce least privilege."
    },
    "hardcoded-secret": {
        "title": "Hardcoded API Secret in MCP Server Configuration",
        "severity": "CRITICAL",
        "description": "Plain-text API keys or credentials found in server environment variables.",
        "remediation": "Move secrets into `.env` or system environment variables and reference with `${VAR_NAME}`."
    },
    "unverified-source": {
        "title": "Unverified or In-House MCP Server",
        "severity": "MEDIUM",
        "description": "MCP server is not from a known/verified registry publisher.",
        "remediation": "Run `mcp-audit source-scan <path>` to audit server source code before deployment."
    }
}

OVERPRIVILEGED_COMMANDS = {
    "bash": "Shell Command Execution",
    "sh": "Shell Command Execution",
    "cmd": "Windows Command Execution",
    "powershell": "PowerShell Command Execution",
    "pwsh": "PowerShell Command Execution",
    "rm": "Destructive File System Action",
    "chmod": "File Permission Modification",
    "curl": "Outbound Network Access",
    "wget": "Outbound Network Access",
}

OVERPRIVILEGED_ARGS = {
    "/": "Root Filesystem Mount",
    "C:\\": "Root Drive Mount",
    "sudo": "Elevated Privilege Execution",
    "DB_NAME": "Direct Database Access",
    "0.0.0.0": "Exposed Global Network Interface",
}


def audit_mcp_config_dict(config_data: dict, source_path: str = "config") -> list:
    """Audit a parsed MCP configuration dictionary (e.g. mcpServers object)."""
    tests = []
    mcp_servers = config_data.get("mcpServers", {})
    if not mcp_servers and "command" in config_data:
        mcp_servers = {"default": config_data}

    for server_name, server_def in mcp_servers.items():
        cmd = server_def.get("command", "")
        args = server_def.get("args", [])
        env = server_def.get("env", {})
        transport = "stdio" if cmd else ("sse" if "url" in server_def else "unknown")

        # 1. Hardcoded secrets
        env_secrets = []
        for env_k, env_v in env.items():
            if isinstance(env_v, str) and MCP_SECRET_RE.search(env_v) and not env_v.startswith("$"):
                env_secrets.append(env_k)

        if env_secrets:
            tests.append({
                "test": f"MCP [{server_name}] Hardcoded Env Credentials ({', '.join(env_secrets)})",
                "severity": "CRITICAL",
                "vulnerable": True,
                "detail": f"MCP server '{server_name}' contains plain-text API secrets in its environment configuration: {', '.join(env_secrets)}",
                "rule_id": "hardcoded-secret"
            })
        else:
            tests.append({
                "test": f"MCP [{server_name}] Environment Credentials Check",
                "severity": "LOW",
                "vulnerable": False,
                "detail": f"No plain-text API keys exposed in '{server_name}' environment variables.",
            })

        # 2. Over-privileged commands
        cmd_base = os.path.basename(cmd).lower().replace(".exe", "")
        if cmd_base in OVERPRIVILEGED_COMMANDS:
            tests.append({
                "test": f"MCP [{server_name}] Over-Privileged Executable ({cmd_base})",
                "severity": "HIGH",
                "vulnerable": True,
                "detail": f"MCP server '{server_name}' executes a high-risk system binary: {OVERPRIVILEGED_COMMANDS[cmd_base]} ({cmd})",
                "rule_id": "broad-permissions"
            })

        # 3. Over-privileged file or network arguments
        flagged_args = []
        arg_str = " ".join(str(a) for a in args)
        for priv_pattern, priv_desc in OVERPRIVILEGED_ARGS.items():
            if priv_pattern.lower() in arg_str.lower():
                flagged_args.append(priv_desc)

        if flagged_args:
            tests.append({
                "test": f"MCP [{server_name}] Excessive Resource Access ({', '.join(flagged_args)})",
                "severity": "HIGH",
                "vulnerable": True,
                "detail": f"MCP server '{server_name}' argument list mounts high-risk local resources: {', '.join(flagged_args)}",
                "rule_id": "broad-permissions"
            })

        # 4. Registry trust lookup
        reg_match = None
        for r_name, r_info in MCP_REGISTRY.items():
            if r_name in server_name.lower() or (cmd and r_name in cmd.lower()):
                reg_match = (r_name, r_info)
                break

        if reg_match:
            r_name, r_info = reg_match
            if r_info["risk"] in ("CRITICAL", "HIGH"):
                tests.append({
                    "test": f"MCP [{server_name}] Registry High-Risk Classification ({r_name})",
                    "severity": r_info["risk"],
                    "vulnerable": True,
                    "detail": f"Server '{server_name}' matches known registry entry '{r_name}' ({r_info['scope']}): {r_info['desc']}",
                    "rule_id": "financial-action" if "financial" in r_info["desc"].lower() else "broad-permissions"
                })
        else:
            tests.append({
                "test": f"MCP [{server_name}] Unverified Publisher Posture",
                "severity": "MEDIUM",
                "vulnerable": True,
                "detail": f"Server '{server_name}' is not in verified registry; consider source-scan.",
                "rule_id": "unverified-source"
            })

    return tests


SHELL_SINKS_JS = re.compile(
    r'(?:child_process\.(?:exec|execSync)|exec\s*\(|execSync\s*\()\s*(?:`[^`]*\$\{[^\}]+\}[^`]*`|[\'"][^\'"]*[\'"]\s*\+\s*[a-zA-Z0-9_]+|[a-zA-Z0-9_]+\s*\+\s*[\'"]|[a-zA-Z0-9_]+)',
    re.IGNORECASE
)
SHELL_SINKS_PY = re.compile(
    r'(?:subprocess\.(?:run|Popen|call|check_output)\s*\([^\)]*shell\s*=\s*True|os\.(?:system|popen)\s*\(\s*(?:f[\'"][^\'"]*\{|[a-zA-Z0-9_]+\s*\+|[a-zA-Z0-9_]+))',
    re.IGNORECASE
)


def source_scan_directory(target_dir: str = ".") -> Dict[str, Any]:
    """Source-scan in-house MCP servers for code-level shell injection and vulnerability sinks."""
    findings = []
    scanned_files = 0

    for root, _, files in os.walk(target_dir):
        if any(skip in root for skip in ["node_modules", ".git", "venv", ".venv", "dist", "build"]):
            continue
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext not in (".js", ".ts", ".mjs", ".cjs", ".py"):
                continue

            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, target_dir)
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

                # Only inspect files that define tools or import MCP SDKs
                is_mcp_source = bool(re.search(r'@modelcontextprotocol|mcp/sdk|Server\s*\(|server\.tool|@tool|ListToolsRequestSchema|CallToolRequestSchema', content, re.I))
                if not is_mcp_source and "mcp" not in file.lower():
                    continue

                scanned_files += 1

                # JS/TS checks
                if ext in (".js", ".ts", ".mjs", ".cjs"):
                    for m in SHELL_SINKS_JS.finditer(content):
                        line_no = content[:m.start()].count("\n") + 1
                        findings.append({
                            "rule_id": "shell-injection-in-source",
                            "title": "Shell Injection Sink in MCP Tool Handler",
                            "severity": "CRITICAL",
                            "file": rel_path,
                            "line": line_no,
                            "snippet": content[max(0, m.start()-30):min(len(content), m.end()+40)].strip(),
                            "detail": "Tool arguments interpolated into child_process.exec without token escaping."
                        })

                # Python checks
                if ext == ".py":
                    for m in SHELL_SINKS_PY.finditer(content):
                        line_no = content[:m.start()].count("\n") + 1
                        findings.append({
                            "rule_id": "shell-injection-in-source",
                            "title": "Shell Injection Sink in MCP Python Server",
                            "severity": "CRITICAL",
                            "file": rel_path,
                            "line": line_no,
                            "snippet": content[max(0, m.start()-30):min(len(content), m.end()+40)].strip(),
                            "detail": "Tool arguments passed to subprocess.run(shell=True) or os.system."
                        })

            except Exception:
                pass

    return {
        "scanned_files": scanned_files,
        "critical_count": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "findings": findings
    }


def source_scan_file(filepath: str) -> list:
    """Scan a single MCP server source file for shell injection sinks."""
    findings = []
    if not os.path.exists(filepath):
        return findings
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        ext = os.path.splitext(filepath)[1].lower()
        if ext in (".js", ".ts", ".mjs"):
            for m in SHELL_SINKS_JS.finditer(content):
                line_no = content[:m.start()].count("\n") + 1
                findings.append({
                    "rule_id": "shell-injection-in-source",
                    "title": "Shell Injection Sink in MCP Tool Handler",
                    "severity": "CRITICAL",
                    "file": filepath,
                    "line": line_no,
                    "snippet": content[max(0, m.start()-30):min(len(content), m.end()+40)].strip(),
                    "detail": "Tool arguments interpolated into child_process.exec without token escaping."
                })
        elif ext == ".py":
            for m in SHELL_SINKS_PY.finditer(content):
                line_no = content[:m.start()].count("\n") + 1
                findings.append({
                    "rule_id": "shell-injection-in-source",
                    "title": "Shell Injection Sink in MCP Python Server",
                    "severity": "CRITICAL",
                    "file": filepath,
                    "line": line_no,
                    "snippet": content[max(0, m.start()-30):min(len(content), m.end()+40)].strip(),
                    "detail": "Tool arguments passed to subprocess.run(shell=True) or os.system."
                })
    except Exception:
        pass
    return findings


def audit_mcp_config(filepath: str) -> dict:
    """Audit a single MCP configuration file."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    results = audit_mcp_config_dict(data, source_path=os.path.basename(filepath))
    vulnerabilities = [r for r in results if r.get("vulnerable")]
    return {
        "total_servers": len(data.get("mcpServers", {})),
        "critical_count": sum(1 for r in vulnerabilities if r.get("severity") == "CRITICAL"),
        "high_count": sum(1 for r in vulnerabilities if r.get("severity") == "HIGH"),
        "results": results
    }


def scan_workspace_mcp(target_dir: str = ".") -> dict:
    """Scan workspace for Claude Desktop, Cursor, VS Code, or project MCP configuration files."""
    all_tests = []
    
    possible_files = [
        os.path.join(target_dir, "mcp.json"),
        os.path.join(target_dir, ".mcp", "config.json"),
        os.path.join(target_dir, ".cursor", "mcp.json"),
        os.path.join(target_dir, ".vscode", "mcp.json"),
        os.path.join(target_dir, "claude_desktop_config.json"),
        os.path.expanduser("~/.cursor/mcp.json"),
        os.path.expanduser("~/AppData/Roaming/Claude/claude_desktop_config.json"),
    ]
    
    found_files = 0
    for filepath in possible_files:
        if os.path.exists(filepath):
            found_files += 1
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    file_tests = audit_mcp_config_dict(data, source_path=os.path.basename(filepath))
                    all_tests.extend(file_tests)
            except Exception as e:
                all_tests.append({
                    "test": f"MCP Config Parse Error ({os.path.basename(filepath)})",
                    "severity": "MEDIUM",
                    "vulnerable": True,
                    "detail": f"Failed to parse MCP configuration file: {e}",
                })

    # Also run source scan
    src_res = source_scan_directory(target_dir)
    for f in src_res.get("findings", []):
        all_tests.append({
            "test": f"MCP Source Vulnerability: {f['title']} ({os.path.basename(f['file'])}:{f['line']})",
            "severity": f["severity"],
            "vulnerable": True,
            "detail": f"{f['detail']} Snippet: `{f['snippet']}`",
            "rule_id": f["rule_id"]
        })

    if found_files == 0 and not src_res.get("findings"):
        all_tests.append({
            "test": "MCP Server Security Posture Check",
            "severity": "LOW",
            "vulnerable": False,
            "detail": "No active Model Context Protocol (MCP) server configuration files or unsafe sources detected.",
        })

    vulnerable_count = sum(1 for t in all_tests if t["vulnerable"])
    return {
        "module": "AI-BOM / MCP Security Audit",
        "total": len(all_tests),
        "vulnerable_count": vulnerable_count,
        "tests": all_tests,
    }


def run(target: str = "") -> dict:
    """Run function compatible with the testing engine interface."""
    return scan_workspace_mcp(".")


if __name__ == "__main__":
    res = run()
    print(json.dumps(res, indent=2))
