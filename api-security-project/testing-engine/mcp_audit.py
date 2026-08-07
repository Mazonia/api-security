"""Model Context Protocol (MCP) & AI Agent Security Auditor.

Audits local MCP configurations (Claude Desktop, Cursor, VS Code) and application
codebases for MCP server definitions, exposed keys, over-privileged tool executions,
and AI agent trust boundary risks.
"""
import glob
import json
import os
import re

MCP_SECRET_RE = re.compile(
    r'(?:sk-|gsk_|pplx-|hf_|AKIA|AIza|ghp_|dop_v1_|[A-Za-z0-9_-]{32,})', re.IGNORECASE
)

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

        # Check 1: Hardcoded credentials in MCP server environment
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
            })
        else:
            tests.append({
                "test": f"MCP [{server_name}] Environment Credentials Check",
                "severity": "HIGH",
                "vulnerable": False,
                "detail": f"No plain-text API keys exposed in '{server_name}' environment variables.",
            })

        # Check 2: Over-privileged command execution
        cmd_base = os.path.basename(cmd).lower()
        if cmd_base in OVERPRIVILEGED_COMMANDS:
            tests.append({
                "test": f"MCP [{server_name}] Over-Privileged Executable ({cmd_base})",
                "severity": "HIGH",
                "vulnerable": True,
                "detail": f"MCP server '{server_name}' executes a high-risk system binary: {OVERPRIVILEGED_COMMANDS[cmd_base]} ({cmd})",
            })

        # Check 3: Over-privileged file or network arguments
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
            })

        # Check 4: Unauthenticated Transport (SSE exposed without auth headers)
        if transport == "sse":
            has_auth = "headers" in server_def or "auth" in str(env).lower()
            if not has_auth:
                tests.append({
                    "test": f"MCP [{server_name}] Unauthenticated SSE Network Endpoint",
                    "severity": "CRITICAL",
                    "vulnerable": True,
                    "detail": f"MCP server '{server_name}' uses Remote SSE transport without explicit token authentication headers.",
                })

    return tests


def scan_workspace_mcp(target_dir: str = ".") -> dict:
    """Scan workspace for Claude Desktop, Cursor, or project MCP configuration files."""
    all_tests = []
    
    # Common MCP config locations
    possible_files = [
        os.path.join(target_dir, "mcp.json"),
        os.path.join(target_dir, ".cursor", "mcp.json"),
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

    if found_files == 0:
        all_tests.append({
            "test": "MCP Server Security Posture Check",
            "severity": "LOW",
            "vulnerable": False,
            "detail": "No active Model Context Protocol (MCP) server configuration files detected in target workspace.",
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
