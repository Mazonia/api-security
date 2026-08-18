"""Unit & Integration Tests for MazAPI MCP Audit."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath("api-security-project/testing-engine"))
import mcp_audit


class TestMCPAudit(unittest.TestCase):
    def test_registry_lookup(self):
        self.assertIn("fetch", mcp_audit.MCP_REGISTRY)
        self.assertIn("filesystem", mcp_audit.MCP_REGISTRY)
        self.assertEqual(mcp_audit.MCP_REGISTRY["filesystem"]["risk"], "HIGH")
        self.assertEqual(mcp_audit.MCP_REGISTRY["fetch"]["risk"], "MEDIUM")

    def test_source_scan_python_shell_injection(self):
        code = '''
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("demo")

@mcp.tool()
def run_cli_command(command: str) -> str:
    # Dangerous shell injection sink
    res = subprocess.run(command, shell=True, capture_output=True, text=True)
    return res.stdout
'''
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(code)
            tmp_path = f.name

        try:
            findings = mcp_audit.source_scan_file(tmp_path)
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0]["severity"], "CRITICAL")
            self.assertIn("shell=True", findings[0]["snippet"])
        finally:
            os.remove(tmp_path)

    def test_source_scan_node_shell_injection(self):
        code = '''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "child_process";

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.tool("exec_cmd", { cmd: z.string() }, async ({ cmd }) => {
    return new Promise((resolve) => {
        exec(cmd, (err, stdout) => resolve({ content: [{ type: "text", text: stdout }] }));
    });
});
'''
        with tempfile.NamedTemporaryFile("w", suffix=".ts", delete=False) as f:
            f.write(code)
            tmp_path = f.name

        try:
            findings = mcp_audit.source_scan_file(tmp_path)
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0]["severity"], "CRITICAL")
        finally:
            os.remove(tmp_path)

    def test_config_scan_with_known_servers(self):
        config_data = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:/"]
                },
                "fetch": {
                    "command": "uvx",
                    "args": ["mcp-server-fetch"]
                }
            }
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            tmp_path = f.name

        try:
            res = mcp_audit.audit_mcp_config(tmp_path)
            self.assertEqual(res["total_servers"], 2)
            self.assertTrue(res["high_count"] > 0)
        finally:
            os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
