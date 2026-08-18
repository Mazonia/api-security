"""Integration test suite for MazAPI Unified CLI."""
import json
import os
import subprocess
import sys
import unittest


class TestCLI(unittest.TestCase):
    def run_cli(self, args):
        cmd = [sys.executable, "api-security-project/cli.py"] + args
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.abspath("."))
        return result

    def test_app_surface_cli(self):
        res = self.run_cli(["app-surface", "scan", "api-security-project", "--format", "json"])
        self.assertEqual(res.returncode, 0, f"Error: {res.stderr}")
        data = json.loads(res.stdout)
        self.assertIn("endpoints", data)
        self.assertIn("total_endpoints", data)

    def test_agent_audit_cli(self):
        res = self.run_cli(["agent-audit", "scan", "api-security-project", "--format", "json", "--governance"])
        self.assertEqual(res.returncode, 0, f"Error: {res.stderr}")
        data = json.loads(res.stdout)
        self.assertIn("findings", data)
        self.assertIn("critical_count", data)

    def test_mcp_audit_registry_cli(self):
        res = self.run_cli(["mcp-audit", "registry"])
        self.assertEqual(res.returncode, 0, f"Error: {res.stderr}")
        self.assertIn("Known MCP Server Registry", res.stdout)
        self.assertIn("postgres", res.stdout)

    def test_mcp_audit_explain_cli(self):
        res = self.run_cli(["mcp-audit", "explain", "shell-injection-in-source"])
        self.assertEqual(res.returncode, 0, f"Error: {res.stderr}")
        self.assertIn("Shell Injection in MCP Server", res.stdout)


if __name__ == "__main__":
    unittest.main()
