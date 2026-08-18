"""Unit & Integration Tests for MazAPI Agent Audit."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath("api-security-project"))
from agent_audit.auditor import AgentAuditor
from agent_audit.rules.excessive_agency import ExcessiveAgencyRule
from agent_audit.rules.authz_gaps import AuthorizationGapsRule
from agent_audit.rules.tool_injection import ToolInjectionRule
from agent_audit.rules.rag_security import RagSecurityRule
from agent_audit.rules.provider_keys import ProviderKeysRule
from agent_audit.ai_bom import AIBOMGenerator


class TestAgentAudit(unittest.TestCase):
    def test_excessive_agency_shell_and_stripe(self):
        code = '''
from langchain.tools import tool
import subprocess

@tool
def execute_shell(command: str) -> str:
    """Executes arbitrary bash command."""
    return subprocess.run(command, shell=True)

@tool
def refund_customer(charge_id: str, amount: int):
    return stripe.Refund.create(charge=charge_id, amount=amount)
'''
        rule = ExcessiveAgencyRule()
        findings = rule.audit("tools/agent_tools.py", code)
        self.assertEqual(len(findings), 2)
        shell_finding = [f for f in findings if f["rule_id"] == "shell-injection-in-tool"][0]
        self.assertEqual(shell_finding["severity"], "CRITICAL")

        stripe_finding = [f for f in findings if f["rule_id"] == "financial-action-tool"][0]
        self.assertEqual(stripe_finding["severity"], "HIGH")

    def test_authorization_gaps_confused_deputy(self):
        code = '''
@tool
def delete_user_record(user_id: str):
    # Missing verification if the calling user owns user_id
    db.client.delete(user_id)
'''
        rule = AuthorizationGapsRule()
        findings = rule.audit("agent.py", code)
        self.assertTrue(any(f["rule_id"] == "confused-deputy-missing-authz" for f in findings))

    def test_tool_injection_sink(self):
        code = '''
def run_query(user_prompt):
    os.system(f"grep {user_prompt} logs.txt")
'''
        rule = ToolInjectionRule()
        findings = rule.audit("search.py", code)
        self.assertTrue(any(f["rule_id"] == "prompt-injection-sink" for f in findings))

    def test_rag_security_missing_tenant_filter(self):
        code = '''
import pinecone
from langchain_community.vectorstores import Pinecone

def query_vector_db(user_query):
    docs = vectorstore.similarity_search(user_query, k=5)
    return docs
'''
        rule = RagSecurityRule()
        findings = rule.audit("rag.py", code)
        self.assertTrue(any(f["rule_id"] == "rag-cross-tenant-isolation-gap" for f in findings))

    def test_provider_key_masked_detection(self):
        code = 'OPENAI_API_KEY = "sk-proj-abc123456789012345678901234567890"'
        rule = ProviderKeysRule()
        findings = rule.audit("config.py", code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "hardcoded-ai-provider-key")
        self.assertTrue("..." in findings[0]["masked_value"])

    def test_ai_bom_generation(self):
        gen = AIBOMGenerator()
        bom = gen.generate(
            frameworks=["LangChain", "CrewAI"],
            models=["gpt-4o", "claude-3-5-sonnet"],
            tools=["execute_shell", "refund_customer"],
            vector_stores=["Pinecone"],
            findings=[{"title": "Shell injection", "severity": "CRITICAL", "description": "Shell tool", "file": "tools.py"}]
        )
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.6")
        self.assertEqual(len(bom["components"]), 7)
        self.assertEqual(len(bom["vulnerabilities"]), 1)


if __name__ == "__main__":
    unittest.main()
