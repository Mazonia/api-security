"""Compliance and Governance Framework Mappings for AI & Agent Surface Findings."""
from typing import Dict, Any

GOVERNANCE_REGISTRY: Dict[str, Dict[str, Any]] = {
    "shell-injection-in-tool": {
        "title": "Shell Command Execution in Agent Tool",
        "owasp_llm": "LLM06: Excessive Agency / LLM05: Improper Output Handling",
        "eu_ai_act": "Art. 15 (Cybersecurity & Robustness), Art. 14 (Human Oversight)",
        "nist_ai_rmf": "MANAGE 2.4, MEASURE 2.6",
        "iso_42001": "A.10 (Operational Control of AI Systems)"
    },
    "financial-action-tool": {
        "title": "Agent Exposes Financial/Payment Mutation Tools",
        "owasp_llm": "LLM06: Excessive Agency",
        "eu_ai_act": "Art. 9 (Risk Management System), Art. 14 (Human Oversight)",
        "nist_ai_rmf": "GOVERN 1.2, MANAGE 4.1",
        "iso_42001": "A.6 (AI Risk Assessment & Treatment)"
    },
    "database-admin-tool": {
        "title": "Agent Exposes Raw/Administrative Database Tools",
        "owasp_llm": "LLM06: Excessive Agency / LLM02: Sensitive Information Disclosure",
        "eu_ai_act": "Art. 15 (Cybersecurity & Data Governance)",
        "nist_ai_rmf": "MANAGE 2.4",
        "iso_42001": "A.10 (Operational Control)"
    },
    "filesystem-destructive-tool": {
        "title": "Agent Exposes Arbitrary/Destructive File System Tools",
        "owasp_llm": "LLM06: Excessive Agency",
        "eu_ai_act": "Art. 14 (Human Oversight)",
        "nist_ai_rmf": "MANAGE 2.4",
        "iso_42001": "A.10 (Operational Control)"
    },
    "cloud-iam-mutation-tool": {
        "title": "Agent Exposes Cloud Infrastructure or IAM Mutation Tools",
        "owasp_llm": "LLM06: Excessive Agency",
        "eu_ai_act": "Art. 9, Art. 15",
        "nist_ai_rmf": "GOVERN 1.1, MANAGE 2.4",
        "iso_42001": "A.6, A.10"
    },
    "confused-deputy-missing-authz": {
        "title": "Missing Calling-User Authorization Gate (Confused Deputy)",
        "owasp_llm": "LLM06: Excessive Agency / LLM01: Prompt Injection",
        "eu_ai_act": "Art. 14 (Human Oversight & Access Boundaries)",
        "nist_ai_rmf": "MAP 1.1, MANAGE 2.4",
        "iso_42001": "A.8 (Human-in-the-loop & Access Control)"
    },
    "wildcard-tool-permissions": {
        "title": "Agent Granted Broad/Wildcard Tool Permissions",
        "owasp_llm": "LLM06: Excessive Agency",
        "eu_ai_act": "Art. 9 (Risk Minimization)",
        "nist_ai_rmf": "GOVERN 1.2",
        "iso_42001": "A.10 (Principle of Least Privilege)"
    },
    "unbounded-multi-agent-delegation": {
        "title": "Unconstrained Multi-Agent Delegation & Trust Boundary Bypass",
        "owasp_llm": "LLM06: Excessive Agency / LLM01: Indirect Prompt Injection",
        "eu_ai_act": "Art. 14 (Human-in-the-loop Oversight)",
        "nist_ai_rmf": "MANAGE 4.1",
        "iso_42001": "A.8 (AI Agent Interoperability Controls)"
    },
    "prompt-injection-sink": {
        "title": "Dynamic External Prompt Interpolation into Tool Calls",
        "owasp_llm": "LLM01: Prompt Injection / LLM05: Improper Output Handling",
        "eu_ai_act": "Art. 15 (Cybersecurity & Adversarial Robustness)",
        "nist_ai_rmf": "MEASURE 2.6",
        "iso_42001": "A.9 (Robustness against Adversarial Attacks)"
    },
    "rag-cross-tenant-isolation-gap": {
        "title": "Vector Store Retrieval Lacks Tenant Isolation Filter",
        "owasp_llm": "LLM08: Vector and Embedding Weaknesses / LLM02: Sensitive Info Disclosure",
        "eu_ai_act": "Art. 10 (Data Governance), Art. 15",
        "nist_ai_rmf": "MEASURE 2.6",
        "iso_42001": "A.10 (Data Protection in AI Systems)"
    },
    "rag-external-poisoning-surface": {
        "title": "RAG Pipeline Ingests Untrusted External Sources",
        "owasp_llm": "LLM04: Data and Model Poisoning",
        "eu_ai_act": "Art. 10 (Data Governance & Quality Controls)",
        "nist_ai_rmf": "MAP 2.2, MEASURE 2.6",
        "iso_42001": "A.10 (Data Integrity Verification)"
    },
    "hardcoded-ai-provider-key": {
        "title": "Hardcoded AI Provider API Key in Repository",
        "owasp_llm": "LLM02: Sensitive Information Disclosure",
        "eu_ai_act": "Art. 15 (Cybersecurity & Key Management)",
        "nist_ai_rmf": "GOVERN 1.1",
        "iso_42001": "A.9 (Information Security Management)"
    },
    "cyber-physical-actuation-tool": {
        "title": "Unconstrained Cyber-Physical IoT Actuation Tool",
        "owasp_llm": "LLM06: Excessive Agency / IoT OWASP Top 10",
        "eu_ai_act": "Art. 14 (Human Oversight for Cyber-Physical AI)",
        "nist_ai_rmf": "MANAGE 2.4, GOVERN 1.2",
        "iso_42001": "A.10 (Operational Control of Physical Actuators)"
    },
    "unencrypted-iot-telemetry-tool": {
        "title": "Unencrypted IoT Telemetry / Protocol Communication",
        "owasp_llm": "LLM02: Sensitive Information Disclosure",
        "eu_ai_act": "Art. 15 (Cybersecurity & Encryption)",
        "nist_ai_rmf": "MEASURE 2.6",
        "iso_42001": "A.9 (Data Transport Protection)"
    },
    "unsigned-ota-firmware-tool": {
        "title": "Unsigned OTA Firmware Update Tool Capability",
        "owasp_llm": "LLM06: Excessive Agency / OWASP IoT I3",
        "eu_ai_act": "Art. 15 (Hardware & Firmware Integrity)",
        "nist_ai_rmf": "MANAGE 2.4",
        "iso_42001": "A.10 (Software & Firmware Supply Chain Control)"
    }
}


def get_governance_mapping(rule_id: str) -> Dict[str, Any]:
    return GOVERNANCE_REGISTRY.get(rule_id, {
        "title": "General AI Surface Finding",
        "owasp_llm": "OWASP Top 10 for LLM (2025)",
        "eu_ai_act": "EU AI Act Art. 9 / 15",
        "nist_ai_rmf": "NIST AI RMF MANAGE",
        "iso_42001": "ISO/IEC 42001"
    })
