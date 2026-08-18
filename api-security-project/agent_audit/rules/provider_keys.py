"""AI Provider Key & Secret Exposure Audit Rule."""
import re
from typing import Dict, List, Any
from ..governance import get_governance_mapping

PROVIDER_KEY_PATTERNS = [
    ("OpenAI API Key", r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}", "OPENAI_API_KEY", "Rotate key in OpenAI Dashboard and move to secrets manager."),
    ("Anthropic API Key", r"sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{30,}", "ANTHROPIC_API_KEY", "Revoke key in Anthropic Console and use environment variable."),
    ("Google Gemini Key", "AIzaSy[A-Za-z0-9_-]{33}", "GEMINI_API_KEY", "Restrict key in Google Cloud Console / AI Studio."),
    ("HuggingFace Token", "hf_[A-Za-z0-9]{34,}", "HUGGINGFACE_TOKEN", "Revoke token in HuggingFace Settings."),
    ("Groq API Key", "gsk_[A-Za-z0-9]{48,}", "GROQ_API_KEY", "Rotate key in Groq Console."),
    ("Mistral API Key", "mistral_[a-zA-Z0-9]{32,}", "MISTRAL_API_KEY", "Rotate key in Mistral Console."),
    ("Cohere API Key", "cohere_[A-Za-z0-9]{32,}", "CO_API_KEY", "Rotate in Cohere Dashboard."),
    ("Perplexity API Key", "pplx-[a-zA-Z0-9]{48,}", "PPLX_API_KEY", "Rotate in Perplexity Settings.")
]


class ProviderKeysRule:
    def audit(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []

        for provider_name, pattern_str, env_var, remedy in PROVIDER_KEY_PATTERNS:
            pattern = re.compile(pattern_str)
            for m in pattern.finditer(content):
                val = m.group(0)
                masked_val = val[:6] + "..." + val[-4:]
                line_no = content[:m.start()].count("\n") + 1
                gov = get_governance_mapping("hardcoded-ai-provider-key")

                findings.append({
                    "rule_id": "hardcoded-ai-provider-key",
                    "title": f"Hardcoded {provider_name} Exposed in Code",
                    "severity": "CRITICAL",
                    "file": file_path,
                    "line": line_no,
                    "masked_value": masked_val,
                    "remediation": remedy,
                    "env_variable": env_var,
                    "description": f"Raw {provider_name} found hardcoded. Secrets must be supplied via `{env_var}`.",
                    "governance": gov
                })

        return findings
