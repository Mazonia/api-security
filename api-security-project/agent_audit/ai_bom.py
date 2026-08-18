"""CycloneDX 1.6 AI-BOM (Artificial Intelligence Bill of Materials) Generator."""
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any


class AIBOMGenerator:
    def generate(self, frameworks: List[str], models: List[str], tools: List[str], vector_stores: List[str], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        bom_id = f"urn:uuid:{uuid.uuid4()}"
        components = []

        # 1. Framework components
        for fw in set(frameworks):
            components.append({
                "type": "framework",
                "name": fw,
                "version": "latest",
                "description": f"AI Agent Framework: {fw}",
                "properties": [{"name": "category", "value": "agent-framework"}]
            })

        # 2. Model components
        for m in set(models):
            components.append({
                "type": "machine-learning-model",
                "name": m,
                "version": "current",
                "description": f"Foundation LLM: {m}",
                "properties": [{"name": "category", "value": "llm-model"}]
            })

        # 3. Vector stores
        for vs in set(vector_stores):
            components.append({
                "type": "data",
                "name": vs,
                "description": f"Vector Store / RAG Backend: {vs}",
                "properties": [{"name": "category", "value": "vector-database"}]
            })

        # 4. Tools & Functions
        for t in set(tools):
            components.append({
                "type": "library",
                "name": t,
                "description": f"Agent Tool / Skill: {t}",
                "properties": [{"name": "category", "value": "agent-tool"}]
            })

        # Format CycloneDX 1.6
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": bom_id,
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "MazAPI",
                        "name": "Agent Audit & AI Surface Scanner",
                        "version": "2.0.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": "AI-Agent-Application",
                    "version": "1.0.0"
                }
            },
            "components": components,
            "vulnerabilities": [
                {
                    "id": f"MAZ-AI-{idx+1:03d}",
                    "source": {"name": "MazAPI Agent Audit"},
                    "ratings": [{"severity": f.get("severity", "MEDIUM").lower()}],
                    "description": f.get("description", ""),
                    "detail": f.get("title", ""),
                    "recommendation": f.get("governance", {}).get("eu_ai_act", ""),
                    "affects": [{"ref": f.get("file", "")}]
                }
                for idx, f in enumerate(findings)
            ]
        }

    def to_json(self, frameworks: List[str], models: List[str], tools: List[str], vector_stores: List[str], findings: List[Dict[str, Any]]) -> str:
        data = self.generate(frameworks, models, tools, vector_stores, findings)
        return json.dumps(data, indent=2)
