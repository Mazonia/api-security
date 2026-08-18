"""SARIF 2.1.0 Exporter for App Surface findings."""
import json
from typing import Dict, List, Any


class AppSurfaceSarifExporter:
    def to_sarif(self, endpoints: List[Dict[str, Any]], shadow_endpoints: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        rules = [
            {
                "id": "MAZAPI-SURFACE-001",
                "name": "BFLAUnprotectedAdminRoute",
                "shortDescription": {"text": "Administrative route exposed without explicit authorization guard."},
                "fullDescription": {"text": "Endpoint path indicates privileged administrative or internal functionality, but no authentication or authorization decorator/middleware was detected."},
                "defaultConfiguration": {"level": "error"},
                "help": {"text": "Add authorization middleware or authentication guard (@Authorize, @login_required, etc.)."}
            },
            {
                "id": "MAZAPI-SURFACE-002",
                "name": "BOLACandidateObjectIdentifier",
                "shortDescription": {"text": "Route contains object identifier parameter without detected authorization check."},
                "fullDescription": {"text": "Path contains variable object identifier (e.g. {id}, :userId) with potential Broken Object Level Authorization risk if access control is missing in the handler."},
                "defaultConfiguration": {"level": "warning"},
                "help": {"text": "Ensure fine-grained object ownership verification is enforced for the requested object ID."}
            },
            {
                "id": "MAZAPI-SURFACE-003",
                "name": "ShadowUndocumentedAPI",
                "shortDescription": {"text": "API endpoint exists in source code but is undocumented in OpenAPI/Swagger specs."},
                "fullDescription": {"text": "Shadow or rogue endpoint found in repository code that does not exist in the committed OpenAPI specification."},
                "defaultConfiguration": {"level": "warning"},
                "help": {"text": "Document the endpoint in your OpenAPI specification or remove dead/unintended routes."}
            }
        ]

        results = []
        for ep in endpoints:
            if ep.get("is_bfla_candidate"):
                results.append({
                    "ruleId": "MAZAPI-SURFACE-001",
                    "message": {"text": f"Unprotected administrative endpoint: {ep.get('method')} {ep.get('path')}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": ep.get("file", "unknown")},
                            "region": {"startLine": ep.get("line", 1)}
                        }
                    }]
                })
            elif ep.get("is_bola_candidate") and not ep.get("has_auth"):
                results.append({
                    "ruleId": "MAZAPI-SURFACE-002",
                    "message": {"text": f"Candidate BOLA path with object parameter: {ep.get('method')} {ep.get('path')}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": ep.get("file", "unknown")},
                            "region": {"startLine": ep.get("line", 1)}
                        }
                    }]
                })

        for ep in (shadow_endpoints or []):
            results.append({
                "ruleId": "MAZAPI-SURFACE-003",
                "message": {"text": f"Shadow / Undocumented endpoint: {ep.get('method')} {ep.get('path')}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": ep.get("file", "unknown")},
                        "region": {"startLine": ep.get("line", 1)}
                    }
                }]
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "MazAPI App Surface",
                            "version": "2.0.0",
                            "informationUri": "https://github.com/apisec-inc/mcp-audit",
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        }
