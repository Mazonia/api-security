"""OpenAPI 3.0 Specification Generator from Discovered Code Surface.

Converts statically mapped endpoints and route parameters into a standards-compliant
OpenAPI 3.0 YAML or JSON specification with security schemes, parameter schemas, and tags.
"""
import json
import re
from typing import Dict, List, Any
import yaml


class OpenAPIGenerator:
    def __init__(self, title: str = "Discovered Application API Surface", version: str = "1.0.0", host_url: str = ""):
        self.title = title
        self.version = version
        self.host_url = host_url

    def generate_spec(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Convert a list of discovered endpoints to an OpenAPI 3.0 dict."""
        spec = {
            "openapi": "3.0.3",
            "info": {
                "title": self.title,
                "version": self.version,
                "description": "Automatically mapped API surface extracted from application source code at PR time by MazAPI App Surface."
            },
            "servers": [{"url": self.host_url or "http://localhost:8000"}],
            "paths": {},
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    },
                    "apiKeyAuth": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key"
                    }
                }
            }
        }

        for ep in endpoints:
            path = ep.get("path", "/")
            method = ep.get("method", "GET").lower()
            framework = ep.get("framework", "Generic")
            has_auth = ep.get("has_auth", False)
            params = ep.get("parameters", [])

            # Normalize path template to {param}
            normalized_path = re.sub(r':([a-zA-Z0-9_]+)', r'{\1}', path)

            if normalized_path not in spec["paths"]:
                spec["paths"][normalized_path] = {}

            # Generate tag from root path segment
            segments = [s for s in normalized_path.split("/") if s and not s.startswith("{")]
            tag = segments[0].capitalize() if segments else "Root"

            operation_id = f"{method}_{normalized_path.strip('/').replace('/', '_').replace('{', '').replace('}', '')}" or f"{method}_root"

            parameters_spec = []
            # Extract path parameters
            for path_var in re.findall(r'\{([a-zA-Z0-9_]+)\}', normalized_path):
                parameters_spec.append({
                    "name": path_var,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "integer" if "id" in path_var.lower() else "string"},
                    "description": f"Target {path_var}"
                })

            for p in params:
                if p.get("in") == "query" and p.get("name") not in [x["name"] for x in parameters_spec]:
                    parameters_spec.append({
                        "name": p.get("name"),
                        "in": "query",
                        "required": False,
                        "schema": {"type": p.get("type", "string")},
                        "description": f"Query parameter {p.get('name')}"
                    })

            op_spec: Dict[str, Any] = {
                "tags": [tag],
                "summary": f"{method.upper()} {normalized_path}",
                "description": f"Extracted from `{ep.get('file', 'code')}:{ep.get('line', 1)}` ({framework})",
                "operationId": operation_id,
                "parameters": parameters_spec,
                "responses": {
                    "200": {
                        "description": "Successful response",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "status": {"type": "string", "example": "success"},
                                        "data": {"type": "object"}
                                    }
                                }
                            }
                        }
                    },
                    "400": {"description": "Bad request / Validation error"},
                    "401": {"description": "Unauthorized access"},
                    "403": {"description": "Forbidden resource"},
                    "404": {"description": "Resource not found"}
                }
            }

            if has_auth:
                op_spec["security"] = [{"bearerAuth": []}]

            # Request Body for mutating verbs
            if method in ("post", "put", "patch"):
                op_spec["requestBody"] = {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "description": "Request payload"
                            }
                        }
                    }
                }

            if method == "any":
                for m in ["get", "post", "put", "delete"]:
                    spec["paths"][normalized_path][m] = dict(op_spec, summary=f"{m.upper()} {normalized_path}")
            else:
                spec["paths"][normalized_path][method] = op_spec

        return spec

    def to_yaml(self, endpoints: List[Dict[str, Any]]) -> str:
        spec = self.generate_spec(endpoints)
        return yaml.dump(spec, sort_keys=False)

    def to_json(self, endpoints: List[Dict[str, Any]], indent: int = 2) -> str:
        spec = self.generate_spec(endpoints)
        return json.dumps(spec, indent=indent)
