"""App Surface Diff Engine & Shadow API Detector.

Tracks API baseline state across PRs and discovers shadow/undocumented endpoints
by diffing extracted routes against existing OpenAPI / Swagger specifications.
"""
import json
import os
import re
from typing import Dict, List, Any, Optional
import yaml


class DiffEngine:
    def __init__(self, baseline_path: Optional[str] = None):
        self.baseline_path = baseline_path

    def load_baseline(self, path: Optional[str] = None) -> List[Dict[str, Any]]:
        target_path = path or self.baseline_path
        if not target_path or not os.path.exists(target_path):
            return []
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                if target_path.endswith((".yaml", ".yml")):
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
                if isinstance(data, dict) and "endpoints" in data:
                    return data["endpoints"]
                elif isinstance(data, list):
                    return data
        except Exception:
            pass
        return []

    def save_baseline(self, endpoints: List[Dict[str, Any]], target_path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
        payload = {
            "version": "1.0.0",
            "total_endpoints": len(endpoints),
            "endpoints": endpoints
        }
        with open(target_path, "w", encoding="utf-8") as f:
            if target_path.endswith((".yaml", ".yml")):
                yaml.dump(payload, f, sort_keys=False)
            else:
                json.dump(payload, f, indent=2)

    def compute_diff(self, current: List[Dict[str, Any]], baseline: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compute added, removed, and modified endpoints between baseline and current state."""
        base_map = {f"{ep.get('method')}:{ep.get('path')}": ep for ep in baseline}
        curr_map = {f"{ep.get('method')}:{ep.get('path')}": ep for ep in current}

        added = []
        removed = []
        modified = []
        unchanged = []

        for key, ep in curr_map.items():
            if key not in base_map:
                added.append(ep)
            else:
                base_ep = base_map[key]
                # Check changes in auth or risk
                if base_ep.get("has_auth") != ep.get("has_auth") or base_ep.get("risk_level") != ep.get("risk_level"):
                    modified.append({
                        "endpoint": ep,
                        "old_auth": base_ep.get("has_auth"),
                        "new_auth": ep.get("has_auth"),
                        "old_risk": base_ep.get("risk_level"),
                        "new_risk": ep.get("risk_level")
                    })
                else:
                    unchanged.append(ep)

        for key, ep in base_map.items():
            if key not in curr_map:
                removed.append(ep)

        return {
            "total_current": len(current),
            "total_baseline": len(baseline),
            "added_count": len(added),
            "removed_count": len(removed),
            "modified_count": len(modified),
            "unchanged_count": len(unchanged),
            "added": added,
            "removed": removed,
            "modified": modified
        }

    def find_shadow_apis(self, current_endpoints: List[Dict[str, Any]], repo_root: str) -> List[Dict[str, Any]]:
        """Identify undocumented/shadow endpoints in code that are missing from OpenAPI/Swagger docs."""
        doc_routes = set()
        
        # Search for swagger/openapi specs in repo
        for root, _, files in os.walk(repo_root):
            for file in files:
                if file.lower() in ("openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml", "swagger.yml"):
                    spec_file = os.path.join(root, file)
                    try:
                        with open(spec_file, "r", encoding="utf-8") as f:
                            if file.endswith((".yaml", ".yml")):
                                spec = yaml.safe_load(f)
                            else:
                                spec = json.load(f)
                            paths = spec.get("paths", {})
                            for p, methods in paths.items():
                                norm_p = re.sub(r'\{[^\}]+\}', '{param}', p.rstrip("/"))
                                for m in methods.keys():
                                    if m.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                                        doc_routes.add(f"{m.upper()}:{norm_p}")
                    except Exception:
                        pass

        if not doc_routes:
            return []

        shadow = []
        for ep in current_endpoints:
            norm_path = re.sub(r':([a-zA-Z0-9_]+)|\{([a-zA-Z0-9_]+)\}', '{param}', ep.get("path", "").rstrip("/"))
            key = f"{ep.get('method')}:{norm_path}"
            if key not in doc_routes and f"ANY:{norm_path}" not in doc_routes:
                shadow.append(dict(ep, shadow_reason="Missing from OpenAPI/Swagger documentation in repository"))

        return shadow
