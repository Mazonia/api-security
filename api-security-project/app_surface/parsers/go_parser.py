"""Go Web Framework Static Route & Endpoint Parser (Gin, Echo, Chi, Fiber, net/http).

Extracts REST routes, HTTP methods, path parameters (:id, {id}), group prefixes,
auth middleware, and BOLA/BFLA security risk indicators from Go source code.
"""
import re
from typing import Dict, List, Any


class GoRouteParser:
    name = "Go (Gin, Echo, Chi, Fiber, net/http)"
    extensions = [".go"]

    def __init__(self):
        self.route_re = re.compile(
            r'(?:[a-zA-Z0-9_]+)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|Handle|HandleFunc)\s*\(\s*[\'"]([^\'"]+)[\'"](.*?)(?=\)\s*\n|\);)',
            re.DOTALL | re.IGNORECASE
        )
        self.group_re = re.compile(
            r'([a-zA-Z0-9_]+)\s*:?=\s*(?:[a-zA-Z0-9_]+)\.(?:Group|Route|Party)\s*\(\s*[\'"]([^\'"]+)[\'"]',
            re.IGNORECASE
        )
        self.auth_middleware_re = re.compile(
            r'(?:Auth|JWT|Token|Session|Require|Admin|Permission|Bearer|OAuth)',
            re.IGNORECASE
        )

    def parse_file(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        endpoints = []

        # 1. Discover router groups
        groups = {}
        for m in self.group_re.finditer(content):
            var_name, prefix = m.group(1), m.group(2)
            groups[var_name] = prefix.strip("/")

        # 2. Extract routes
        for m in self.route_re.finditer(content):
            method_token = m.group(1).upper()
            raw_path = m.group(2)
            args = m.group(3) or ""
            line_no = content[:m.start()].count("\n") + 1

            if method_token in ("HANDLE", "HANDLEFUNC"):
                method = "ANY"
            else:
                method = method_token

            # Prefix checking
            router_caller = content[max(0, m.start()-30):m.start()].strip()
            matched_var = re.search(r'([a-zA-Z0-9_]+)\s*$', router_caller)
            prefix = ""
            if matched_var and matched_var.group(1) in groups:
                prefix = groups[matched_var.group(1)]

            full_path = self._join_paths(prefix, raw_path)
            has_auth = bool(self.auth_middleware_re.search(args))
            is_bola = bool(re.search(r':(?:id|userId|accountId|uuid|key)|{[^}]+}', full_path, re.I))
            is_admin = bool(re.search(r'/(?:admin|manage|internal|private|system)', full_path, re.I))

            endpoints.append({
                "file": file_path,
                "line": line_no,
                "framework": "Go (Gin/Echo/Chi/net/http)",
                "method": method,
                "path": full_path,
                "handler": "handler",
                "parameters": self._extract_path_params(full_path),
                "has_auth": has_auth,
                "auth_type": "Middleware (JWT/Token)" if has_auth else "None",
                "is_bola_candidate": is_bola,
                "is_bfla_candidate": is_admin and not has_auth,
                "risk_level": "HIGH" if (is_admin and not has_auth) else ("MEDIUM" if is_bola and not has_auth else "LOW")
            })

        return endpoints

    def _join_paths(self, prefix: str, path: str) -> str:
        prefix = (prefix or "").strip().strip("/")
        path = (path or "").strip().strip("/")
        if not prefix and not path:
            return "/"
        if not prefix:
            return "/" + path
        if not path:
            return "/" + prefix
        return "/" + prefix + "/" + path

    def _extract_path_params(self, path: str) -> List[Dict[str, str]]:
        params = []
        for match in re.finditer(r':([a-zA-Z0-9_]+)|\{([a-zA-Z0-9_]+)\}', path):
            name = match.group(1) or match.group(2)
            params.append({"name": name, "type": "string", "in": "path"})
        return params
