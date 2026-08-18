"""C# & ASP.NET Core Static Route & Endpoint Parser.

Extracts endpoints from ASP.NET Core MVC Controllers, Web API controllers, and .NET Minimal APIs
with authorization attributes ([Authorize], .RequireAuthorization()) and BOLA/BFLA security indicators.
"""
import re
from typing import Dict, List, Any


class DotnetRouteParser:
    name = ".NET (ASP.NET Core Controllers & Minimal APIs)"
    extensions = [".cs"]

    def __init__(self):
        self.class_route_re = re.compile(
            r'\[Route\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)\]',
            re.IGNORECASE
        )
        self.http_attr_re = re.compile(
            r'\[Http(Get|Post|Put|Delete|Patch|Head|Options)\s*(?:\(\s*[\'"]?([^\'"]*?)[\'"]?\s*\))?\]',
            re.IGNORECASE
        )
        self.minimal_api_re = re.compile(
            r'(?:app|group|endpoints)\.Map(Get|Post|Put|Delete|Patch)\s*\(\s*[\'"]([^\'"]+)[\'"](.*?)(?=\);|\n\s*(?:app|group|endpoints|var|builder))',
            re.DOTALL | re.IGNORECASE
        )
        self.map_group_re = re.compile(
            r'(?:app|group)\.MapGroup\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
            re.IGNORECASE
        )
        self.authorize_attr_re = re.compile(
            r'\[Authorize(?:\([^\)]*\))?\]',
            re.IGNORECASE
        )
        self.require_auth_re = re.compile(
            r'\.RequireAuthorization\s*\(',
            re.IGNORECASE
        )

    def parse_file(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        endpoints = []

        # 1. Check controller-based routes
        class_route = ""
        cr = self.class_route_re.search(content)
        if cr:
            class_route = cr.group(1).replace("[controller]", "controller").strip("/")

        has_controller_auth = bool(self.authorize_attr_re.search(content[:cr.start() if cr else 300]))

        for m in self.http_attr_re.finditer(content):
            verb = m.group(1).upper()
            sub_path = (m.group(2) or "").strip("/")
            
            full_path = self._join_paths(class_route, sub_path)
            line_no = content[:m.start()].count("\n") + 1

            # Check method-level auth
            window_start = max(0, m.start() - 250)
            window_end = min(len(content), m.end() + 200)
            context = content[window_start:window_end]
            has_auth = (has_controller_auth or bool(self.authorize_attr_re.search(context))) and not bool(re.search(r'\[AllowAnonymous\]', context))

            is_bola = bool(re.search(r'\{[^\}]*(?:id|userId|uuid|key|code)[^\}]*\}', full_path, re.I))
            is_admin = bool(re.search(r'/(?:admin|manage|internal|actuator|system)', full_path, re.I))

            endpoints.append({
                "file": file_path,
                "line": line_no,
                "framework": "ASP.NET Core Controller",
                "method": verb,
                "path": full_path,
                "handler": "action",
                "parameters": self._extract_path_params(full_path),
                "has_auth": has_auth,
                "auth_type": "ASP.NET Core [Authorize]" if has_auth else "None",
                "is_bola_candidate": is_bola,
                "is_bfla_candidate": is_admin and not has_auth,
                "risk_level": "HIGH" if (is_admin and not has_auth) else ("MEDIUM" if is_bola and not has_auth else "LOW")
            })

        # 2. Minimal APIs
        for m in self.minimal_api_re.finditer(content):
            verb = m.group(1).upper()
            path = "/" + m.group(2).lstrip("/")
            body = m.group(3) or ""
            line_no = content[:m.start()].count("\n") + 1

            has_auth = bool(self.require_auth_re.search(body))
            is_bola = bool(re.search(r'\{[^\}]*(?:id|userId|uuid|key|code)[^\}]*\}', path, re.I))
            is_admin = bool(re.search(r'/(?:admin|manage|internal|system)', path, re.I))

            endpoints.append({
                "file": file_path,
                "line": line_no,
                "framework": "ASP.NET Core Minimal API",
                "method": verb,
                "path": path,
                "handler": "lambda",
                "parameters": self._extract_path_params(path),
                "has_auth": has_auth,
                "auth_type": ".RequireAuthorization()" if has_auth else "None",
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
        for match in re.finditer(r'\{([a-zA-Z0-9_]+)\}', path):
            params.append({"name": match.group(1), "type": "string", "in": "path"})
        return params
