"""PHP Framework Static Route & Endpoint Parser (Laravel & Symfony).

Extracts routes, HTTP methods, route parameters ({id}), auth middleware (sanctum, jwt, auth),
and BOLA/BFLA security risk indicators from PHP web application source code.
"""
import re
from typing import Dict, List, Any


class PhpRouteParser:
    name = "PHP (Laravel & Symfony)"
    extensions = [".php"]

    def __init__(self):
        # Laravel: Route::get('/users/{id}', [UserController::class, 'show'])->middleware('auth:sanctum');
        self.laravel_route_re = re.compile(
            r'Route::(get|post|put|delete|patch|options|any|apiResource|resource)\s*\(\s*[\'"]([^\'"]+)[\'"](.*?)(?=\);|\n\s*(?:Route::|return|\$))',
            re.DOTALL | re.IGNORECASE
        )
        # Symfony attributes: #[Route('/api/users/{id}', name: 'user_show', methods: ['GET', 'POST'])]
        self.symfony_attr_re = re.compile(
            r'#\[Route\s*\(\s*[\'"]([^\'"]+)[\'"](?:\s*,\s*methods\s*:\s*\[(.*?)\])?',
            re.IGNORECASE
        )
        self.auth_middleware_re = re.compile(
            r'middleware\s*\(\s*\[?[\'"]?(?:auth|sanctum|jwt|passport|verified|can:|admin)',
            re.IGNORECASE
        )

    def parse_file(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        endpoints = []

        # 1. Laravel Routes
        for m in self.laravel_route_re.finditer(content):
            method_type = m.group(1).lower()
            raw_path = m.group(2)
            chained_calls = m.group(3) or ""
            line_no = content[:m.start()].count("\n") + 1

            has_auth = bool(self.auth_middleware_re.search(chained_calls))
            clean_path = "/" + raw_path.lstrip("/")

            if method_type == "apiresource":
                # Generates CRUD endpoints
                methods = [("GET", clean_path), ("POST", clean_path), ("GET", f"{clean_path}/{{id}}"), ("PUT", f"{clean_path}/{{id}}"), ("DELETE", f"{clean_path}/{{id}}")]
            elif method_type == "resource":
                methods = [("GET", clean_path), ("POST", clean_path), ("GET", f"{clean_path}/{{id}}"), ("PUT", f"{clean_path}/{{id}}"), ("DELETE", f"{clean_path}/{{id}}")]
            elif method_type == "any":
                methods = [("ANY", clean_path)]
            else:
                methods = [(method_type.upper(), clean_path)]

            for method, p in methods:
                is_bola = bool(re.search(r'\{[^\}]*(?:id|userId|uuid|key|code)[^\}]*\}', p, re.I))
                is_admin = bool(re.search(r'/(?:admin|manage|internal|system)', p, re.I))

                endpoints.append({
                    "file": file_path,
                    "line": line_no,
                    "framework": "Laravel",
                    "method": method,
                    "path": p,
                    "handler": "controller",
                    "parameters": self._extract_path_params(p),
                    "has_auth": has_auth,
                    "auth_type": "Laravel Middleware (Sanctum/Auth)" if has_auth else "None",
                    "is_bola_candidate": is_bola,
                    "is_bfla_candidate": is_admin and not has_auth,
                    "risk_level": "HIGH" if (is_admin and not has_auth) else ("MEDIUM" if is_bola and not has_auth else "LOW")
                })

        # 2. Symfony Attributes
        for m in self.symfony_attr_re.finditer(content):
            raw_path = m.group(1)
            raw_methods = m.group(2) or "'GET'"
            methods = [meth.strip().strip("'\"").upper() for meth in raw_methods.split(",") if meth.strip()]
            clean_path = "/" + raw_path.lstrip("/")
            line_no = content[:m.start()].count("\n") + 1

            has_auth = bool(re.search(r'#\[IsGranted|#\[Security', content[max(0, m.start()-150):m.end()+150]))
            is_bola = bool(re.search(r'\{[^\}]*(?:id|userId|uuid|key|code)[^\}]*\}', clean_path, re.I))
            is_admin = bool(re.search(r'/(?:admin|manage|internal|system)', clean_path, re.I))

            for method in methods:
                endpoints.append({
                    "file": file_path,
                    "line": line_no,
                    "framework": "Symfony",
                    "method": method,
                    "path": clean_path,
                    "handler": "action",
                    "parameters": self._extract_path_params(clean_path),
                    "has_auth": has_auth,
                    "auth_type": "Symfony Security (#[IsGranted])" if has_auth else "None",
                    "is_bola_candidate": is_bola,
                    "is_bfla_candidate": is_admin and not has_auth,
                    "risk_level": "HIGH" if (is_admin and not has_auth) else ("MEDIUM" if is_bola and not has_auth else "LOW")
                })

        return endpoints

    def _extract_path_params(self, path: str) -> List[Dict[str, str]]:
        params = []
        for match in re.finditer(r'\{([a-zA-Z0-9_]+)\}', path):
            params.append({"name": match.group(1), "type": "string", "in": "path"})
        return params
