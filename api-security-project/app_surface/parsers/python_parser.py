"""Python Web Framework Static Route & Endpoint Parser.

Extracts endpoints, HTTP methods, path/query parameters, auth decorators, and candidate
BOLA/BFLA security indicators from FastAPI, Starlette, Flask, and Django codebases.
"""
import ast
import os
import re
from typing import Dict, List, Any


class PythonRouteParser:
    name = "Python (FastAPI, Flask, Django, Starlette)"
    extensions = [".py"]

    def __init__(self):
        # Regex fallbacks and helpers
        self.fastapi_re = re.compile(
            r'@(?:app|router|api_router|api)\.(get|post|put|delete|patch|options|head)\s*\(\s*[\'"]([^\'"]+)[\'"]',
            re.IGNORECASE
        )
        self.flask_re = re.compile(
            r'@(?:app|bp|blueprint|api)\.route\s*\(\s*[\'"]([^\'"]+)[\'"](?:\s*,\s*methods\s*=\s*\[(.*?)\])?',
            re.IGNORECASE
        )
        self.django_path_re = re.compile(
            r'(?:path|re_path)\s*\(\s*[\'"]([^\'"]*)[\'"]\s*,\s*([^,\)]+)',
            re.IGNORECASE
        )
        self.drf_api_view_re = re.compile(
            r'@api_view\s*\(\s*\[(.*?)\]\s*\)',
            re.IGNORECASE
        )
        self.auth_decorator_re = re.compile(
            r'@(?:login_required|permission_required|jwt_required|auth_required|require_auth|roles_required|admin_required)',
            re.IGNORECASE
        )
        self.depends_auth_re = re.compile(
            r'Depends\s*\(\s*(?:get_current_user|auth|oauth2|jwt|security|get_admin_user|verify_token|require_)',
            re.IGNORECASE
        )

        # MQTT and CoAP IoT regexes for Python
        self.mqtt_sub_re = re.compile(
            r'(?:@mqtt\.subscribe|client\.subscribe|mqtt_client\.subscribe)\s*\(\s*[\'"]([^\'"]+)[\'"]',
            re.IGNORECASE
        )
        self.coap_res_re = re.compile(
            r'(?:root\.add_resource|site\.add_resource|CoapResource)\s*\(\s*\[?[\'"]([^\'"]+)[\'"]\]?',
            re.IGNORECASE
        )

    def parse_file(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        endpoints = []
        try:
            tree = ast.parse(content, filename=file_path)
            endpoints.extend(self._parse_ast(tree, file_path, content))
        except Exception:
            # Fall back to high-res regex scanning if AST fails
            endpoints.extend(self._parse_regex(file_path, content))

        # Scan for MQTT and CoAP IoT handlers in Python
        endpoints.extend(self._parse_iot(file_path, content))

        return endpoints

    def _parse_ast(self, tree: ast.AST, file_path: str, content: str) -> List[Dict[str, Any]]:
        endpoints = []
        lines = content.splitlines()

        # Prefix discovery from router definitions
        router_prefixes = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                # APIRouter(prefix="/api/v1") or Blueprint('users', __name__, url_prefix="/api/v1")
                if isinstance(node.value, ast.Call):
                    prefix = ""
                    for kw in node.value.keywords:
                        if kw.arg in ("prefix", "url_prefix") and isinstance(kw.value, ast.Constant):
                            prefix = kw.value.value
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            router_prefixes[target.id] = prefix

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = node.name
                line_no = node.lineno
                
                # Check decorators
                for decorator in node.decorator_list:
                    route_info = self._extract_route_from_decorator(decorator, router_prefixes)
                    if route_info:
                        for method, path in route_info:
                            # Analyze parameters
                            params = self._extract_function_params(node)
                            # Auth detection
                            has_auth = self._check_auth_guards(node, decorator, content, lines, line_no)
                            
                            # Check BOLA candidate (path contains object IDs)
                            is_bola_candidate = bool(re.search(r'\{[^\}]*(?:id|uuid|pk|key|code|slug)[^\}]*\}|<[^\>]*id[^\>]*>|:[a-zA-Z0-9_]*id', path, re.I))
                            is_admin = bool(re.search(r'/(?:admin|manage|internal|private|system|root|debug)', path, re.I))

                            endpoints.append({
                                "file": file_path,
                                "line": line_no,
                                "framework": "FastAPI/Flask/Starlette",
                                "method": method.upper(),
                                "path": path,
                                "handler": func_name,
                                "parameters": params,
                                "has_auth": has_auth,
                                "auth_type": "Bearer/OAuth2/Session" if has_auth else "None",
                                "is_bola_candidate": is_bola_candidate,
                                "is_bfla_candidate": is_admin and not has_auth,
                                "risk_level": "HIGH" if (is_admin and not has_auth) else ("MEDIUM" if is_bola_candidate and not has_auth else "LOW")
                            })

        # Django urlpatterns AST discovery
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "urlpatterns":
                        endpoints.extend(self._extract_django_urlpatterns(node.value, file_path, lines))

        return endpoints

    def _extract_route_from_decorator(self, decorator: ast.AST, prefixes: Dict[str, str]) -> List[tuple]:
        results = []
        if isinstance(decorator, ast.Call):
            func = decorator.func
            # FastAPI: @router.get("/users")
            if isinstance(func, ast.Attribute) and func.attr.lower() in ('get', 'post', 'put', 'delete', 'patch', 'options', 'head'):
                path = "/"
                if decorator.args and isinstance(decorator.args[0], ast.Constant):
                    path = str(decorator.args[0].value)
                elif decorator.keywords:
                    for kw in decorator.keywords:
                        if kw.arg == "path" and isinstance(kw.value, ast.Constant):
                            path = str(kw.value.value)
                
                router_name = func.value.id if isinstance(func.value, ast.Name) else ""
                prefix = prefixes.get(router_name, "")
                full_path = self._join_paths(prefix, path)
                results.append((func.attr.upper(), full_path))

            # Flask: @app.route("/users", methods=["GET", "POST"])
            elif isinstance(func, ast.Attribute) and func.attr.lower() == 'route':
                path = "/"
                methods = ["GET"]
                if decorator.args and isinstance(decorator.args[0], ast.Constant):
                    path = str(decorator.args[0].value)
                for kw in decorator.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        methods = [elt.value.upper() for elt in kw.value.elts if isinstance(elt, ast.Constant)]
                
                bp_name = func.value.id if isinstance(func.value, ast.Name) else ""
                prefix = prefixes.get(bp_name, "")
                full_path = self._join_paths(prefix, path)
                for m in methods:
                    results.append((m, full_path))
        return results

    def _extract_function_params(self, node: ast.FunctionDef) -> List[Dict[str, str]]:
        params = []
        for arg in node.args.args:
            name = arg.arg
            if name in ('self', 'cls', 'request', 'req'):
                continue
            param_type = "string"
            if arg.annotation:
                if isinstance(arg.annotation, ast.Name):
                    param_type = arg.annotation.id
                elif isinstance(arg.annotation, ast.Constant):
                    param_type = str(arg.annotation.value)
            params.append({"name": name, "type": param_type, "in": "path" if "id" in name.lower() else "query"})
        return params

    def _check_auth_guards(self, func_node: ast.AST, current_dec: ast.AST, content: str, lines: List[str], line_no: int) -> bool:
        # Check other decorators on the function
        if hasattr(func_node, 'decorator_list'):
            for dec in func_node.decorator_list:
                dec_str = ast.unparse(dec) if hasattr(ast, 'unparse') else ""
                if self.auth_decorator_re.search(dec_str):
                    return True
        # Check function arguments for Depends(get_current_user)
        func_str = ast.unparse(func_node) if hasattr(ast, 'unparse') else ""
        if self.depends_auth_re.search(func_str):
            return True
        return False

    def _extract_django_urlpatterns(self, node: ast.AST, file_path: str, lines: List[str]) -> List[Dict[str, Any]]:
        endpoints = []
        if isinstance(node, (ast.List, ast.Tuple)):
            for elt in node.elts:
                if isinstance(elt, ast.Call):
                    func_name = elt.func.id if isinstance(elt.func, ast.Name) else ""
                    if func_name in ("path", "re_path") and elt.args:
                        path_str = elt.args[0].value if isinstance(elt.args[0], ast.Constant) else ""
                        handler = elt.args[1].id if len(elt.args) > 1 and isinstance(elt.args[1], ast.Name) else "view"
                        clean_path = "/" + path_str.lstrip("/")
                        is_admin = bool(re.search(r'/(?:admin|manage|internal|private)', clean_path, re.I))
                        endpoints.append({
                            "file": file_path,
                            "line": elt.lineno if hasattr(elt, 'lineno') else 1,
                            "framework": "Django",
                            "method": "ANY",
                            "path": clean_path,
                            "handler": handler,
                            "parameters": [],
                            "has_auth": False,
                            "auth_type": "Session/None",
                            "is_bola_candidate": bool(re.search(r'<[^\>]*id[^\>]*>', clean_path, re.I)),
                            "is_bfla_candidate": is_admin,
                            "risk_level": "HIGH" if is_admin else "LOW"
                        })
        return endpoints

    def _parse_regex(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        endpoints = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            m = self.fastapi_re.search(line)
            if m:
                method, path = m.group(1).upper(), m.group(2)
                endpoints.append({
                    "file": file_path,
                    "line": line_no,
                    "framework": "FastAPI",
                    "method": method,
                    "path": path,
                    "handler": "handler",
                    "parameters": [],
                    "has_auth": bool(self.depends_auth_re.search(line)),
                    "auth_type": "Bearer/OAuth2" if self.depends_auth_re.search(line) else "None",
                    "is_bola_candidate": "{" in path,
                    "is_bfla_candidate": "/admin" in path.lower(),
                    "risk_level": "MEDIUM" if "{" in path else "LOW"
                })
        return endpoints

    def _join_paths(self, prefix: str, path: str) -> str:
        prefix = (prefix or "").strip()
        path = (path or "").strip()
        if not prefix:
            return path if path.startswith("/") else "/" + path
        if not path or path == "/":
            return prefix if prefix.startswith("/") else "/" + prefix
        return "/" + prefix.strip("/") + "/" + path.strip("/")

    def _parse_iot(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        endpoints = []
        lines = content.splitlines()

        for m in self.mqtt_sub_re.finditer(content):
            topic = m.group(1)
            line_no = content[:m.start()].count("\n") + 1
            has_auth = bool(re.search(r'(?:tls|ssl|auth|cert|jwt)', content[max(0, m.start()-150):min(len(content), m.end()+150)], re.I))
            endpoints.append({
                "file": file_path,
                "line": line_no,
                "framework": "FastAPI/Paho MQTT",
                "method": "SUBSCRIBE",
                "path": topic,
                "handler": "on_message",
                "parameters": [],
                "has_auth": has_auth,
                "auth_type": "MQTT ACL/TLS" if has_auth else "None",
                "is_bola_candidate": "+" in topic or "#" in topic,
                "is_bfla_candidate": not has_auth,
                "risk_level": "HIGH" if ("#" in topic or not has_auth) else "LOW",
                "protocol": "MQTT"
            })

        for m in self.coap_res_re.finditer(content):
            path = "/" + m.group(1).lstrip("/")
            line_no = content[:m.start()].count("\n") + 1
            has_auth = bool(re.search(r'(?:dtls|psk|auth)', content[max(0, m.start()-150):min(len(content), m.end()+150)], re.I))
            endpoints.append({
                "file": file_path,
                "line": line_no,
                "framework": "aiocoap / CoAP",
                "method": "GET",
                "path": path,
                "handler": "render",
                "parameters": [],
                "has_auth": has_auth,
                "auth_type": "DTLS/PSK" if has_auth else "None",
                "is_bola_candidate": False,
                "is_bfla_candidate": not has_auth,
                "risk_level": "MEDIUM" if not has_auth else "LOW",
                "protocol": "CoAP"
            })

        return endpoints

