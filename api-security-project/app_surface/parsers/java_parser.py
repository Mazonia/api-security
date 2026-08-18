"""Java & Kotlin Enterprise Route & Endpoint Parser (Spring Boot, Micronaut, Quarkus).

Extracts REST endpoints, HTTP methods, path variables, authorization annotations
(@PreAuthorize, @Secured, @RolesAllowed), and BOLA/BFLA security risk indicators.
"""
import re
from typing import Dict, List, Any


class JavaRouteParser:
    name = "Java / Kotlin (Spring Boot, Micronaut, Quarkus)"
    extensions = [".java", ".kt"]

    def __init__(self):
        self.class_mapping_re = re.compile(
            r'@RequestMapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?[\'"]([^\'"]+)[\'"]',
            re.IGNORECASE
        )
        self.method_mapping_re = re.compile(
            r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(\s*(?:value\s*=\s*|path\s*=\s*)?[\'"]?([^\'"]*?)[\'"]?\s*(?:,\s*method\s*=\s*RequestMethod\.([A-Z]+))?\s*\))?',
            re.IGNORECASE
        )
        self.security_re = re.compile(
            r'@(?:PreAuthorize|Secured|RolesAllowed|Authenticated)',
            re.IGNORECASE
        )
        self.micronaut_controller_re = re.compile(
            r'@Controller\s*\(\s*[\'"]?([^\'"]*?)[\'"]?\s*\)',
            re.IGNORECASE
        )
        self.micronaut_method_re = re.compile(
            r'@(Get|Post|Put|Delete|Patch|Head|Options)\s*(?:\(\s*[\'"]?([^\'"]*?)[\'"]?\s*\))?',
            re.IGNORECASE
        )

    def parse_file(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        endpoints = []
        
        # 1. Base class path prefix
        class_prefix = ""
        class_end_pos = 0
        cm = self.class_mapping_re.search(content)
        if cm:
            class_prefix = cm.group(1).strip("/")
            class_end_pos = cm.end()
        else:
            mc = self.micronaut_controller_re.search(content)
            if mc:
                class_prefix = mc.group(1).strip("/")
                class_end_pos = mc.end()

        has_class_security = bool(self.security_re.search(content[:cm.start() if cm else 200]))

        # 2. Method mappings (Spring)
        for m in self.method_mapping_re.finditer(content[class_end_pos:]):
            annotation = m.group(1)
            raw_subpath = m.group(2) or ""
            method_override = m.group(3)

            if annotation.lower() == "getmapping":
                method = "GET"
            elif annotation.lower() == "postmapping":
                method = "POST"
            elif annotation.lower() == "putmapping":
                method = "PUT"
            elif annotation.lower() == "deletemapping":
                method = "DELETE"
            elif annotation.lower() == "patchmapping":
                method = "PATCH"
            else:
                method = method_override if method_override else "ANY"

            full_path = self._join_paths(class_prefix, raw_subpath)
            line_no = content[:m.start()].count("\n") + 1

            # Check method-level security
            window_start = max(0, m.start() - 250)
            window_end = min(len(content), m.end() + 200)
            method_context = content[window_start:window_end]
            has_auth = has_class_security or bool(self.security_re.search(method_context))

            is_bola = bool(re.search(r'\{[^\}]*(?:id|userId|uuid|key|code)[^\}]*\}', full_path, re.I))
            is_admin = bool(re.search(r'/(?:admin|manage|internal|actuator|system|root)', full_path, re.I))

            endpoints.append({
                "file": file_path,
                "line": line_no,
                "framework": "Spring Boot",
                "method": method,
                "path": full_path,
                "handler": "method",
                "parameters": self._extract_path_params(full_path),
                "has_auth": has_auth,
                "auth_type": "Spring Security (@PreAuthorize/@Secured)" if has_auth else "None",
                "is_bola_candidate": is_bola,
                "is_bfla_candidate": is_admin and not has_auth,
                "risk_level": "HIGH" if (is_admin and not has_auth) else ("MEDIUM" if is_bola and not has_auth else "LOW")
            })

        # 3. Micronaut / Quarkus if no Spring found
        if not endpoints:
            for m in self.micronaut_method_re.finditer(content):
                method = m.group(1).upper()
                raw_subpath = m.group(2) or ""
                full_path = self._join_paths(class_prefix, raw_subpath)
                line_no = content[:m.start()].count("\n") + 1

                is_bola = bool(re.search(r'\{[^\}]*(?:id|userId|uuid|key|code)[^\}]*\}', full_path, re.I))
                is_admin = bool(re.search(r'/(?:admin|manage|internal|system)', full_path, re.I))

                endpoints.append({
                    "file": file_path,
                    "line": line_no,
                    "framework": "Micronaut/Quarkus",
                    "method": method,
                    "path": full_path,
                    "handler": "method",
                    "parameters": self._extract_path_params(full_path),
                    "has_auth": has_class_security,
                    "auth_type": "Security Annotation" if has_class_security else "None",
                    "is_bola_candidate": is_bola,
                    "is_bfla_candidate": is_admin and not has_class_security,
                    "risk_level": "HIGH" if (is_admin and not has_class_security) else ("MEDIUM" if is_bola and not has_class_security else "LOW")
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
