"""Node.js & TypeScript Framework Static Route & Endpoint Parser.

Extracts endpoints, HTTP methods, path/query parameters, auth middleware, and security
risk indicators from Express, Fastify, NestJS, Koa, and Hono codebases.
"""
import re
from typing import Dict, List, Any


class NodeRouteParser:
    name = "Node.js / TypeScript (Express, NestJS, Fastify, Koa, Hono)"
    extensions = [".js", ".ts", ".mjs", ".cjs"]

    def __init__(self):
        # Express / Fastify / Koa / Hono methods: app.get('/users/:id', authMiddleware, handler)
        self.express_re = re.compile(
            r'(?:app|router|api|server|v1|route)\.(get|post|put|delete|patch|options|head|all)\s*\(\s*[\'"`]([^\'"`]+)[\'"`](.*?)(?=\);|\}\);|\n\s*(?:app|router|export))',
            re.DOTALL | re.IGNORECASE
        )
        # NestJS decorators: @Controller('users'), @Get(':id'), @Post(), @UseGuards(AuthGuard)
        self.nest_controller_re = re.compile(
            r'@Controller\s*\(\s*[\'"`]([^\'"`]*)[\'"`]\s*\)',
            re.IGNORECASE
        )
        self.nest_method_re = re.compile(
            r'@(?:(Get|Post|Put|Delete|Patch|Options|Head))\s*\(\s*[\'"`]?([^\'"`\)]*)[\'"`]?\s*\)',
            re.IGNORECASE
        )
        # Auth middleware patterns
        self.auth_middleware_re = re.compile(
            r'(?:auth|authenticate|verifyToken|jwt|passport|requireAuth|checkRole|guard|isAuthorized|isAdmin|session)',
            re.IGNORECASE
        )
        self.use_router_re = re.compile(
            r'(?:app|router)\.use\s*\(\s*[\'"`]([^\'"`]+)[\'"`]\s*,\s*([a-zA-Z0-9_]+)\s*\)',
            re.IGNORECASE
        )

    def parse_file(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        endpoints = []
        
        # 1. Discover router mount prefixes
        router_prefixes = {}
        for m in self.use_router_re.finditer(content):
            mount_path, router_var = m.group(1), m.group(2)
            router_prefixes[router_var] = mount_path

        # 2. Check for NestJS controller style
        controller_match = self.nest_controller_re.search(content)
        if controller_match:
            prefix = controller_match.group(1).strip("/")
            has_class_guard = bool(re.search(r'@UseGuards\s*\(', content))
            
            for m in self.nest_method_re.finditer(content):
                method = m.group(1).upper()
                sub_path = m.group(2).strip("/")
                full_path = "/" + "/".join(p for p in [prefix, sub_path] if p)
                
                # Check for method-level guard nearby
                start_pos = max(0, m.start() - 200)
                method_context = content[start_pos:m.end()]
                has_auth = has_class_guard or bool(re.search(r'@UseGuards\s*\(', method_context))
                
                is_bola = bool(re.search(r':(?:id|userId|accountId|orgId|key)|{[^}]+}', full_path, re.I))
                is_admin = bool(re.search(r'/(?:admin|manage|internal|debug|root)', full_path, re.I))
                
                line_no = content[:m.start()].count("\n") + 1
                endpoints.append({
                    "file": file_path,
                    "line": line_no,
                    "framework": "NestJS",
                    "method": method,
                    "path": full_path,
                    "handler": "method",
                    "parameters": self._extract_path_params(full_path),
                    "has_auth": has_auth,
                    "auth_type": "Guard/JWT/Passport" if has_auth else "None",
                    "is_bola_candidate": is_bola,
                    "is_bfla_candidate": is_admin and not has_auth,
                    "risk_level": "HIGH" if (is_admin and not has_auth) else ("MEDIUM" if is_bola and not has_auth else "LOW")
                })
            if endpoints:
                return endpoints

        # 3. Standard Express / Fastify / Koa / Hono routes
        for m in self.express_re.finditer(content):
            method = m.group(1).upper()
            raw_path = m.group(2)
            args_str = m.group(3) or ""
            
            line_no = content[:m.start()].count("\n") + 1
            has_auth = bool(self.auth_middleware_re.search(args_str))
            
            # Normalize path
            clean_path = "/" + raw_path.lstrip("/")
            is_bola = bool(re.search(r':[a-zA-Z0-9_]*(?:id|key|uuid|token|code)|{[^}]+}', clean_path, re.I))
            is_admin = bool(re.search(r'/(?:admin|manage|internal|private|system|debug)', clean_path, re.I))
            
            endpoints.append({
                "file": file_path,
                "line": line_no,
                "framework": "Express/Fastify/Koa",
                "method": method,
                "path": clean_path,
                "handler": "handler",
                "parameters": self._extract_path_params(clean_path),
                "has_auth": has_auth,
                "auth_type": "Middleware (JWT/Session)" if has_auth else "None",
                "is_bola_candidate": is_bola,
                "is_bfla_candidate": is_admin and not has_auth,
                "risk_level": "HIGH" if (is_admin and not has_auth) else ("MEDIUM" if is_bola and not has_auth else "LOW")
            })

        return endpoints

    def _extract_path_params(self, path: str) -> List[Dict[str, str]]:
        params = []
        for match in re.finditer(r':([a-zA-Z0-9_]+)|\{([a-zA-Z0-9_]+)\}', path):
            name = match.group(1) or match.group(2)
            params.append({"name": name, "type": "string", "in": "path"})
        return params
