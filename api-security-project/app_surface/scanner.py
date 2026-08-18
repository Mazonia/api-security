"""App Surface Core Scanner.

Discovers and maps application API endpoints, routes, parameters, auth decorators, and security
risk indicators directly from source code at PR time across Python, Node.js, Java, .NET, Go, and PHP.
"""
import os
import sys
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .parsers import ALL_PARSERS
from .openapi_generator import OpenAPIGenerator
from .diff_engine import DiffEngine
from .sarif_exporter import AppSurfaceSarifExporter

console = Console()

IGNORE_DIRS = {
    "node_modules", ".git", ".github", ".venv", "venv", "env", "__pycache__",
    ".pytest_cache", "dist", "build", "target", "bin", "obj", "vendor", ".idea", ".vscode"
}


class AppSurfaceScanner:
    def __init__(self, target_dir: str = "."):
        self.target_dir = os.path.abspath(target_dir)
        self.parsers = ALL_PARSERS
        self.openapi_gen = OpenAPIGenerator()
        self.diff_engine = DiffEngine()
        self.sarif_exporter = AppSurfaceSarifExporter()

    def scan(self, baseline_path: Optional[str] = None) -> Dict[str, Any]:
        """Scan directory and return complete discovered API surface."""
        endpoints = []
        scanned_files = 0

        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                applicable_parsers = [p for p in self.parsers if ext in p.extensions]
                if not applicable_parsers:
                    continue

                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, self.target_dir)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    scanned_files += 1
                    for parser in applicable_parsers:
                        parsed_eps = parser.parse_file(rel_path, content)
                        endpoints.extend(parsed_eps)
                except Exception as e:
                    pass

        # Deduplicate endpoints by method + path + file
        unique_endpoints = []
        seen = set()
        for ep in endpoints:
            key = f"{ep.get('method')}:{ep.get('path')}:{ep.get('file')}"
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(ep)

        # Shadow API detection
        shadow_apis = self.diff_engine.find_shadow_apis(unique_endpoints, self.target_dir)

        # Baseline diffing if requested
        diff_results = None
        if baseline_path:
            baseline_eps = self.diff_engine.load_baseline(baseline_path)
            diff_results = self.diff_engine.compute_diff(unique_endpoints, baseline_eps)

        # Risk metrics
        bfla_count = sum(1 for ep in unique_endpoints if ep.get("is_bfla_candidate"))
        bola_count = sum(1 for ep in unique_endpoints if ep.get("is_bola_candidate"))
        unauth_count = sum(1 for ep in unique_endpoints if not ep.get("has_auth"))
        high_risk_count = sum(1 for ep in unique_endpoints if ep.get("risk_level") == "HIGH")

        score = max(0, 100 - (high_risk_count * 15 + bfla_count * 10 + len(shadow_apis) * 5))

        return {
            "target_dir": self.target_dir,
            "scanned_files": scanned_files,
            "total_endpoints": len(unique_endpoints),
            "score": score,
            "high_risk_count": high_risk_count,
            "bfla_candidates": bfla_count,
            "bola_candidates": bola_count,
            "unauthenticated_count": unauth_count,
            "shadow_apis_count": len(shadow_apis),
            "endpoints": unique_endpoints,
            "shadow_apis": shadow_apis,
            "diff": diff_results
        }

    def print_report(self, results: Dict[str, Any], show_governance: bool = True) -> None:
        """Render a rich visual scorecard and endpoint inventory table."""
        score = results.get("score", 100)
        grade = "A" if score >= 90 else ("B" if score >= 80 else ("C" if score >= 70 else ("D" if score >= 60 else "F")))
        grade_color = "green" if grade in ("A", "B") else ("yellow" if grade == "C" else "red")

        summary_text = (
            f"[bold {grade_color}]App Surface Scorecard: Grade {grade} ({score}/100)[/]\n"
            f"Mapped [cyan]{results['total_endpoints']}[/] endpoints across [cyan]{results['scanned_files']}[/] source files\n"
            f"Findings: [red]{results['high_risk_count']} High Risk[/] | "
            f"[yellow]{results['bfla_candidates']} BFLA/Admin Risks[/] | "
            f"[magenta]{results['bola_candidates']} BOLA Candidates[/] | "
            f"[orange3]{results['shadow_apis_count']} Shadow/Undocumented APIs[/]"
        )
        console.print(Panel(summary_text, title="[bold]MazAPI App Surface ? Code API Map[/]", border_style=grade_color))

        table = Table(title="Discovered Application Endpoints", show_header=True, header_style="bold blue")
        table.add_column("Method", style="bold", width=8)
        table.add_column("Path", style="cyan", width=35)
        table.add_column("Framework", style="dim", width=18)
        table.add_column("Auth", width=14)
        table.add_column("Risk Flag", style="bold", width=22)
        table.add_column("Source", style="dim", width=25)

        for ep in results.get("endpoints", [])[:30]:
            method = ep.get("method", "GET")
            m_color = "green" if method == "GET" else ("yellow" if method == "POST" else ("blue" if method == "PUT" else "red"))
            
            risk_label = "[green]LOW[/]"
            if ep.get("is_bfla_candidate"):
                risk_label = "[red]? BFLA (Admin unauth)[/]"
            elif ep.get("is_bola_candidate"):
                risk_label = "[yellow]? BOLA candidate[/]"

            auth_str = "[green]? Auth[/]" if ep.get("has_auth") else "[red]? Public[/]"
            src_str = f"{os.path.basename(ep.get('file', ''))}:{ep.get('line', 1)}"

            table.add_row(f"[{m_color}]{method}[/]", ep.get("path"), ep.get("framework", "Generic")[:18], auth_str, risk_label, src_str)

        console.print(table)
        if len(results.get("endpoints", [])) > 30:
            console.print(f"[dim]... and {len(results['endpoints']) - 30} more endpoints.[/]")

        if results.get("shadow_apis"):
            s_table = Table(title="Shadow / Undocumented APIs (Missing from OpenAPI Specs)", header_style="bold yellow")
            s_table.add_column("Method", width=8)
            s_table.add_column("Path", width=35)
            s_table.add_column("Location", width=30)
            for s in results["shadow_apis"][:10]:
                s_table.add_row(s.get("method"), s.get("path"), f"{s.get('file')}:{s.get('line')}")
            console.print(s_table)

    def export_openapi(self, endpoints: List[Dict[str, Any]], output_path: str, fmt: str = "yaml") -> None:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        content = self.openapi_gen.to_yaml(endpoints) if fmt == "yaml" else self.openapi_gen.to_json(endpoints)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    def export_sarif(self, results: Dict[str, Any], output_path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        sarif_dict = self.sarif_exporter.to_sarif(results.get("endpoints", []), results.get("shadow_apis", []))
        with open(output_path, "w", encoding="utf-8") as f:
            import json
            json.dump(sarif_dict, f, indent=2)
