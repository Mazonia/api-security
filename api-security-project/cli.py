#!/usr/bin/env python3
"""MazAPI Unified CLI ? Enterprise App Surface, Agent Audit, MCP Audit & API Security Suite.

Commands:
  mazapi app-surface scan <path>       Static AST route & parameter discovery across frameworks
  mazapi agent-audit scan <path>       Audit AI agents for authorization & tool execution gaps
  mazapi mcp-audit scan <path>         Audit local IDE & repository MCP server configurations
  mazapi mcp-audit source-scan <path>  Source-scan MCP server source code for injection sinks
  mazapi mcp-audit registry            Search and explore known MCP servers & risk ratings
  mazapi mcp-audit explain <flag>      Show remediation guidance for risk flags
  mazapi scan --target <url>           Run dynamic OWASP API Top 10 vulnerability scan
  mazapi train-models                  Train 32-feature calibrated ML threat models
"""
import argparse
import json
import os
import sys

from rich.console import Console
from rich.table import Table

console = Console()


def cmd_app_surface(args):
    from app_surface.scanner import AppSurfaceScanner
    scanner = AppSurfaceScanner(target_dir=args.path)
    res = scanner.scan(baseline_path=args.baseline)

    if args.update_baseline:
        scanner.diff_engine.save_baseline(res["endpoints"], args.update_baseline)
        console.print(f"[green]? Baseline snapshot updated -> {args.update_baseline}[/]")

    if args.format == "table":
        scanner.print_report(res)
    elif args.format == "json":
        out = json.dumps(res, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            console.print(f"[green]? JSON report saved -> {args.output}[/]")
        else:
            print(out)
    elif args.format in ("openapi", "openapi-yaml", "openapi-json"):
        fmt = "json" if args.format == "openapi-json" else "yaml"
        out_path = args.output or f"apisec-bolt-code-discovery/openapi_spec.{fmt}"
        scanner.export_openapi(res["endpoints"], out_path, fmt=fmt)
        console.print(f"[green]? OpenAPI 3.0 specification exported -> {out_path}[/]")
    elif args.format == "asyncapi":
        out_path = args.output or "asyncapi_spec.json"
        scanner.export_asyncapi(res["endpoints"], out_path)
        console.print(f"[green]? AsyncAPI 3.0 IoT specification exported -> {out_path}[/]")
    elif args.format == "sarif":
        out_path = args.output or "app-surface.sarif"
        scanner.export_sarif(res, out_path)
        console.print(f"[green]? SARIF 2.1.0 report exported -> {out_path}[/]")

    # CI Gating
    if args.fail_on:
        threshold = args.fail_on.lower()
        if threshold in ("high", "critical") and res["high_risk_count"] > 0:
            console.print(f"[red bold]? CI Gate Failed: Found {res['high_risk_count']} high-risk endpoints.[/]")
            sys.exit(1)
        elif threshold == "critical" and res["bfla_candidates"] > 0:
            console.print(f"[red bold]? CI Gate Failed: Found {res['bfla_candidates']} critical BFLA endpoints.[/]")
            sys.exit(1)


def cmd_agent_audit(args):
    from agent_audit.auditor import AgentAuditor
    auditor = AgentAuditor(target_dir=args.path)
    res = auditor.audit()

    if args.format == "table":
        auditor.print_report(res, show_governance=args.governance)
    elif args.format == "json":
        out = json.dumps(res, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            console.print(f"[green]? JSON report saved -> {args.output}[/]")
        else:
            print(out)
    elif args.format in ("cyclonedx", "ai-bom"):
        out_path = args.output or "ai-bom.json"
        auditor.export_ai_bom(res, out_path)
        console.print(f"[green]? CycloneDX 1.6 AI-BOM exported -> {out_path}[/]")
    elif args.format == "sarif":
        out_path = args.output or "agent-audit.sarif"
        auditor.export_sarif(res, out_path)
        console.print(f"[green]? SARIF 2.1.0 report exported -> {out_path}[/]")

    # CI Gating
    if args.fail_on:
        threshold = args.fail_on.lower()
        if threshold == "critical" and res["critical_count"] > 0:
            console.print(f"[red bold]? CI Gate Failed: Found {res['critical_count']} critical AI agent findings.[/]")
            sys.exit(1)
        elif threshold == "high" and (res["critical_count"] > 0 or res["high_count"] > 0):
            console.print(f"[red bold]? CI Gate Failed: Found {res['critical_count'] + res['high_count']} high/critical AI agent findings.[/]")
            sys.exit(1)


def cmd_mcp_audit(args):
    te_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testing-engine")
    if te_dir not in sys.path:
        sys.path.insert(0, te_dir)
    import mcp_audit

    if args.mcp_cmd == "scan":
        res = mcp_audit.scan_workspace_mcp(args.path)
        print(json.dumps(res, indent=2))
    elif args.mcp_cmd == "source-scan":
        res = mcp_audit.source_scan_directory(args.path)
        console.print(f"Scanned {res['scanned_files']} MCP server source files. Critical findings: {res['critical_count']}")
        for f in res.get("findings", []):
            console.print(f"[{f['severity']}] {f['title']} in {f['file']}:{f['line']}\n  Snippet: {f['snippet']}")
        if args.exit_code and res["critical_count"] > 0:
            sys.exit(1)
    elif args.mcp_cmd == "registry":
        table = Table(title="Known MCP Server Registry & Risk Posture", header_style="bold blue")
        table.add_column("MCP Name", style="cyan", width=20)
        table.add_column("Risk Level", style="bold", width=12)
        table.add_column("Scope", style="yellow", width=22)
        table.add_column("Description", style="dim", width=45)
        for name, info in mcp_audit.MCP_REGISTRY.items():
            r_color = "red" if info["risk"] == "CRITICAL" else ("orange3" if info["risk"] == "HIGH" else "green")
            table.add_row(name, f"[{r_color}]{info['risk']}[/]", info["scope"], info["desc"])
        console.print(table)
    elif args.mcp_cmd == "explain":
        flag = args.flag
        if flag in mcp_audit.RISK_EXPLANATIONS:
            info = mcp_audit.RISK_EXPLANATIONS[flag]
            console.print(f"[bold red]{info['title']} ({info['severity']})[/]\n\n{info['description']}\n\n[bold green]Remediation Guidance:[/] {info['remediation']}")
        else:
            console.print(f"Available risk flags: {', '.join(mcp_audit.RISK_EXPLANATIONS.keys())}")


def cmd_iot_audit(args):
    te_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testing-engine")
    if te_dir not in sys.path:
        sys.path.insert(0, te_dir)
    from owasp_tests.test_iot_api import run_iot_security_tests
    findings = run_iot_security_tests(args.target)
    console.print(f"[bold cyan]MazAPI IoT Security Audit for:[/] {args.target}")
    console.print(f"Discovered [bold red]{len(findings)}[/] IoT vulnerability findings.\n")
    for f in findings:
        console.print(f"[{f['severity']}] {f['title']} on {f['endpoint']}\n  CWE: {f['cwe']}\n  Evidence: {f['evidence']}\n")


def cmd_train_models(args):
    from monitoring.train_model import train_and_save
    train_and_save()


def main():
    parser = argparse.ArgumentParser(prog="mazapi", description="MazAPI Enterprise API & AI Surface Security Platform")
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. app-surface
    p_app = subparsers.add_parser("app-surface", help="Static code API & route discovery at PR time")
    p_app.add_argument("action", choices=["scan"], default="scan", nargs="?")
    p_app.add_argument("path", default=".", nargs="?")
    p_app.add_argument("--format", choices=["table", "json", "openapi", "openapi-yaml", "openapi-json", "asyncapi", "sarif"], default="table")
    p_app.add_argument("--output", "-o", help="Output file destination")
    p_app.add_argument("--baseline", help="Compare against baseline JSON file")
    p_app.add_argument("--update-baseline", help="Save current endpoints as new baseline JSON")
    p_app.add_argument("--fail-on", choices=["high", "critical"], help="Exit with non-zero on high or critical findings")

    # 2. agent-audit
    p_agent = subparsers.add_parser("agent-audit", help="Audit AI agents for authorization & tool call gaps")
    p_agent.add_argument("action", choices=["scan"], default="scan", nargs="?")
    p_agent.add_argument("path", default=".", nargs="?")
    p_agent.add_argument("--format", choices=["table", "json", "cyclonedx", "ai-bom", "sarif"], default="table")
    p_agent.add_argument("--output", "-o", help="Output file destination")
    p_agent.add_argument("--governance", action="store_true", help="Print EU AI Act, NIST AI RMF, and ISO 42001 clauses")
    p_agent.add_argument("--fail-on", choices=["high", "critical"], help="Exit with non-zero on high or critical findings")

    # 3. mcp-audit
    p_mcp = subparsers.add_parser("mcp-audit", help="MCP server configuration and source-level security audit")
    p_mcp.add_argument("mcp_cmd", choices=["scan", "source-scan", "registry", "explain"], default="scan")
    p_mcp.add_argument("path", default=".", nargs="?")
    p_mcp.add_argument("--flag", default="shell-injection-in-source", help="Risk flag for explain command")
    p_mcp.add_argument("--exit-code", action="store_true", help="Exit with non-zero code on critical findings")

    # 4. iot-audit
    p_iot = subparsers.add_parser("iot-audit", help="Audit IoT endpoints, MQTT brokers, CoAP, and OTA update surfaces")
    p_iot.add_argument("--target", default="http://localhost:8000", help="Target IoT API URL")

    # 5. train-models
    subparsers.add_parser("train-models", help="Train 32-feature calibrated ML anomaly and threat models")

    args = parser.parse_args()

    if args.subcommand == "app-surface":
        cmd_app_surface(args)
    elif args.subcommand == "agent-audit":
        cmd_agent_audit(args)
    elif args.subcommand == "mcp-audit":
        cmd_mcp_audit(args)
    elif args.subcommand == "iot-audit":
        cmd_iot_audit(args)
    elif args.subcommand == "train-models":
        cmd_train_models(args)
    else:
        parser.print_help()



if __name__ == "__main__":
    main()
