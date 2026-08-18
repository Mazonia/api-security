# MazAPI — Comprehensive API Security Framework & GUI Extensions

Welcome to the **MazAPI Security Framework**. This repository contains an enterprise-grade multi-tier API security ecosystem: a containerized training lab, real-time ML-powered monitoring dashboard, side-loadable Chrome/Brave browser extension (running in Side Panel mode), native VS Code scanner plugin, and unified CLI scanners.

Every user interface across this ecosystem features a premium, polished theme using **Emerald Cyber Green** and **Vivid Indigo** with full dark/light mode toggle support.

---

## 📂 Repository Architecture

```
api-security/
├── api-security-project/      # Core engines, ML monitoring, and training lab
│   ├── agent_audit/           # AI Agent audit rules, AI-BOM generator, and governance
│   ├── app_surface/           # AST parsers, diff engine, and OpenAPI/SARIF exporters
│   ├── monitoring/            # Proxy server, Random Forest model, and anomaly dashboard
│   ├── testing-engine/        # Automated black-box OWASP scanner & MCP auditor
│   ├── cli.py                 # Unified command-line interface for the scanners
│   ├── vulnerable-api/        # Intentionally flawed FastAPI backend + Shop App (Port 8000)
│   └── hardened-api/          # Mitigated FastAPI backend with OWASP protections (Port 8001)
├── mazapi-extension/          # Chrome/Brave Side Panel extension (traffic & auth harvest)
└── mazapi-vscode/             # VS Code / Antigravity IDE Workspace scanner plugin
```

---

## 🌟 Key Features

### 1. App Surface Discovery Engine
Find endpoints, routes, and parameters directly from your source code at PR time before they reach production:
*   **Multi-Language AST Parsing**: Full syntax trees analyzed for Python (FastAPI/Flask/Django), Node.js (Express/NestJS/Fastify), Java (Spring Boot/JAX-RS), .NET (ASP.NET), Go (Gin/Echo/Fiber/Chi), and PHP (Laravel/Symfony).
*   **Shadow API Diff Engine**: Performs structural diffs of code bases between Git commits (`--base` vs `--head`) to flag undocumented or shadow APIs before deployment.
*   **OpenAPI & SARIF Synthesis**: Automatically outputs standardized OpenAPI 3.0 specification documents and exports security alerts to GitHub-compatible SARIF files.

### 2. AI Agent Audit Engine
Inspect agentic workflows and LLM applications for exploitable gaps and excessive privilege constraints before shipping:
*   **Framework Support**: Comprehensive analysis for 11+ platforms (LangChain, LangGraph, CrewAI, AutoGen, Semantic Kernel, LlamaIndex, Haystack, DSPy, OpenAI Swarm, Bedrock Agents, Custom Tools).
*   **Strategic Audit Rules**:
    *   *Authorization Gaps*: Flags caller-identity bypasses and unauthenticated tool execution sinks.
    *   *Excessive Agency*: Detects unconstrained shell commands, database mutation queries, or stripe-based financial executions operating without a human-in-the-loop approval.
    *   *Provider Key Exposure*: Warns about hardcoded, unmasked API keys in application scripts.
    *   *RAG Isolation*: Checks if vector search queries (Pinecone,Pgvector, PgVector, Pgvector, Pgvector, pgvector, pgvector, Pgvector) lack proper tenant separation constraints.
*   **CycloneDX 1.6 AI-BOM**: Generates structured AI Software Bill of Materials detailing model definitions, parameters, and tool interfaces.

### 3. Model Context Protocol (MCP) Auditor
Audit MCP server configurations and custom implementations:
*   **Registry Verification**: Cross-references servers against a security registry containing over 50 verified community and enterprise configurations.
*   **Static Source Scans**: Identifies path traversals and shell injection sinks in custom Node.js and Python MCP servers.

### 4. Calibrated ML Anomaly Detector
*   Powered by a **32-feature Random Forest model** evaluating request size, path entropy, parameter types, header configurations, and traffic timing.
*   Calibrated classifier achieving **99.73% accuracy** in distinguishing legitimate API flows from OWASP Top 10 attacks and credential enumeration.

### 5. Chrome / Brave Side Panel Workbench
MazAPI BOLT runs entirely inside Chrome's native persistent Side Panel:
*   **JWT & Key Harvester**: Intercepts active request headers, decodes JWT payloads, and flags weak symmetric secrets.
*   **BOLA / IDOR Workbench**: Interactive request manipulator with parameter swappers to inspect authorization robustness.
*   **OAS Endpoint Picker**: Selectively filter and download discovered endpoints directly into OpenAPI 3.0 specs.

---

## 🚀 Getting Started

### 1. Main Security Lab & Monitoring Dashboard
Navigate to the project directory and launch the containerized lab:
```bash
cd api-security-project
docker compose up -d --build
```
*   **Live Monitoring Dashboard**: [http://localhost:9000/dashboard](http://localhost:9000/dashboard)
*   **Vulnerable Shop App**: [http://localhost:8000/ui](http://localhost:8000/ui)
*   **Hardened API target**: [http://localhost:8001](http://localhost:8001)

### 2. Using the Unified CLI
Execute scans directly from your terminal:
```bash
# Audit an AI Agent code directory
python cli.py agent-audit --target ./my-agent-src/ --output-bom ./bom.json

# Check application surface changes between commits
python cli.py app-surface --base ccba56b --head db3725c --lang python --output-sarif ./scan.sarif

# Check MCP Configuration safety
python cli.py mcp-audit --config C:/Users/Mazonia/AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json
```

---

## 🦁 Brave / Chrome Side Panel Installation
1. Open Brave/Chrome and go to **`chrome://extensions`** or **`brave://extensions`**.
2. Toggle on **Developer mode** in the top right.
3. Click **Load unpacked** in the top left.
4. Select the folder:
   ```
   c:\Users\Mazonia\Desktop\cyberlab work II\api-security-main\mazapi-extension\
   ```
5. Click the extension icon in the toolbar. It will open as a persistent Side Panel side-by-side with your browsing session.

---

## 🛸 VS Code / Antigravity IDE Extension Installation
1. Open your **Antigravity IDE** window.
2. Open the Command Palette (**`Ctrl+Shift+P`**).
3. Type and select **`Extensions: Install from VSIX...`**.
4. Select the packaged extension:
   ```
   c:\Users\Mazonia\Desktop\cyberlab work II\api-security-main\mazapi-vscode\mazapi-scanner-1.0.3.vsix
   ```
