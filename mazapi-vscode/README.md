<h1 align="center">MazAPI Scanner</h1>

<p align="center">
  <strong>API Security Testing Framework &mdash; VS Code Extension</strong><br/>
  Detect API vulnerabilities, hardcoded secrets, and PII leaks directly inside your IDE
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-58a6ff?style=flat-square" alt="v1.0.0"/>
  <img src="https://img.shields.io/badge/VS%20Code-%5E1.85.0-007ACC?style=flat-square&logo=visualstudiocode" alt="VS Code"/>
  <img src="https://img.shields.io/badge/OWASP-API%20Top%2010-e06c00?style=flat-square" alt="OWASP"/>
  <img src="https://img.shields.io/badge/compliance-PCI--DSS%20%7C%20GDPR%20%7C%20ISO%2027001-3fb950?style=flat-square" alt="Compliance"/>
  <img src="https://img.shields.io/badge/CY384-UMaT%20Ghana-7c3aed?style=flat-square" alt="UMaT CY384"/>
</p>

---

## Overview

MazAPI Scanner brings a full API security testing engine into VS Code (and any VS Code-compatible IDE such as Antigravity, Cursor, Windsurf, or VSCodium). It combines two modes:

- **Static analysis** — scans source files for hardcoded secrets, API keys, PII patterns, and exposed endpoints without running any code
- **Live endpoint testing** — fires a full OWASP API Top 10 test suite against a running API, using your local MazAPI Docker backend

Results appear as red/yellow squiggles in the editor, entries in the Problems panel, and a rich visual results panel with compliance mappings, evidence captures, and export options.

---

## Features

- **File & workspace scan** — detects hardcoded bearer tokens, API keys, AWS credentials, credit card numbers, SSNs, email addresses, and plain-text passwords across JS, TS, Python, `.env`, and JSON files
- **Live OWASP API Top 10 scan** — broken object-level auth, broken auth, excessive data exposure, rate limiting, function-level auth, mass assignment, security misconfiguration, injection, JWT weak-secret + alg:none attacks
- **GraphQL security** — introspection exposure, query depth abuse, batch query abuse
- **PII detection** — scans API responses for unmasked personal data
- **Compliance mapping** — every finding is tagged with PCI-DSS, GDPR, and ISO 27001 Annex A references
- **Regression tracking** — NEW / RECURRING / FIXED badges comparing each scan against the previous result
- **Evidence capture** — exact request and response for each finding, collapsible inline
- **SARIF 2.1.0 export** — import into GitHub Security tab, JIRA, or any SARIF-aware tool
- **HTML report** — self-contained, shareable report with score cards and full finding details
- **Webhook alerts** — Slack / Microsoft Teams notifications for critical findings
- **Activity bar panel** — Findings and Detected Endpoints tree views
- **Auto-scan on save** — optional background scan triggered whenever a file is saved
- **Status bar shortcut** — one-click file scan from the bottom status bar

---

## Requirements

- VS Code 1.85 or any compatible fork (Antigravity, Cursor, Windsurf, VSCodium)
- Node.js 18+ and TypeScript 5.3+ (to build from source)
- For live endpoint scanning: Docker with the MazAPI stack running (`docker compose up -d`)

---

## Installation

### Option A — Install from VSIX (recommended)

```bash
# 1. Navigate to the extension directory
cd mazapi-vscode

# 2. Install dependencies and compile
npm install
npm run compile

# 3. Package as VSIX (requires @vscode/vsce)
npm install -g @vscode/vsce
vsce package --no-dependencies
# → produces mazapi-scanner-1.0.0.vsix

# 4. In your IDE: Ctrl+Shift+P → "Extensions: Install from VSIX…"
#    Select the .vsix file and reload when prompted
```

### Option B — Development mode (VS Code only)

Open the `mazapi-vscode/` folder in VS Code and press **F5**. This launches an Extension Development Host with MazAPI loaded. Changes to source require `npm run compile` and a window reload.

---

## Quick Start

1. **Start the Docker stack** (required for live scanning):
   ```bash
   docker compose up -d
   ```

2. **Open your project** in VS Code / Antigravity

3. **Click the shield icon** in the Activity Bar to open the MazAPI panel

4. **Configure settings** — press `Ctrl+,` and search for `mazapi`:
   - Set `mazapi.backendUrl` to `http://localhost:9000`
   - Set `mazapi.orgName` to your organisation name (shown in reports)

5. **Run your first scan** — press `Ctrl+Shift+P` → **MazAPI: Scan Current File**

---

## Commands

All commands are available via `Ctrl+Shift+P`:

| Command | Description |
|---|---|
| `MazAPI: Scan Current File for API Issues` | Static-analyse the active editor file for secrets, PII, and exposed endpoints. Results appear in the Problems panel (`Ctrl+Shift+M`). |
| `MazAPI: Scan Entire Workspace for API Issues` | Scans all `.js`, `.ts`, `.py`, `.env`, and `.json` files in the workspace (skips `node_modules`). Shows a progress bar. |
| `MazAPI: Scan This API Endpoint` | Place cursor on any line containing a URL and run this command (or right-click → context menu). Opens the results panel and fires a full live OWASP scan against that URL. |
| `MazAPI: Open Results Panel` | Open the results panel manually. Enter any API base URL and bearer token, then click **Run Full Scan**. |
| `MazAPI: Export Last Scan as SARIF` | Saves the most recent panel scan as a `.sarif` file in the workspace root. Importable into GitHub Security → Code Scanning. |
| `MazAPI: Export Last Scan as HTML Report` | Generates a self-contained HTML report and opens it in the default browser. |
| `MazAPI: Configure Webhook Alert URL` | Prompts for a Slack or Microsoft Teams incoming webhook URL and saves it to global settings. |

---

## Settings

Configure via `Ctrl+,` → search `mazapi`, or directly in `settings.json`:

| Setting | Type | Default | Description |
|---|---|---|---|
| `mazapi.backendUrl` | string | `http://localhost:9000` | URL of the MazAPI Docker monitoring container. Used for all live endpoint scans. |
| `mazapi.autoScanOnSave` | boolean | `false` | Automatically run a static file scan each time a supported file is saved. |
| `mazapi.webhookUrl` | string | `""` | Slack or Teams incoming webhook URL. The **Send Alert** button in the panel posts to this URL. Set via `MazAPI: Configure Webhook Alert URL` or directly here. |
| `mazapi.orgName` | string | `""` | Organisation name displayed in the header of exported HTML reports. |

---

## Results Panel

When you run a live scan, the panel shows:

```
┌──────────────────────────────────────────────────────┐
│  Score: 42 / 100   ● 2 Critical  ● 3 High  ● 1 Med  │
├──────────────────────────────────────────────────────┤
│  [↓ SARIF]  [↓ HTML Report]  [🔔 Send Alert]        │
├──────────────────────────────────────────────────────┤
│  ● BROKEN AUTH — JWT Weak Secret         [CRITICAL]  │
│    NEW  PCI-DSS 6.2  GDPR Art.32  ISO A.14.2        │
│    ▶ Evidence  (request / response)                  │
│    [Mark as False Positive]                          │
│                                                      │
│  ● RATE LIMITING — No 429 on brute force  [HIGH]    │
│    RECURRING  PCI-DSS 6.5  ISO A.9.4                │
│    ▶ Evidence                                        │
│  …                                                   │
└──────────────────────────────────────────────────────┘
```

- **Regression badges** — `NEW` (first time seen), `RECURRING` (seen in previous scan), `FIXED` (was failing, now passes)
- **Compliance chips** — PCI-DSS, GDPR, ISO 27001 references per finding
- **Evidence** — click the triangle to expand the exact HTTP request sent and response received
- **False positives** — click **Mark as False Positive** to grey out a finding without removing it from the record

---

## Static Analysis: What It Detects

The file scanner (`Ctrl+Shift+P` → **Scan Current File**) uses pattern matching to find:

| Category | Examples |
|---|---|
| Hardcoded API keys | `api_key = "sk-..."`, `API_KEY="..."` |
| Bearer tokens | `Authorization: Bearer eyJ...` in source |
| AWS credentials | `AKIAIOSFODNN7EXAMPLE`, `aws_secret_access_key` |
| Plain-text passwords | `password = "hunter2"`, `passwd="..."` |
| PII — email addresses | `user@example.com` in source literals |
| PII — credit card numbers | 16-digit sequences matching Luhn pattern |
| PII — SSN | `123-45-6789` pattern |
| Hardcoded API endpoints | `http://` / `https://` URLs in source |

---

## How It Works

```
┌─────────────────┐        HTTP        ┌──────────────────────────┐
│  VS Code Panel  │ ──────────────────► │  MazAPI Monitoring API   │
│  (Webview)      │ ◄────────────────── │  localhost:9000          │
└─────────────────┘    JSON results     └──────────────────────────┘
                                                   │
                                                   ▼
                                        ┌──────────────────────────┐
                                        │  Target API              │
                                        │  (your API under test)   │
                                        └──────────────────────────┘
```

1. You enter the target URL and bearer token in the panel
2. The extension sends the scan request to the MazAPI Docker container at `localhost:9000`
3. The container runs 15 OWASP test categories against your target API
4. Results are returned as JSON and rendered in the webview with compliance tags, evidence, and regression info
5. Exports (SARIF, HTML) are generated client-side in the webview and written to your filesystem via the extension host

---

## Compliance Coverage

| Standard | References included |
|---|---|
| **PCI-DSS v4** | Requirements 6.2, 6.4, 6.5, 8.2, 8.3 |
| **GDPR** | Articles 5(1)(f), 25, 32, 33 |
| **ISO/IEC 27001:2022** | Annex A controls A.8.24, A.9.4, A.14.2, A.18.1 |
| **OWASP API Security Top 10** | All 10 categories (API1 – API10) |
| **MITRE ATT&CK** | T1110 (Credential Access), T1190 (Exploit Public Facing) |
| **CWE** | CWE-20, 89, 200, 287, 306, 311, 352, 798, 918 |

---

## Project Context

MazAPI Scanner is part of the **MazAPI API Security Testing Framework**, developed as a graded CY384 semester project at the University of Mines and Technology (UMaT), Ghana. The full stack includes:

- `api-security-project/` — Docker Compose stack: vulnerable API, hardened API, ML anomaly detection monitoring service, OWASP testing engine
- `mazapi-extension/` — Chrome/Edge browser extension with live capture and scanning
- `mazapi-vscode/` — This VS Code extension

---

## License

MIT © MazAPI — UMaT Ghana, CY384
