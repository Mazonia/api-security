# MazAPI — Comprehensive API Security Framework & GUI Extensions

Welcome to the **MazAPI Security Framework**. This repository contains a complete multi-tier API security training lab, real-time ML-powered monitoring dashboard, side-loadable browser extension, and a native VS Code scanner plugin. 

Every user interface across this ecosystem features a unified, premium **Emerald Cyber Green** and **Vivid Indigo** theme with full dark/light mode toggle support.

---

## 📂 Repository Architecture

```
api-security/
├── api-security-project/      # Main FastAPI services & ML monitoring lab
│   ├── vulnerable-api/        # Port 8000 — Intentionally flawed FastAPI backend + Shop App
│   ├── hardened-api/          # Port 8001 — Fixed FastAPI backend with OWASP mitigations
│   ├── monitoring/            # Port 9000 — Proxy server + Real-time dashboard + ML models
│   └── testing-engine/        # Automated black-box OWASP scanner & report generator
├── mazapi-extension/          # Side-loadable Brave Browser Extension (intercepts API calls)
└── mazapi-vscode/             # VS Code / Antigravity IDE Extension (run scans in workspace)
```

---

## 🚀 Getting Started

### 1. Main Security Lab & Monitoring Dashboard
Navigate to the project directory and build the containerized environment:
```bash
cd api-security-project
docker compose up -d --build
```
- **Live Monitoring Dashboard**: [http://localhost:9000/dashboard](http://localhost:9000/dashboard)
- **Vulnerable Shop App target**: [http://localhost:8000/ui](http://localhost:8000/ui)
- **Hardened API target**: [http://localhost:8001](http://localhost:8001)
- **VulnBank Lab target**: [http://localhost:8002/lab/ui](http://localhost:8002/lab/ui) (port `8002` inside containers)

---

## 🦁 Brave Browser Extension Installation
The browser extension allows you to inspect APIs, intercept tokens, detect keys, and execute localized OWASP security scans.

1. Open Brave and go to **`brave://extensions`**.
2. Enable **Developer mode** in the top-right corner.
3. Click **Load unpacked** in the top-left corner.
4. Select the unpacked directory:
   ```
   c:\Users\username\Desktop\cyberlab work II\api-security-main\mazapi-extension\
   ```
5. Click the extension icon to view captured calls and toggle between Dark/Light mode.

---

## 🛸 VS Code / Antigravity Extension Installation
Run fully-fledged black-box security scans from the comfort of your editor.

1. Open your **Antigravity IDE** window.
2. Open the Command Palette (**`Ctrl+Shift+P`**).
3. Type and select **`Extensions: Install from VSIX...`**.
4. Browse and select the packaged VSIX package:
   ```
   c:\Users\username\Desktop\cyberlab work II\api-security-main\mazapi-vscode\mazapi-scanner-1.0.3.vsix
   ```
5. The extension sidebar view is now loaded. Configure your target endpoint, optional authentication bearer tokens, and trigger a scan.
