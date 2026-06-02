# CY384 API Security Framework

A live, interactive API security demonstration framework covering six OWASP API Security Top 10:2023 vulnerabilities. Runs entirely in Docker with no internet required during demos.

**University of Mines and Technology (UMaT), Ghana — CY384 Network and Application Security**

---

## What's Inside

| Component | Port | Description |
|---|---|---|
| `vulnerable-api` | 8000 | FastAPI backend with six intentional OWASP flaws + Shop App UI |
| `hardened-api` | 8001 | Same API with every flaw corrected |
| `monitoring` | 9000 | Transparent proxy + real-time ML anomaly detection + live dashboard |
| `testing-engine` | — | Automated black-box scanner (run-once, profile: tools) |

### OWASP Categories Covered

| ID | Category | Demo Method |
|---|---|---|
| API1:2023 | Broken Object Level Authorization (BOLA) | Shop App / demo.py |
| API2:2023 | Broken Authentication (JWT Forgery) | Python shell / demo.py |
| API3:2023 | Mass Assignment (Privilege Escalation) | Shop App / demo.py |
| API4:2023 | Unrestricted Resource Consumption (Rate Limiting) | rate_limit_demo.py |
| API5:2023 | Broken Function Level Authorization | Shop App / demo.py |
| API8:2023 | Security Misconfiguration (Debug Endpoint) | Shop App / demo.py |

---

## Quick Start

### Prerequisites

- Docker Desktop (running)
- Python 3.9+ with `httpx rich python-jose` installed on the host

### Start

```bash
# Clone and enter the project
git clone https://github.com/Mazonia/api-security.git
cd api-security

# First run (builds images — takes ~2 min)
docker compose up -d --build

# Subsequent runs (uses cached images)
docker compose up -d

# Verify all containers are up
docker compose ps

# Health check
curl http://localhost:9000/monitor/health
```

### Open the Dashboard

```
http://localhost:9000/dashboard
```

Keep the dashboard open alongside any demo. Every request appears within 10 seconds.

### Stop

```bash
# Stop containers (data preserved)
docker compose down

# Full reset (also clears database and ML model)
docker compose down
del data\traffic.db
del data\model.joblib
```

---

## Demo Scripts

All scripts run from the project root on the **host machine** (not inside Docker). All traffic routes through the monitoring proxy at port 9000 so requests appear on the dashboard.

```bash
# Install host dependencies
pip install httpx rich python-jose

# Automated press-Enter walkthrough of all 6 OWASP scenarios
python demo.py

# Interactive API4 rate-limit brute-force demo (choose a preset)
python rate_limit_demo.py

# Standalone comparison: runs all 7 attack scenarios against both APIs
python evaluate.py

# Regenerate the presenter reference guide (HTML + PDF)
python generate_report.py
```

### rate_limit_demo.py Presets

| Preset | Requests | Delay | Use case |
|---|---|---|---|
| 1 — Light | 6 | 0.3 s | Quick classroom demo |
| 2 — Medium | 12 | 0.1 s | Password-spray simulation |
| 3 — Heavy | 20 | none | Rapid brute-force |
| 4 — Burst | 30 | none | Full sustained attack demo |

---

## Architecture

```
  ┌──────────────────── Docker Bridge: api-net ────────────────────┐
  │                                                                  │
  │   vulnerable-api:8000          hardened-api:8001                │
  │   (FastAPI + Shop App)         (FastAPI + all fixes)            │
  │           │                           │                         │
  │   ┌───────┴───────────────────────────┴────────┐               │
  │   │         monitoring:9000                     │               │
  │   │  Transparent Proxy + SQLite + ML + Dashboard│               │
  │   └─────────────────────────────────────────────┘               │
  └──────────────────────────────────────────────────────────────────┘
         ▲                    ▲                   ▲
    localhost:8000       localhost:8001       localhost:9000
   (vulnerable api        (direct access)    (monitoring +
    + shop app UI)                            proxy entry)
```

> **Important:** All traffic that should appear on the dashboard must go through port 9000. The `X-Target: hardened` request header routes traffic to the hardened API while keeping monitoring visibility.

---

## Monitoring & ML Detection

The monitoring service uses a two-layer detection system:

**Rule-based (fires first):**
| Trigger | Reason code | Score |
|---|---|---|
| JWT sub ≠ user ID in /users/{id} | `bola_object_accessed` | -0.8 |
| /debug in path | `debug_endpoint_access` | -0.9 |
| /admin in path | `admin_endpoint_access` | -0.7 |
| HTTP 429 response | `rate_limit_triggered` | -0.5 |

**ML fallback:** IsolationForest trained on 2000 synthetic normal-traffic samples with `contamination=0.05`. The model is auto-trained on first startup if `/data/model.joblib` is missing.

---

## Automated Scanner

```bash
# Brief report (pass/fail + score)
docker compose run --rm --profile tools testing-engine

# Detailed report (CVEs, PoC payloads, remediation steps)
docker compose run --rm --profile tools -e REPORT_DETAIL=detailed testing-engine
```

Reports appear in the dashboard → **Reports** tab as HTML files you can open directly.

---

## Credentials (demo only)

| Account | Username | Password | Role |
|---|---|---|---|
| Alice | alice | alice123 | user |
| Bob | bob | bob123 | user |
| Admin | admin | admin123 | admin |
| JWT weak secret (vulnerable only) | — | `secret` | — |

---

## Repository Structure

```
api-security/
├── docker-compose.yml        # Orchestrates all four services
├── .env                      # JWT_SECRET and ALLOWED_ORIGINS for hardened API
├── demo.py                   # Automated CLI demo (all 6 scenarios)
├── rate_limit_demo.py        # Interactive API4 rate-limit demo
├── evaluate.py               # Standalone comparison script
├── generate_report.py        # Generates presenter reference guide
├── DEMO_SCRIPT.md            # Step-by-step presentation guide
├── vulnerable-api/           # Intentionally flawed FastAPI + Shop App UI
├── hardened-api/             # Fixed FastAPI with all OWASP mitigations
├── monitoring/               # Proxy + SQLite + IsolationForest + dashboard
│   ├── static/chart.min.js   # Bundled Chart.js (offline capable)
│   └── templates/dashboard.html
├── testing-engine/           # Black-box OWASP scanner
│   └── owasp_tests/          # One test module per OWASP category
├── data/                     # Runtime only — traffic.db + model.joblib
└── reports/                  # Scanner and comparison report output
```

---

## License

MIT — see [LICENSE](LICENSE).
