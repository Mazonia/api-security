"""Generate HTML, JSON, and SARIF reports from OWASP test results."""
import json
import os
from datetime import datetime
from jinja2 import Template

# ── Compliance mapping ────────────────────────────────────────────────────────
COMPLIANCE_MAP = {
    "API1:2023 - Broken Object Level Authorization":          {"pci_dss": ["6.2.4","8.2.3"],    "gdpr": ["Art. 5(1)(f)","Art. 32"],   "iso27001": ["A.9.4.1","A.14.2.5"]},
    "API2:2023 - Broken Authentication":                      {"pci_dss": ["8.2.1","8.3.1"],    "gdpr": ["Art. 32(1)(b)"],            "iso27001": ["A.9.4.3","A.10.1.1"]},
    "API3:2023 - Broken Object Property Level Authorization": {"pci_dss": ["6.2.4"],            "gdpr": ["Art. 5(1)(c)","Art. 25"],   "iso27001": ["A.14.2.5","A.18.1.3"]},
    "API4:2023 - Unrestricted Resource Consumption":          {"pci_dss": ["6.2.4","6.3.1"],    "gdpr": ["Art. 32"],                  "iso27001": ["A.12.6.1","A.17.2.1"]},
    "API5:2023 - Broken Function Level Authorization":        {"pci_dss": ["7.1.1","7.2.1"],    "gdpr": ["Art. 32(4)"],               "iso27001": ["A.9.2.3","A.9.4.1"]},
    "API8:2023 - Security Misconfiguration":                  {"pci_dss": ["6.3.3","6.4.1"],    "gdpr": ["Art. 32"],                  "iso27001": ["A.14.1.3","A.18.1.3"]},
    "API9:2023 - Improper Inventory Management (GraphQL)":    {"pci_dss": ["6.3.3"],            "gdpr": ["Art. 32"],                  "iso27001": ["A.12.6.1"]},
    "CWE-312 / GDPR - PII Exposure in API Responses":        {"pci_dss": ["3.4.1","4.2.1"],    "gdpr": ["Art. 5","Art. 17","Art. 25","Art. 32","Art. 83(4)"], "iso27001": ["A.18.1.4","A.8.2.3"]},
}

def _get_compliance(category: str) -> dict:
    for key, val in COMPLIANCE_MAP.items():
        if category == key or category.startswith(key.split(" - ")[0]):
            return val
    return {}


def generate_sarif(results: list, target: str) -> dict:
    """Generate a SARIF 2.1.0 document from test results."""
    seen_rules: set = set()
    rules = []
    for cat in results:
        cat_id = cat["category"].replace(" ", "-").replace("/", "-")[:64]
        if cat_id not in seen_rules:
            seen_rules.add(cat_id)
            rules.append({
                "id": cat_id,
                "name": cat["category"].split(" - ")[0],
                "shortDescription": {"text": cat["category"].split(" - ", 1)[-1]},
                "helpUri": "https://owasp.org/API-Security/",
                "properties": {"tags": ["security", "api"]},
            })

    sarif_results = []
    for cat in results:
        cat_id = cat["category"].replace(" ", "-").replace("/", "-")[:64]
        for t in cat["tests"]:
            if not t.get("vulnerable"):
                continue
            sarif_results.append({
                "ruleId": cat_id,
                "level": "error" if t.get("severity") in ("CRITICAL", "HIGH") else "warning",
                "message": {"text": f"{t['test']}: {t.get('actual', t.get('detail', 'Vulnerability detected'))}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": target, "uriBaseId": "TARGETROOT"}}}],
                "properties": {
                    "severity": t.get("severity"),
                    "expected": t.get("expected"),
                    "compliance": _get_compliance(cat["category"]),
                },
            })

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "MazAPI Testing Engine",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/Mazonia/api-security",
                    "rules": rules,
                }
            },
            "results": sarif_results,
            "properties": {"target": target, "scannedAt": datetime.utcnow().isoformat()},
        }],
    }

try:
    from cve_data import CVE_DB
except ImportError:
    CVE_DB = {}

_TEMPLATE = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MazAPI Security Test Report — {{ target }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@400;500;600;700;800&family=Outfit:wght@500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {
  --bg: #070b13;
  --surf: #0e1424;
  --surf2: #171e35;
  --surf-glass: rgba(14, 20, 36, 0.85);
  --border: rgba(255, 255, 255, 0.09);
  --border-glow: rgba(99, 102, 241, 0.35);
  --text: #f3f4f6;
  --text-muted: #9ca3af;
  --emerald: #10b981;
  --emerald-dim: rgba(16, 185, 129, 0.15);
  --indigo: #6366f1;
  --indigo-dim: rgba(99, 102, 241, 0.15);
  --rose: #f43f5e;
  --rose-dim: rgba(244, 63, 94, 0.15);
  --amber: #f59e0b;
  --amber-dim: rgba(245, 158, 11, 0.15);
  --purple: #8b5cf6;
  --radius: 14px;
  --radius-sm: 8px;
  --shadow: 0 10px 30px rgba(0,0,0,0.35);
  --toc-bg: rgba(14, 20, 36, 0.92);
  --card-bg: #0e1424;
}

[data-theme="light"] {
  --bg: #f8fafc;
  --surf: #ffffff;
  --surf2: #f1f5f9;
  --surf-glass: rgba(255, 255, 255, 0.9);
  --border: #e2e8f0;
  --border-glow: rgba(99, 102, 241, 0.25);
  --text: #0f172a;
  --text-muted: #64748b;
  --emerald: #059669;
  --emerald-dim: rgba(5, 150, 105, 0.12);
  --indigo: #4f46e5;
  --indigo-dim: rgba(79, 70, 229, 0.1);
  --rose: #dc2626;
  --rose-dim: rgba(220, 38, 38, 0.1);
  --amber: #d97706;
  --amber-dim: rgba(217, 119, 6, 0.12);
  --purple: #7c3aed;
  --shadow: 0 8px 24px rgba(149, 157, 165, 0.12);
  --toc-bg: rgba(255, 255, 255, 0.95);
  --card-bg: #ffffff;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  padding-bottom: 60px;
  transition: background 0.25s ease, color 0.25s ease;
}

/* ─── Top Header ─────────────────────────────────────────────────────────── */
.header {
  background: linear-gradient(135deg, #0a0f1d 0%, #1e1b4b 50%, #070b13 100%);
  padding: 40px 24px 36px;
  text-align: center;
  border-bottom: 1px solid var(--border);
  box-shadow: var(--shadow);
  position: relative;
  overflow: hidden;
}
[data-theme="light"] .header {
  background: linear-gradient(135deg, #ffffff 0%, #e0e7ff 60%, #f8fafc 100%);
  border-bottom: 1px solid #cbd5e1;
}

.header-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  max-width: 1320px;
  margin: 0 auto 18px;
}
.brand-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  background: var(--emerald-dim);
  color: var(--emerald);
  border: 1px solid rgba(16, 185, 129, 0.35);
  padding: 5px 14px;
  border-radius: 99px;
  font-size: 0.82rem;
  font-weight: 700;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}
.theme-toggle-btn {
  background: var(--surf);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 18px;
  border-radius: 99px;
  cursor: pointer;
  font-size: 0.85rem;
  font-weight: 700;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  transition: all 0.2s ease;
  box-shadow: 0 2px 8px rgba(0,0,0,0.15);
}
.theme-toggle-btn:hover {
  border-color: var(--indigo);
  color: var(--indigo);
  transform: translateY(-1px);
}

.header h1 {
  font-family: 'Outfit', sans-serif;
  color: var(--text);
  font-size: 2.3rem;
  font-weight: 800;
  letter-spacing: -0.02em;
  margin-bottom: 8px;
  display: inline-flex;
  align-items: center;
  gap: 12px;
}
.header p { color: var(--text-muted); font-size: 0.95rem; font-weight: 500; }
.header p span { color: var(--emerald); font-weight: 700; font-family: 'Fira Code', monospace; }
.detail-badge {
  background: var(--indigo-dim);
  color: var(--indigo);
  border: 1px solid rgba(99, 102, 241, 0.4);
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 0.45em;
  font-weight: 700;
  vertical-align: middle;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

/* ─── Main Layout with Side TOC ─────────────────────────────────────────── */
.layout {
  max-width: 1380px;
  margin: 0 auto;
  padding: 32px 24px;
  display: grid;
  grid-template-columns: 240px 1fr;
  gap: 32px;
  align-items: start;
}
@media (max-width: 1024px) {
  .layout { grid-template-columns: 1fr; }
  .report-toc { display: none; }
}

/* ─── Floating Sidebar TOC (Bookmarks) ──────────────────────────────────── */
.report-toc {
  position: sticky;
  top: 24px;
  background: var(--toc-bg);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 18px 14px;
  box-shadow: var(--shadow);
  max-height: calc(100vh - 48px);
  overflow-y: auto;
}
.toc-title {
  font-family: 'Outfit', sans-serif;
  font-size: 0.78rem;
  font-weight: 800;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  padding: 0 8px 10px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 10px;
  display: flex;
  align-items: center;
  gap: 6px;
}
.toc-list { list-style: none; display: flex; flex-direction: column; gap: 4px; }
.toc-item a {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  color: var(--text-muted);
  text-decoration: none;
  font-size: 0.82rem;
  font-weight: 600;
  transition: all 0.15s ease;
  line-height: 1.3;
}
.toc-item a:hover {
  background: var(--surf2);
  color: var(--indigo);
  transform: translateX(3px);
}
.toc-badge {
  margin-left: auto;
  font-size: 0.72rem;
  padding: 2px 6px;
  border-radius: 99px;
  font-weight: 700;
}

/* ─── Executive Score Cards ─────────────────────────────────────────────── */
.cards {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 18px;
  margin-bottom: 30px;
}
@media (max-width: 768px) {
  .cards { grid-template-columns: repeat(2, 1fr); }
}
.card {
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 22px 18px;
  text-align: center;
  box-shadow: var(--shadow);
  transition: transform 0.2s, border-color 0.2s;
  position: relative;
  overflow: hidden;
}
.card:hover { transform: translateY(-3px); border-color: var(--border-glow); }
.card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3.5px; }
.card.c-red::before { background: var(--rose); }
.card.c-indigo::before { background: var(--indigo); }
.card.c-green::before { background: var(--emerald); }
.card.c-yellow::before { background: var(--amber); }

.card .num {
  font-family: 'Outfit', sans-serif;
  font-size: 2.7rem;
  font-weight: 800;
  line-height: 1;
}
.card .lbl {
  color: var(--text-muted);
  font-size: 0.76rem;
  font-weight: 700;
  margin-top: 8px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.red { color: var(--rose); }
.green { color: var(--emerald); }
.indigo { color: var(--indigo); }
.yellow { color: var(--amber); }

/* ─── Analytics & Modern Charts Grid ────────────────────────────────────── */
.charts {
  display: grid;
  grid-template-columns: 1.4fr 1fr;
  gap: 22px;
  margin-bottom: 36px;
}
@media (max-width: 900px) {
  .charts { grid-template-columns: 1fr; }
}
.cbox {
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 24px;
  box-shadow: var(--shadow);
  position: relative;
}
.cbox-hdr {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}
.cbox h3 {
  color: var(--text);
  font-family: 'Outfit', sans-serif;
  font-weight: 700;
  font-size: 1.05rem;
  display: flex;
  align-items: center;
  gap: 8px;
}
.cbox h3::before {
  content: '';
  display: inline-block;
  width: 4px;
  height: 16px;
  background: var(--indigo);
  border-radius: 2px;
}
.chart-container {
  position: relative;
  height: 250px;
  width: 100%;
}
.donut-center-label {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  text-align: center;
  pointer-events: none;
}
.donut-score {
  font-family: 'Outfit', sans-serif;
  font-size: 2.1rem;
  font-weight: 800;
  color: var(--text);
  line-height: 1;
}
.donut-sub {
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  color: var(--text-muted);
  letter-spacing: 0.05em;
  margin-top: 4px;
}

/* ─── Category Sections ─────────────────────────────────────────────────── */
.cat {
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 28px;
  overflow: hidden;
  box-shadow: var(--shadow);
  transition: border-color 0.2s ease;
}
.cat:hover { border-color: var(--border-glow); }
.cat-hdr {
  padding: 18px 24px;
  border-bottom: 1px solid var(--border);
  background: var(--surf2);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
}
.cat-hdr h2 {
  font-family: 'Outfit', sans-serif;
  font-size: 1.15rem;
  font-weight: 700;
  color: var(--text);
}
.badge {
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.03em;
}
.bv { background: var(--rose-dim); color: var(--rose); border: 1px solid rgba(244,63,94,0.4); }
.bs { background: var(--emerald-dim); color: var(--emerald); border: 1px solid rgba(16,185,129,0.4); }
.sev-CRITICAL { background: rgba(244,63,94,0.2); color: var(--rose); border: 1px solid var(--rose); }
.sev-HIGH { background: var(--rose-dim); color: var(--rose); border: 1px solid rgba(244,63,94,0.5); }
.sev-MEDIUM { background: var(--amber-dim); color: var(--amber); border: 1px solid rgba(245,158,11,0.5); }
.sev-LOW { background: var(--indigo-dim); color: var(--indigo); border: 1px solid rgba(99,102,241,0.5); }

/* ─── Table ─────────────────────────────────────────────────────────────── */
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; text-align: left; }
th {
  background: var(--surf2);
  padding: 12px 18px;
  font-size: 0.76rem;
  color: var(--text-muted);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  border-bottom: 1px solid var(--border);
}
td {
  padding: 14px 18px;
  border-top: 1px solid var(--border);
  font-size: 0.88rem;
  word-break: break-word;
}
code {
  font-family: 'Fira Code', monospace;
  background: var(--surf2);
  color: var(--indigo);
  padding: 3px 8px;
  border-radius: 4px;
  font-size: 0.85em;
  border: 1px solid var(--border);
}
.vY { color: var(--rose); font-weight: 700; }
.vN { color: var(--emerald); font-weight: 700; }
.sC { color: var(--rose); font-weight: 800; }
.sH { color: var(--rose); font-weight: 700; }
.sM { color: var(--amber); font-weight: 700; }
.sL { color: var(--indigo); font-weight: 600; }

/* ─── CVE & Remediation Panel ───────────────────────────────────────────── */
.cve-panel {
  padding: 22px 24px;
  border-top: 1px solid var(--border);
  background: var(--surf2);
}
.cve-panel h4 {
  color: var(--text-muted);
  font-size: 0.78rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 14px;
}
.cve-row {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 16px;
  align-items: center;
}
.cve-badge {
  background: var(--indigo-dim);
  border: 1px solid rgba(99,102,241,0.3);
  border-radius: 6px;
  padding: 5px 12px;
  font-size: 0.82rem;
  font-family: 'Fira Code', monospace;
  color: var(--indigo);
  text-decoration: none;
  transition: all 0.15s ease;
  font-weight: 600;
}
.cve-badge:hover { background: var(--indigo); color: #fff; transform: translateY(-1px); }
.owasp-link {
  font-size: 0.84rem;
  color: var(--emerald);
  text-decoration: none;
  margin-left: auto;
  font-weight: 700;
}
.owasp-link:hover { text-decoration: underline; }
.vuln-desc {
  font-size: 0.92rem;
  color: var(--text);
  margin-bottom: 16px;
  line-height: 1.6;
}
.fixes h5 {
  font-size: 0.78rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  color: var(--text-muted);
  margin-bottom: 10px;
}
.fixes ol { padding-left: 20px; }
.fixes li {
  font-size: 0.88rem;
  color: var(--text);
  line-height: 1.7;
  padding: 3px 0;
}
.fixes li code { color: var(--emerald); }

/* ─── Detail PoC & Code Diffs ───────────────────────────────────────────── */
.detail-section {
  padding: 24px;
  border-top: 1px solid var(--border);
  background: var(--surf);
}
.impact-block { margin-bottom: 20px; }
.impact-block h4 {
  color: var(--amber);
  font-size: 0.82rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 10px;
}
.impact-block p { font-size: 0.92rem; color: var(--text); line-height: 1.7; }
.poc-block { margin-bottom: 20px; }
.poc-block h5 {
  font-size: 0.78rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  color: var(--text-muted);
  margin-bottom: 10px;
}
.poc-block ol { padding-left: 20px; }
.poc-block li { font-size: 0.88rem; color: var(--text); line-height: 1.7; padding: 3px 0; }
.code-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 12px; }
@media (max-width: 800px) { .code-grid { grid-template-columns: 1fr; } }
.code-label {
  font-size: 0.75rem;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  padding: 6px 14px;
  display: inline-block;
  border-radius: 6px 6px 0 0;
}
.code-label.vuln-lbl { background: var(--rose-dim); color: var(--rose); border: 1px solid rgba(244,63,94,0.3); border-bottom: none; }
.code-label.fix-lbl { background: var(--emerald-dim); color: var(--emerald); border: 1px solid rgba(16,185,129,0.3); border-bottom: none; }
pre.code-pre {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 0 8px 8px 8px;
  padding: 16px;
  font-size: 0.84rem;
  font-family: 'Fira Code', monospace;
  color: var(--text);
  overflow-x: auto;
  white-space: pre;
  margin: 0;
  line-height: 1.65;
}

.footer {
  text-align: center;
  padding: 32px;
  color: var(--text-muted);
  font-size: 0.85rem;
  border-top: 1px solid var(--border);
  margin-top: 40px;
}
.footer span { color: var(--emerald); font-weight: 700; }
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div class="brand-pill">🔒 MazAPI Security Suite</div>
    <button class="theme-toggle-btn" id="theme-btn" onclick="toggleReportTheme()">☀️ Light Mode</button>
  </div>
  <h1>🛡️ API Security Audit Report{% if detail == 'detailed' %}<span class="detail-badge">Detailed Analysis</span>{% endif %}</h1>
  <p>Target: <span>{{ target }}</span> &nbsp;•&nbsp; {{ timestamp }} &nbsp;•&nbsp; OWASP API Top 10 Standard</p>
</div>

<div class="layout">
  <!-- ─── Floating Table of Contents / Bookmarks ────────────────────────── -->
  <aside class="report-toc">
    <div class="toc-title">📑 Report Bookmarks</div>
    <ul class="toc-list">
      <li class="toc-item"><a href="#overview"><span>📊</span> Overview Cards</a></li>
      <li class="toc-item"><a href="#analytics"><span>📈</span> Visual Analytics</a></li>
      <li class="toc-title" style="margin-top: 12px;">🛡️ Category Breakdown</li>
      {% for cat in categories %}
      <li class="toc-item">
        <a href="#cat-{{ loop.index }}">
          <span>•</span>
          <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ cat.category.split(' - ')[0] }}</span>
          {% if cat.vulnerable_count > 0 %}
          <span class="toc-badge bv" style="margin-left:auto">{{ cat.vulnerable_count }}</span>
          {% else %}
          <span class="toc-badge bs" style="margin-left:auto">OK</span>
          {% endif %}
        </a>
      </li>
      {% endfor %}
    </ul>
  </aside>

  <!-- ─── Main Content ──────────────────────────────────────────────────── -->
  <main class="content">
    <section id="overview">
      <div class="cards">
        <div class="card c-red">
          <div class="num red">{{ total_vuln }}</div>
          <div class="lbl">Vulnerabilities Found</div>
        </div>
        <div class="card c-indigo">
          <div class="num indigo">{{ total_tests }}</div>
          <div class="lbl">Total Tests Executed</div>
        </div>
        <div class="card c-green">
          <div class="num green">{{ total_tests - total_vuln }}</div>
          <div class="lbl">Tests Passed (Secure)</div>
        </div>
        <div class="card c-yellow">
          <div class="num yellow">{{ "%.0f"|format(score) }}%</div>
          <div class="lbl">Security Posture Score</div>
        </div>
      </div>
    </section>

    <!-- ─── Analytics & Charts ─────────────────────────────────────────── -->
    <section id="analytics">
      <div class="charts">
        <div class="cbox">
          <div class="cbox-hdr">
            <h3>Vulnerability Findings by Category</h3>
          </div>
          <div class="chart-container">
            <canvas id="barChart"></canvas>
          </div>
        </div>
        <div class="cbox">
          <div class="cbox-hdr">
            <h3>Overall Security Posture</h3>
          </div>
          <div class="chart-container" style="position: relative;">
            <canvas id="doughnutChart"></canvas>
            <div class="donut-center-label">
              <div class="donut-score">{{ "%.0f"|format(score) }}%</div>
              <div class="donut-sub">{% if score >= 80 %}SECURE{% elif score >= 50 %}MODERATE{% else %}AT RISK{% endif %}</div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- ─── Detailed Category Findings ─────────────────────────────────── -->
    {% for cat in categories %}
    {% set cve = cve_db.get(cat.category, {}) %}
    <div class="cat" id="cat-{{ loop.index }}">
      <div class="cat-hdr">
        <h2>{{ cat.category }}</h2>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          {% if cve %}
          <span class="badge sev-{{ cve.severity }}">{{ cve.severity }}</span>
          {% endif %}
          <span class="badge {% if cat.vulnerable_count > 0 %}bv{% else %}bs{% endif %}">
            {{ cat.vulnerable_count }}/{{ cat.total }} Vulnerable
          </span>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Test Vector</th><th>Request Payload / Path</th><th>Expected Result</th><th>Actual Result</th><th>Severity</th><th>Status</th></tr>
          </thead>
          <tbody>
            {% for t in cat.tests %}
            <tr>
              <td style="font-weight:600;color:var(--text)">{{ t.test }}</td>
              <td><code>{{ t.request }}</code></td>
              <td style="color:var(--text-muted)">{{ t.expected }}</td>
              <td>{{ t.actual }}</td>
              <td class="s{{ t.severity[0] }}">{{ t.severity }}</td>
              <td class="{% if t.vulnerable %}vY{% else %}vN{% endif %}">{{ "VULNERABLE" if t.vulnerable else "SECURE" }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

      {% if cve %}
      <div class="cve-panel">
        <h4>CVE References &amp; Remediation Guidance</h4>
        <div class="cve-row">
          {% for cve_id in cve.cves %}
          <a class="cve-badge" href="https://nvd.nist.gov/vuln/detail/{{ cve_id }}" target="_blank" rel="noopener">{{ cve_id }}</a>
          {% endfor %}
          <a class="owasp-link" href="{{ cve.owasp_ref }}" target="_blank" rel="noopener">OWASP Official Guide &rarr;</a>
        </div>
        <p class="vuln-desc">{{ cve.description }}</p>
        <div class="fixes">
          <h5>Recommended Remediation Actions</h5>
          <ol>
            {% for fix in cve.fixes %}
            <li>{{ fix }}</li>
            {% endfor %}
          </ol>
        </div>
      </div>
      {% if detail == 'detailed' and cve.impact %}
      <div class="detail-section">
        <div class="impact-block">
          <h4>Impact Assessment</h4>
          <p>{{ cve.impact }}</p>
        </div>
        {% if cve.poc_steps %}
        <div class="poc-block">
          <h5>Proof of Concept — Attack Steps</h5>
          <ol>
            {% for step in cve.poc_steps %}
            <li>{{ step }}</li>
            {% endfor %}
          </ol>
        </div>
        {% endif %}
        {% if cve.code_before %}
        <div class="code-grid">
          <div class="code-pane">
            <div class="code-label vuln-lbl">Vulnerable Implementation</div>
            <pre class="code-pre">{{ cve.code_before|e }}</pre>
          </div>
          <div class="code-pane">
            <div class="code-label fix-lbl">Hardened Fix Implementation</div>
            <pre class="code-pre">{{ cve.code_after|e }}</pre>
          </div>
        </div>
        {% endif %}
      </div>
      {% endif %}
      {% endif %}
    </div>
    {% endfor %}

    <div class="footer">
      MazAPI Security Suite &nbsp;•&nbsp; <span>CY384 Cybersecurity Lab Work II</span> &nbsp;•&nbsp; University of Mines and Technology, Ghana
    </div>
  </main>
</div>

<script>
let barChartInstance = null;
let doughnutChartInstance = null;

const labels = {{ cat_labels|tojson }};
const vulns  = {{ vuln_counts|tojson }};
const totalVuln = {{ total_vuln }};
const totalTests = {{ total_tests }};
const totalPass = Math.max(0, totalTests - totalVuln);

function getThemeColors() {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  return {
    textColor: isLight ? '#475569' : '#9ca3af',
    gridColor: isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.06)',
    cardBg: isLight ? '#ffffff' : '#0e1424',
    font: 'Inter'
  };
}

function initCharts() {
  const tc = getThemeColors();
  
  // 1. Horizontal Gradient Bar Chart
  const ctxBar = document.getElementById('barChart').getContext('2d');
  const gradientBar = ctxBar.createLinearGradient(0, 0, 400, 0);
  gradientBar.addColorStop(0, '#f43f5e');
  gradientBar.addColorStop(1, '#fb7185');

  if (barChartInstance) barChartInstance.destroy();
  barChartInstance = new Chart(ctxBar, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Vulnerabilities',
        data: vulns,
        backgroundColor: vulns.map(v => v > 0 ? gradientBar : 'rgba(16,185,129,0.3)'),
        borderColor: vulns.map(v => v > 0 ? '#f43f5e' : '#10b981'),
        borderWidth: 1.5,
        borderRadius: 8,
        borderSkipped: false
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: tc.cardBg,
          titleColor: tc.textColor,
          bodyColor: tc.textColor,
          borderColor: 'rgba(99,102,241,0.4)',
          borderWidth: 1,
          padding: 10,
          boxPadding: 4,
          usePointStyle: true
        }
      },
      scales: {
        x: {
          ticks: { color: tc.textColor, font: { family: tc.font, size: 11 } },
          grid: { display: false }
        },
        y: {
          ticks: { color: tc.textColor, stepSize: 1, font: { family: tc.font, size: 11 } },
          grid: { color: tc.gridColor }
        }
      }
    }
  });

  // 2. Modern Doughnut Chart
  const ctxDoughnut = document.getElementById('doughnutChart').getContext('2d');
  if (doughnutChartInstance) doughnutChartInstance.destroy();
  doughnutChartInstance = new Chart(ctxDoughnut, {
    type: 'doughnut',
    data: {
      labels: ['Vulnerable Findings', 'Secure / Passed'],
      datasets: [{
        data: [totalVuln, totalPass],
        backgroundColor: ['#f43f5e', '#10b981'],
        borderColor: [tc.cardBg, tc.cardBg],
        borderWidth: 4,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '76%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: tc.textColor, font: { family: tc.font, size: 12 }, padding: 14 }
        }
      }
    }
  });
}

function toggleReportTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('mazapi_report_theme', next);
  
  const btn = document.getElementById('theme-btn');
  if (btn) btn.innerHTML = next === 'light' ? '🌙 Dark Mode' : '☀️ Light Mode';
  
  initCharts();
}

// Load saved theme
const savedTheme = localStorage.getItem('mazapi_report_theme');
if (savedTheme) {
  document.documentElement.setAttribute('data-theme', savedTheme);
  const btn = document.getElementById('theme-btn');
  if (btn) btn.innerHTML = savedTheme === 'light' ? '🌙 Dark Mode' : '☀️ Light Mode';
}

window.addEventListener('DOMContentLoaded', initCharts);
</script>
</body>
</html>"""


def generate(results: list, target: str, report_dir: str = "/reports", detail: str = "brief") -> tuple:
    ts_label = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    ts_file  = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    total_vuln  = sum(r["vulnerable_count"] for r in results)
    total_tests = sum(r["total"] for r in results)
    score = max(0.0, (1 - total_vuln / total_tests) * 100) if total_tests else 100.0

    cat_labels  = [r["category"].split(" - ")[0] for r in results]
    vuln_counts = [r["vulnerable_count"] for r in results]

    os.makedirs(report_dir, exist_ok=True)
    slug = target.replace("http://", "").replace(":", "-").replace("/", "_")

    # Enrich results with compliance mapping
    for cat in results:
        compliance = _get_compliance(cat["category"])
        if compliance:
            cat["compliance"] = compliance

    suffix = f"_{detail}" if detail != "brief" else ""
    json_path = os.path.join(report_dir, f"report_{slug}_{ts_file}{suffix}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"target": target, "timestamp": ts_label,
                   "score": round(score, 1), "detail": detail, "results": results}, f, indent=2)

    html_path = os.path.join(report_dir, f"report_{slug}_{ts_file}{suffix}.html")
    html = Template(_TEMPLATE).render(
        target=target, timestamp=ts_label, categories=results,
        total_vuln=total_vuln, total_tests=total_tests, score=score,
        cat_labels=cat_labels, vuln_counts=vuln_counts,
        cve_db=CVE_DB,
        detail=detail,
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # SARIF export (always generated alongside JSON/HTML)
    sarif_path = os.path.join(report_dir, f"report_{slug}_{ts_file}{suffix}.sarif")
    with open(sarif_path, "w", encoding="utf-8") as f:
        json.dump(generate_sarif(results, target), f, indent=2)

    return json_path, html_path, sarif_path
