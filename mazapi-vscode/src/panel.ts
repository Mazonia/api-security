import * as vscode from 'vscode';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

export class MazAPIPanel {
    public static currentPanel: MazAPIPanel | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private _target: string;
    private _lastData: unknown = null;

    public static createOrShow(extensionUri: vscode.Uri, target: string) {
        const col = vscode.window.activeTextEditor ? vscode.ViewColumn.Beside : vscode.ViewColumn.One;
        if (MazAPIPanel.currentPanel) {
            MazAPIPanel.currentPanel._panel.reveal(col);
            MazAPIPanel.currentPanel._target = target;
            MazAPIPanel.currentPanel._update(target);
            return;
        }
        const panel = vscode.window.createWebviewPanel(
            'mazapiScanner', 'MazAPI Scanner', col,
            { enableScripts: true, retainContextWhenHidden: true }
        );
        MazAPIPanel.currentPanel = new MazAPIPanel(panel, extensionUri, target);
    }

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri, target: string) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this._target = target;
        this._update(target);
        this._panel.onDidDispose(() => { MazAPIPanel.currentPanel = undefined; });
        this._panel.webview.onDidReceiveMessage(async msg => {
            switch (msg.type) {
                case 'runScan':      await this._runScan(msg.target, msg.token); break;
                case 'exportSARIF': this._exportSARIF(msg.data); break;
                case 'exportHTML':  this._exportHTML(msg.html); break;
                case 'sendWebhook': {
                    // URL comes from VS Code settings, not from webview (prompt() is blocked in webviews)
                    const url = vscode.workspace.getConfiguration('mazapi').get<string>('webhookUrl') || '';
                    await this._sendWebhook(url, msg.data);
                    break;
                }
                case 'triggerExport':
                    // Triggered by mazapi.exportSARIF / mazapi.exportHTML commands from command palette
                    if (this._lastData) {
                        if (msg.format === 'sarif') this._exportSARIF(this._lastData);
                        if (msg.format === 'html')  this._panel.webview.postMessage({ type: 'requestHtml' });
                    } else {
                        vscode.window.showWarningMessage('MazAPI: Run a scan first.');
                    }
                    break;
            }
        });
    }

    public postToWebview(msg: unknown) {
        this._panel.webview.postMessage(msg);
    }

    private async _runScan(target: string, token: string) {
        const cfg = vscode.workspace.getConfiguration('mazapi');
        const backendUrl = cfg.get<string>('backendUrl') || 'http://localhost:9000';
        this._panel.webview.postMessage({ type: 'scanStarted' });
        try {
            const payload: Record<string, unknown> = { target, tests: null };
            if (token) payload.direct_token = token;
            const resp = await fetch(`${backendUrl}/monitor/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                signal: AbortSignal.timeout(120000),
            });
            const data = await resp.json();
            this._lastData = data;
            this._panel.webview.postMessage({ type: 'scanResult', data });
        } catch (err: unknown) {
            const m = err instanceof Error ? err.message : String(err);
            this._panel.webview.postMessage({ type: 'scanError', message: m });
        }
    }

    private _exportSARIF(data: unknown) {
        const d = data as Record<string, unknown>;
        const categories = (d.categories as unknown[]) || [];
        const seen = new Set<string>();
        const rules: unknown[] = [];
        for (const cat of categories as Record<string, unknown>[]) {
            const rid = String(cat.category).replace(/[ /]/g, '-').slice(0, 64);
            if (!seen.has(rid)) { seen.add(rid); rules.push({ id: rid, name: String(cat.category).split(' - ')[0], shortDescription: { text: String(cat.category) }, helpUri: 'https://owasp.org/API-Security/' }); }
        }
        const results: unknown[] = [];
        for (const cat of categories as Record<string, unknown>[]) {
            const rid = String(cat.category).replace(/[ /]/g, '-').slice(0, 64);
            for (const t of (cat.tests as Record<string, unknown>[]) || []) {
                if (!t.vulnerable) continue;
                results.push({ ruleId: rid, level: ['CRITICAL','HIGH'].includes(String(t.severity)) ? 'error' : 'warning', message: { text: `${t.test}: ${t.actual}` }, locations: [{ physicalLocation: { artifactLocation: { uri: String(d.target || ''), uriBaseId: 'TARGETROOT' } } }], properties: { severity: t.severity, compliance: (cat as Record<string,unknown>).compliance || {} } });
            }
        }
        const sarif = { version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [{ tool: { driver: { name: 'MazAPI Scanner', version: '2.0.0', rules } }, results, properties: { target: d.target, scannedAt: new Date().toISOString() } }] };
        this._downloadJSON(sarif, `mazapi-${Date.now()}.sarif`);
    }

    private _exportHTML(html: string) {
        const wsFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        const filePath = path.join(wsFolder || os.tmpdir(), `mazapi-report-${Date.now()}.html`);
        fs.writeFileSync(filePath, html, 'utf8');
        vscode.env.openExternal(vscode.Uri.file(filePath));
        vscode.window.showInformationMessage(`MazAPI HTML report saved: ${filePath}`);
    }

    private async _sendWebhook(webhookUrl: string, data: unknown) {
        if (!webhookUrl) { vscode.window.showWarningMessage('No webhook URL configured (mazapi.webhookUrl).'); return; }
        try {
            const d = data as Record<string, unknown>;
            const categories = (d.categories as Record<string,unknown>[]) || [];
            const vulns = categories.flatMap(c => (c.tests as Record<string,unknown>[]).filter(t => t.vulnerable));
            const payload = { source: 'MazAPI VS Code Extension', target: d.target, score: d.score, total_tests: d.total_tests, total_vulnerable: d.total_vulnerable, text: `*MazAPI Alert* — \`${d.target}\`\nScore: *${d.score}%* | Vulnerable: ${d.total_vulnerable}/${d.total_tests}`, findings: vulns.slice(0,10).map(t => ({ test: t.test, severity: t.severity, actual: t.actual })) };
            await fetch(webhookUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: AbortSignal.timeout(10000) });
            vscode.window.showInformationMessage('MazAPI: Webhook alert sent.');
        } catch (e) {
            vscode.window.showErrorMessage(`MazAPI webhook failed: ${e instanceof Error ? e.message : e}`);
        }
    }

    private _downloadJSON(obj: unknown, filename: string) {
        const wsFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        const filePath = path.join(wsFolder || os.tmpdir(), filename);
        fs.writeFileSync(filePath, JSON.stringify(obj, null, 2), 'utf8');
        vscode.env.openExternal(vscode.Uri.file(filePath));
        vscode.window.showInformationMessage(`MazAPI: ${filename} saved to workspace.`);
    }

    private _update(target: string) {
        this._panel.title = 'MazAPI Scanner';
        this._panel.webview.html = this._getHtml(target);
    }

    private _getHtml(target: string): string {
        return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--vscode-font-family);background:var(--vscode-editor-background);color:var(--vscode-foreground);padding:20px;font-size:13px}
h1{font-size:1.1em;margin-bottom:16px;color:var(--vscode-textLink-foreground)}
.field{margin-bottom:12px}
.field label{display:block;font-size:.85em;color:var(--vscode-descriptionForeground);margin-bottom:4px}
.field input{width:100%;background:var(--vscode-input-background);border:1px solid var(--vscode-input-border);color:var(--vscode-input-foreground);padding:6px 8px;border-radius:3px;font-family:inherit;font-size:.9em}
button{background:var(--vscode-button-background);color:var(--vscode-button-foreground);border:none;border-radius:3px;padding:8px 18px;cursor:pointer;font-size:.9em;font-family:inherit}
button:hover{background:var(--vscode-button-hoverBackground)}
button:disabled{opacity:.5;cursor:not-allowed}
.btn-sec{background:transparent;color:var(--vscode-textLink-foreground);border:1px solid var(--vscode-textLink-foreground);margin-left:6px;padding:6px 12px}
.btn-sec:hover{background:var(--vscode-textLink-activeForeground);color:#fff}
#status{margin-top:10px;font-size:.85em;color:var(--vscode-descriptionForeground)}
.result{border-left:3px solid;padding:10px 12px;margin-bottom:6px;border-radius:0 4px 4px 0}
.result.vuln{border-color:#f85149;background:rgba(248,81,73,.08)}
.result.safe{border-color:#3fb950;background:rgba(63,185,80,.08)}
.result-title{font-weight:600;font-size:.9em}
.result-cat{font-size:.78em;color:var(--vscode-descriptionForeground);margin-top:2px}
.result-detail{font-size:.82em;margin-top:4px}
.compliance{font-size:.74em;color:var(--vscode-descriptionForeground);margin-top:5px}
.comp-chip{background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid rgba(88,166,255,.3);border-radius:3px;padding:1px 5px;margin-right:3px}
details summary{font-size:.75em;color:#58a6ff;cursor:pointer;margin-top:5px}
details pre{background:var(--vscode-textBlockQuote-background);border:1px solid var(--vscode-widget-border);border-radius:3px;padding:6px;font-size:.73em;white-space:pre-wrap;margin-top:4px;word-break:break-all}
.score{font-size:1.8em;font-weight:700;text-align:center;padding:10px 0}
.export-bar{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.reg-badge{display:inline-block;border:1px solid;border-radius:3px;padding:1px 5px;font-size:.72em;font-weight:700;margin-left:6px;vertical-align:middle}
</style></head><body>
<div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width="36" height="36" style="flex-shrink:0;border-radius:8px">
  <defs>
    <linearGradient id="ppr" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#00d4ff"/><stop offset="100%" stop-color="#7c3aed"/></linearGradient>
    <linearGradient id="pwv" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stop-color="#00d4ff" stop-opacity="0"/><stop offset="20%" stop-color="#00d4ff"/><stop offset="80%" stop-color="#00d4ff"/><stop offset="100%" stop-color="#00d4ff" stop-opacity="0"/></linearGradient>
    <filter id="pgl"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <filter id="psg"><feGaussianBlur stdDeviation="1.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
  </defs>
  <polygon points="100,24 161,59 161,129 100,164 39,129 39,59" fill="url(#ppr)" fill-opacity="0.14"/>
  <polygon points="100,24 161,59 161,129 100,164 39,129 39,59" fill="none" stroke="url(#ppr)" stroke-width="2.5" filter="url(#pgl)"/>
  <polygon points="100,44 143,69 143,119 100,144 57,119 57,69" fill="none" stroke="url(#ppr)" stroke-width="0.8" opacity="0.22"/>
  <circle cx="100" cy="44" r="3" fill="#00d4ff" opacity="0.45"/>
  <circle cx="143" cy="69" r="2.5" fill="#7c3aed" opacity="0.45"/>
  <circle cx="143" cy="119" r="2.5" fill="#7c3aed" opacity="0.45"/>
  <circle cx="100" cy="144" r="3" fill="#00d4ff" opacity="0.45"/>
  <circle cx="57" cy="119" r="2.5" fill="#7c3aed" opacity="0.45"/>
  <circle cx="57" cy="69" r="2.5" fill="#7c3aed" opacity="0.45"/>
  <circle cx="68"  cy="65" r="5.5" fill="#00d4ff" opacity="0.9" filter="url(#psg)"/>
  <circle cx="100" cy="96" r="5.5" fill="#00d4ff" opacity="0.8" filter="url(#psg)"/>
  <circle cx="132" cy="65" r="5.5" fill="#00d4ff" opacity="0.9" filter="url(#psg)"/>
  <path d="M68,120 L68,65 L100,96 L132,65 L132,120" fill="none" stroke="#dde3ec" stroke-width="11" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M68,120 L68,65 L100,96 L132,65 L132,120" fill="none" stroke="url(#ppr)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" opacity="0.4"/>
  <path d="M70,145 L80,135 L90,152 L100,135 L110,152 L120,135 L130,145" fill="none" stroke="url(#pwv)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" filter="url(#psg)"/>
  <circle cx="80" cy="135" r="2.5" fill="#00d4ff" opacity="0.9"/>
  <circle cx="90" cy="152" r="2" fill="#00d4ff" opacity="0.55"/>
  <circle cx="100" cy="135" r="2.5" fill="#00d4ff" opacity="0.9"/>
  <circle cx="110" cy="152" r="2" fill="#00d4ff" opacity="0.55"/>
  <circle cx="120" cy="135" r="2.5" fill="#00d4ff" opacity="0.9"/>
</svg>
<h1 style="margin:0">MazAPI Scanner</h1>
</div>
<div style="color:#3fb950;font-size:.8em;margin:-4px 0 12px;line-height:1.5">&#128274; Runs entirely on your machine. No user data is stored remotely or sent to any MazAPI server. The only requests made are the security tests sent to the target you choose to scan.</div>
<div class="field"><label>Target URL</label><input id="target" value="${target}" placeholder="https://api.example.com"></div>
<div class="field"><label>Bearer Token (optional)</label><input id="token" placeholder="eyJhbGciOiJIUzI1NiIs…"></div>
<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
  <button id="btn-scan">&#9654; Run Full Scan</button>
  <button class="btn-sec" id="btn-sarif" disabled>&#8675; SARIF</button>
  <button class="btn-sec" id="btn-html" disabled>&#8675; HTML</button>
  <button class="btn-sec" id="btn-webhook" disabled>&#128276;</button>
</div>
<div id="status"></div>
<div id="results" style="margin-top:16px"></div>
<script>
const vscode = acquireVsCodeApi();
let _data = null;

document.getElementById('btn-scan').addEventListener('click', () => {
  const target = document.getElementById('target').value.trim();
  const token  = document.getElementById('token').value.trim();
  if (!target) { document.getElementById('status').textContent = 'Enter a target URL'; return; }
  vscode.postMessage({ type: 'runScan', target, token });
});

document.getElementById('btn-sarif').addEventListener('click', () => {
  if (_data) vscode.postMessage({ type: 'exportSARIF', data: _data });
});

document.getElementById('btn-html').addEventListener('click', () => {
  if (!_data) return;
  const html = buildHTMLReport(_data);
  vscode.postMessage({ type: 'exportHTML', html });
});

document.getElementById('btn-webhook').addEventListener('click', () => {
  // prompt() is blocked in VS Code webviews — URL comes from mazapi.webhookUrl setting
  if (_data) vscode.postMessage({ type: 'sendWebhook', data: _data });
});

window.addEventListener('message', e => {
  const msg = e.data;
  if (msg.type === 'requestHtml') {
    if (_data) vscode.postMessage({ type: 'exportHTML', html: buildHTMLReport(_data) });
    return;
  }
  const status  = document.getElementById('status');
  const results = document.getElementById('results');
  if (msg.type === 'scanStarted') {
    status.textContent = 'Scanning… (up to 120 seconds)';
    results.innerHTML  = '';
    document.getElementById('btn-scan').disabled = true;
    ['btn-sarif','btn-html','btn-webhook'].forEach(id => document.getElementById(id).disabled = true);
  }
  if (msg.type === 'scanError') {
    status.textContent = 'Error: ' + msg.message + ' — is the MazAPI backend running at localhost:9000?';
    document.getElementById('btn-scan').disabled = false;
  }
  if (msg.type === 'scanResult') {
    document.getElementById('btn-scan').disabled = false;
    ['btn-sarif','btn-html','btn-webhook'].forEach(id => document.getElementById(id).disabled = false);
    status.textContent = '';
    _data = msg.data;
    const d  = msg.data;
    const sc = d.score ?? 0;
    const color = sc >= 90 ? '#3fb950' : sc >= 70 ? '#e3b341' : '#f85149';
    let html = '<div class="score" style="color:'+color+'">'+sc+'%<span style="font-size:.4em;color:var(--vscode-descriptionForeground);margin-left:8px">Security Score</span></div>';
    html += '<p style="text-align:center;font-size:.82em;color:var(--vscode-descriptionForeground);margin-bottom:14px">'+(d.total_vulnerable||0)+' vulnerabilities / '+(d.total_tests||0)+' tests</p>';
    const REG_COLOR = { NEW: '#f85149', RECURRING: '#e3b341', FIXED: '#3fb950' };
    const SEV_COLOR = { CRITICAL: '#ff6b6b', HIGH: '#f85149', MEDIUM: '#e3b341', LOW: '#58a6ff' };
    for (const cat of (d.categories||[])) {
      const comp = cat.compliance;
      for (const t of (cat.tests||[])) {
        const sev   = SEV_COLOR[t.severity] || '#8b949e';
        const regBadge = t.regression ? \`<span class="reg-badge" style="color:\${REG_COLOR[t.regression]};border-color:\${REG_COLOR[t.regression]}">\${t.regression}</span>\` : '';
        const compHtml = comp ? \`<div class="compliance">
          <span class="comp-chip">PCI-DSS</span>\${(comp.pci_dss||[]).join(', ')} &nbsp;
          <span class="comp-chip">GDPR</span>\${(comp.gdpr||[]).join(', ')} &nbsp;
          <span class="comp-chip">ISO 27001</span>\${(comp.iso27001||[]).join(', ')}
        </div>\` : '';
        const evHtml = t.evidence ? \`<details><summary>Evidence</summary><pre>\${t.evidence.request.method} \${t.evidence.request.url}\${t.evidence.request.body?'\\nBody: '+t.evidence.request.body:''}\\n→ HTTP \${t.evidence.response.status}\${t.evidence.response.snippet?'\\n'+t.evidence.response.snippet:''}</pre></details>\` : '';
        const cls = t.vulnerable ? 'vuln' : 'safe';
        html += \`<div class="result \${cls}">
          <div class="result-title" style="color:\${t.vulnerable?sev:'#3fb950'}">\${t.vulnerable?'✗':'✓'} \${t.test}\${regBadge}</div>
          <div class="result-cat">\${cat.category} &nbsp;<span style="color:\${sev};font-size:.82em;font-weight:700">\${t.severity}</span></div>
          <div class="result-detail">\${t.actual}</div>
          \${compHtml}\${evHtml}
        </div>\`;
      }
    }
    results.innerHTML = html;
  }
});

function buildHTMLReport(d) {
  const sc = d.score ?? 0;
  const color = sc >= 90 ? '#3fb950' : sc >= 70 ? '#e3b341' : '#f85149';
  const SEV_COLOR = { CRITICAL: '#ff6b6b', HIGH: '#f85149', MEDIUM: '#e3b341', LOW: '#58a6ff' };
  let rows = '';
  for (const cat of (d.categories || [])) {
    const comp = cat.compliance;
    for (const t of (cat.tests || [])) {
      const sev = SEV_COLOR[t.severity] || '#8b949e';
      const compHtml = comp ? \`<div style="font-size:.77em;color:#8b949e;margin-top:6px"><b style="color:#58a6ff">Compliance:</b> PCI-DSS \${(comp.pci_dss||[]).join(', ')} | GDPR \${(comp.gdpr||[]).join(', ')} | ISO 27001 \${(comp.iso27001||[]).join(', ')}</div>\` : '';
      rows += \`<div style="border-left:3px solid \${t.vulnerable?sev:'#30363d'};padding:10px 14px;margin-bottom:8px;border-radius:0 6px 6px 0;background:\${t.vulnerable?'rgba(248,81,73,.04)':'rgba(63,185,80,.04)'}">
        <div style="display:flex;justify-content:space-between"><span style="font-weight:600;color:\${t.vulnerable?sev:'#3fb950'}">\${t.vulnerable?'✗':'✓'} \${t.test}</span><span style="font-size:.78em;color:\${sev};font-weight:700">\${t.severity}</span></div>
        <div style="font-size:.78em;color:#8b949e;margin-top:2px">\${cat.category}</div>
        <div style="font-size:.82em;margin-top:4px">\${t.actual}</div>
        \${compHtml}
      </div>\`;
    }
  }
  return '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>MazAPI Report</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:system-ui;background:#0d1117;color:#c9d1d9;padding:28px}</style></head><body>'
    + \`<div style="text-align:center;margin-bottom:24px"><h1 style="color:#58a6ff;font-size:1.8em">MazAPI Security Report</h1><p style="color:#8b949e">\${d.target} | \${new Date().toLocaleString()}</p></div>\`
    + \`<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px">\`
    + [['Score',sc+'%',color],['Vulnerable',(d.total_vulnerable||0),'#f85149'],['Secure',((d.total_tests||0)-(d.total_vulnerable||0)),'#3fb950'],['Tests',(d.total_tests||0),'#58a6ff']].map(([l,v,c]) =>
        \`<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;text-align:center"><div style="font-size:1.8em;font-weight:700;color:\${c}">\${v}</div><div style="font-size:.78em;color:#8b949e;margin-top:4px">\${l}</div></div>\`
      ).join('') + '</div>' + rows + '<div style="text-align:center;padding:16px;color:#8b949e;font-size:.78em;border-top:1px solid #21262d;margin-top:20px">MazAPI Scanner — CY384, UMaT Ghana</div></body></html>';
}
</script></body></html>`;
    }
}
