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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
/* ── Design tokens ── */
:root {
  --bg:     var(--vscode-editor-background);
  --sur:    var(--vscode-editorWidget-background, #161b22);
  --bdr:    var(--vscode-widget-border, #30363d);
  --txt:    var(--vscode-foreground);
  --txt2:   var(--vscode-descriptionForeground);
  --accent: var(--vscode-textLink-foreground, #58a6ff);
  --accdim: rgba(88,166,255,.12);
  --green:  #34d399;
  --red:    #f87171;
  --amber:  #fbbf24;
  --radius: 9px;
  --radius-sm: 5px;
  --shadow: 0 2px 10px rgba(0,0,0,.25);
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:'Inter',var(--vscode-font-family),sans-serif;
  background:var(--bg);color:var(--txt);
  padding:20px 22px;font-size:13px;
  line-height:1.5;
}
/* ── Header ── */
.maz-header{
  display:flex;align-items:center;justify-content:space-between;
  margin-bottom:18px;
}
.maz-brand{display:flex;align-items:center;gap:10px}
.maz-brand h1{font-size:1.15em;font-weight:800;color:var(--accent);letter-spacing:-.01em;margin:0}
.maz-brand .ver{
  font-size:.7em;font-weight:500;color:var(--txt2);
  background:var(--accdim);border:1px solid rgba(88,166,255,.25);
  border-radius:20px;padding:1px 8px;
}
/* Theme toggle */
.theme-btn{
  background:var(--sur);border:1px solid var(--bdr);color:var(--txt2);
  border-radius:20px;padding:4px 12px;cursor:pointer;font-size:.8em;
  font-family:inherit;display:flex;align-items:center;gap:5px;
  transition:all .18s ease;
}
.theme-btn:hover{border-color:var(--accent);color:var(--accent)}
/* Privacy note */
.privacy{
  background:rgba(52,211,153,.07);border:1px solid rgba(52,211,153,.2);
  border-radius:var(--radius-sm);padding:7px 11px;font-size:.78em;
  color:var(--green);margin-bottom:16px;display:flex;align-items:center;gap:6px;
}
/* ── Form ── */
.field{margin-bottom:11px}
.field label{display:block;font-size:.8em;color:var(--txt2);margin-bottom:4px;font-weight:500}
.field input{
  width:100%;background:var(--vscode-input-background);
  border:1px solid var(--vscode-input-border,var(--bdr));
  color:var(--vscode-input-foreground,var(--txt));
  padding:7px 10px;border-radius:var(--radius-sm);
  font-family:inherit;font-size:.9em;
  transition:border-color .15s,box-shadow .15s;
}
.field input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accdim)}
/* ── Action bar ── */
.action-bar{display:flex;align-items:center;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.btn-primary{
  background:linear-gradient(135deg,#0ea5e9,#6366f1);
  color:#fff;border:none;border-radius:var(--radius-sm);
  padding:9px 20px;cursor:pointer;font-size:.9em;font-weight:700;
  font-family:inherit;box-shadow:0 2px 10px rgba(14,165,233,.3);
  transition:opacity .15s,transform .15s;
}
.btn-primary:hover{opacity:.88;transform:translateY(-1px)}
.btn-primary:disabled{opacity:.4;cursor:not-allowed;transform:none}
.btn-sec{
  background:var(--accdim);color:var(--accent);
  border:1px solid rgba(88,166,255,.3);border-radius:var(--radius-sm);
  padding:7px 13px;cursor:pointer;font-size:.82em;font-weight:600;
  font-family:inherit;transition:all .15s;
}
.btn-sec:hover{background:var(--accent);color:#fff;border-color:var(--accent)}
.btn-sec:disabled{opacity:.38;cursor:not-allowed}
/* ── Status ── */
#status{font-size:.84em;color:var(--txt2);padding:6px 0}
.spinner{
  display:inline-block;width:12px;height:12px;
  border:2px solid var(--bdr);border-top-color:var(--accent);
  border-radius:50%;animation:spin .65s linear infinite;vertical-align:middle;margin-right:5px;
}
@keyframes spin{to{transform:rotate(360deg)}}
/* ── Stat cards ── */
.stat-grid{
  display:grid;grid-template-columns:repeat(4,1fr);
  gap:10px;margin-bottom:18px;
}
.stat-card{
  background:var(--sur);border:1px solid var(--bdr);
  border-radius:var(--radius);padding:12px 10px;text-align:center;
  box-shadow:var(--shadow);transition:border-color .15s;
}
.stat-card:hover{border-color:var(--accent)}
.stat-num{font-size:1.6em;font-weight:800;line-height:1}
.stat-lbl{font-size:.7em;color:var(--txt2);margin-top:4px;font-weight:500}
/* ── Score ring ── */
.score-wrap{text-align:center;padding:8px 0 14px}
.score-val{font-size:2.4em;font-weight:800}
.score-sub{font-size:.8em;color:var(--txt2);margin-top:3px}
/* ── Result cards ── */
.result{
  border-left:3px solid var(--bdr);padding:11px 14px;
  margin-bottom:7px;border-radius:0 var(--radius) var(--radius) 0;
  background:var(--sur);box-shadow:var(--shadow);
  transition:box-shadow .15s;
}
.result:hover{box-shadow:0 4px 18px rgba(0,0,0,.3)}
.result.vuln{border-color:var(--red);background:rgba(248,113,113,.06)}
.result.safe{border-color:var(--green);background:rgba(52,211,153,.05)}
.res-hdr{display:flex;justify-content:space-between;align-items:flex-start;gap:6px;margin-bottom:4px}
.res-title{font-weight:700;font-size:.9em;flex:1}
.result.vuln .res-title{color:var(--red)}
.result.safe .res-title{color:var(--green)}
.sev-pill{
  font-size:.68em;font-weight:800;padding:2px 8px;border-radius:20px;
  white-space:nowrap;margin-top:1px;
}
.sev-CRITICAL{background:rgba(239,68,68,.18);color:#ef4444}
.sev-HIGH    {background:rgba(248,113,113,.18);color:var(--red)}
.sev-MEDIUM  {background:rgba(251,191,36,.15);color:var(--amber)}
.sev-LOW     {background:rgba(88,166,255,.15);color:var(--accent)}
.res-cat{font-size:.76em;color:var(--txt2);margin-bottom:3px}
.res-detail{font-size:.82em;margin-bottom:6px;color:var(--txt)}
.compliance{font-size:.73em;color:var(--txt2);line-height:1.8;margin-top:4px}
.comp-chip{
  background:var(--accdim);color:var(--accent);
  border:1px solid rgba(88,166,255,.28);
  border-radius:3px;padding:1px 5px;margin-right:3px;font-weight:600;font-size:.92em;
}
.reg-badge{
  display:inline-block;border:1px solid;border-radius:4px;
  padding:1px 6px;font-size:.7em;font-weight:700;margin-left:5px;vertical-align:middle;
}
details summary{font-size:.77em;color:var(--accent);cursor:pointer;margin-top:5px}
details pre{
  background:rgba(0,0,0,.18);border:1px solid var(--bdr);border-radius:var(--radius-sm);
  padding:7px;font-size:.72em;white-space:pre-wrap;margin-top:5px;
  word-break:break-all;color:var(--txt);font-family:'SF Mono',Consolas,monospace;
}
</style></head><body>
<!-- Header -->
<div class="maz-header">
  <div class="maz-brand">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width="34" height="34" style="flex-shrink:0;border-radius:8px">
      <defs>
        <linearGradient id="ppr" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#00d4ff"/><stop offset="100%" stop-color="#7c3aed"/></linearGradient>
        <filter id="pgl"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
      </defs>
      <polygon points="100,24 161,59 161,129 100,164 39,129 39,59" fill="url(#ppr)" fill-opacity="0.14"/>
      <polygon points="100,24 161,59 161,129 100,164 39,129 39,59" fill="none" stroke="url(#ppr)" stroke-width="2.5" filter="url(#pgl)"/>
      <circle cx="68"  cy="65"  r="5.5" fill="#00d4ff" opacity="0.9"/>
      <circle cx="100" cy="96"  r="5.5" fill="#00d4ff" opacity="0.8"/>
      <circle cx="132" cy="65"  r="5.5" fill="#00d4ff" opacity="0.9"/>
      <path d="M68,120 L68,65 L100,96 L132,65 L132,120" fill="none" stroke="url(#ppr)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <h1>MazAPI Scanner</h1>
    <span class="ver">v2.2</span>
  </div>
  <button class="theme-btn" id="btn-theme">☀️ <span id="theme-label">Light</span></button>
</div>

<div class="privacy">🔒 Runs entirely on your machine. No telemetry. Only outbound traffic is the security tests you run.</div>

<div class="field"><label>Target URL</label><input id="target" value="${target}" placeholder="https://api.example.com"></div>
<div class="field"><label>Bearer Token (optional)</label><input id="token" type="password" placeholder="eyJhbGciOiJIUzI1NiIs…"></div>

<div class="action-bar">
  <button class="btn-primary" id="btn-scan">▶ Run Full Scan</button>
  <button class="btn-sec" id="btn-sarif" disabled>↓ SARIF</button>
  <button class="btn-sec" id="btn-html"  disabled>↓ HTML</button>
  <button class="btn-sec" id="btn-webhook" disabled>🔔 Alert</button>
</div>
<div id="status"></div>
<div id="results" style="margin-top:14px"></div>

<script>
const vscode = acquireVsCodeApi();
let _data = null;
let _theme = 'dark';

// ── Theme toggle ─────────────────────────────────────────────────────
function applyTheme(t) {
  _theme = t;
  document.body.style.setProperty('--sur',    t==='light'?'#f0f4fa':'var(--vscode-editorWidget-background,#161b22)');
  document.body.style.setProperty('--bdr',    t==='light'?'#c8d5e6':'var(--vscode-widget-border,#30363d)');
  document.body.style.setProperty('--accdim', t==='light'?'rgba(2,132,199,.10)':'rgba(88,166,255,.12)');
  document.getElementById('btn-theme').innerHTML = t==='light'?'🌙 Dark':'☀️ Light';
}
document.getElementById('btn-theme').addEventListener('click',()=>{
  applyTheme(_theme==='dark'?'light':'dark');
});

// ── Scan actions ─────────────────────────────────────────────────────
document.getElementById('btn-scan').addEventListener('click',()=>{
  const target=document.getElementById('target').value.trim();
  const token =document.getElementById('token').value.trim();
  if(!target){document.getElementById('status').textContent='Enter a target URL';return;}
  vscode.postMessage({type:'runScan',target,token});
});
document.getElementById('btn-sarif').addEventListener('click',()=>{if(_data)vscode.postMessage({type:'exportSARIF',data:_data});});
document.getElementById('btn-html').addEventListener('click',()=>{if(!_data)return;vscode.postMessage({type:'exportHTML',html:buildHTMLReport(_data)});});
document.getElementById('btn-webhook').addEventListener('click',()=>{if(_data)vscode.postMessage({type:'sendWebhook',data:_data});});

window.addEventListener('message',e=>{
  const msg=e.data;
  if(msg.type==='requestHtml'){if(_data)vscode.postMessage({type:'exportHTML',html:buildHTMLReport(_data)});return;}
  const status=document.getElementById('status');
  const results=document.getElementById('results');
  if(msg.type==='scanStarted'){
    status.innerHTML='<span class="spinner"></span>Scanning… (up to 120 s)';
    results.innerHTML='';
    document.getElementById('btn-scan').disabled=true;
    ['btn-sarif','btn-html','btn-webhook'].forEach(id=>document.getElementById(id).disabled=true);
  }
  if(msg.type==='scanError'){
    status.textContent='⚠ '+msg.message+' — is the MazAPI backend running at localhost:9000?';
    document.getElementById('btn-scan').disabled=false;
  }
  if(msg.type==='scanResult'){
    document.getElementById('btn-scan').disabled=false;
    ['btn-sarif','btn-html','btn-webhook'].forEach(id=>document.getElementById(id).disabled=false);
    status.textContent='';
    _data=msg.data;
    const d=msg.data;
    const sc=d.score??0;
    const sc_color=sc>=90?'#34d399':sc>=70?'#fbbf24':'#f87171';
    const vuln=d.total_vulnerable||0;const total=d.total_tests||0;
    const safe=total-vuln;
    let html=\`<div class="score-wrap">
      <div class="score-val" style="color:\${sc_color}">\${sc}%</div>
      <div class="score-sub">Security Score</div>
    </div>
    <div class="stat-grid">
      <div class="stat-card"><div class="stat-num" style="color:#f87171">\${vuln}</div><div class="stat-lbl">Vulnerable</div></div>
      <div class="stat-card"><div class="stat-num" style="color:#34d399">\${safe}</div><div class="stat-lbl">Secure</div></div>
      <div class="stat-card"><div class="stat-num" style="color:var(--accent)">\${total}</div><div class="stat-lbl">Total Tests</div></div>
      <div class="stat-card"><div class="stat-num" style="color:\${sc_color}">\${sc}%</div><div class="stat-lbl">Score</div></div>
    </div>\`;
    const REG_COLOR={NEW:'#f87171',RECURRING:'#fbbf24',FIXED:'#34d399'};
    for(const cat of(d.categories||[])){
      const comp=cat.compliance;
      for(const t of(cat.tests||[])){
        const sev=t.severity||'';
        const regBadge=t.regression?\`<span class="reg-badge" style="color:\${REG_COLOR[t.regression]};border-color:\${REG_COLOR[t.regression]}">\${t.regression}</span>\`:'';
        const compHtml=comp?\`<div class="compliance">
          <span class="comp-chip">PCI-DSS</span>\${(comp.pci_dss||[]).join(', ')}&nbsp;
          <span class="comp-chip">GDPR</span>\${(comp.gdpr||[]).join(', ')}&nbsp;
          <span class="comp-chip">ISO 27001</span>\${(comp.iso27001||[]).join(', ')}
        </div>\`:'';
        const evHtml=t.evidence?\`<details><summary>Evidence</summary><pre>\${t.evidence.request.method} \${t.evidence.request.url}\${t.evidence.request.body?'\\nBody: '+t.evidence.request.body:''}\\n→ HTTP \${t.evidence.response.status}\${t.evidence.response.snippet?'\\n'+t.evidence.response.snippet:''}</pre></details>\`:'';
        const cls=t.vulnerable?'vuln':'safe';
        html+=\`<div class="result \${cls}">
          <div class="res-hdr">
            <div class="res-title">\${t.vulnerable?'✗':'✓'} \${t.test}\${regBadge}</div>
            <span class="sev-pill sev-\${sev}">\${sev}</span>
          </div>
          <div class="res-cat">\${cat.category}</div>
          <div class="res-detail">\${t.actual}</div>
          \${compHtml}\${evHtml}
        </div>\`;
      }
    }
    results.innerHTML=html;
  }
});

function buildHTMLReport(d){
  const sc=d.score??0;
  const sc_color=sc>=90?'#34d399':sc>=70?'#fbbf24':'#f87171';
  let rows='';
  for(const cat of(d.categories||[])){
    const comp=cat.compliance;
    for(const t of(cat.tests||[])){
      const sev=t.severity||'';
      const compHtml=comp?\`<div style="font-size:.77em;color:#8b949e;margin-top:6px"><b style="color:#58a6ff">Compliance:</b> PCI-DSS \${(comp.pci_dss||[]).join(', ')} | GDPR \${(comp.gdpr||[]).join(', ')} | ISO 27001 \${(comp.iso27001||[]).join(', ')}</div>\`:'';
      const sevColor=sev==='CRITICAL'?'#ef4444':sev==='HIGH'?'#f87171':sev==='MEDIUM'?'#fbbf24':'#58a6ff';
      rows+=\`<div style="border-left:3px solid \${t.vulnerable?sevColor:'#30363d'};padding:11px 15px;margin-bottom:8px;border-radius:0 8px 8px 0;background:\${t.vulnerable?'rgba(248,113,113,.05)':'rgba(52,211,153,.04)'}">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px">
          <span style="font-weight:700;color:\${t.vulnerable?sevColor:'#34d399'}">\${t.vulnerable?'✗':'✓'} \${t.test}</span>
          <span style="font-size:.72em;font-weight:800;padding:2px 9px;border-radius:20px;background:rgba(88,166,255,.12);color:\${sevColor}">\${sev}</span>
        </div>
        <div style="font-size:.78em;color:#8b949e;margin-bottom:3px">\${cat.category}</div>
        <div style="font-size:.83em">\${t.actual}</div>
        \${compHtml}
      </div>\`;
    }
  }
  return \`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>MazAPI Report — \${d.target||''}</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Inter',system-ui;background:#0d1117;color:#c9d1d9;padding:30px 32px}h1{color:#58a6ff;font-size:1.7em;font-weight:800;margin-bottom:6px}.sub{color:#8b949e;font-size:.88em;margin-bottom:22px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px;text-align:center}.card-n{font-size:1.9em;font-weight:800;line-height:1}.card-l{font-size:.73em;color:#8b949e;margin-top:5px}.footer{text-align:center;padding:18px;color:#8b949e;font-size:.76em;border-top:1px solid #21262d;margin-top:22px}</style>
  </head><body>
  <h1>MazAPI Security Report</h1>
  <div class="sub">\${d.target||''} &nbsp;·&nbsp; \${new Date().toLocaleString()}</div>
  <div class="grid">
    <div class="card"><div class="card-n" style="color:\${sc_color}">\${sc}%</div><div class="card-l">Score</div></div>
    <div class="card"><div class="card-n" style="color:#f87171">\${d.total_vulnerable||0}</div><div class="card-l">Vulnerable</div></div>
    <div class="card"><div class="card-n" style="color:#34d399">\${(d.total_tests||0)-(d.total_vulnerable||0)}</div><div class="card-l">Secure</div></div>
    <div class="card"><div class="card-n" style="color:#58a6ff">\${d.total_tests||0}</div><div class="card-l">Tests</div></div>
  </div>
  \${rows}
  <div class="footer">MazAPI Scanner v2.2 — CY384, UMaT Ghana &nbsp;·&nbsp; Runs locally, no remote telemetry</div>
  </body></html>\`;
}
</script></body></html>`;
}
}
