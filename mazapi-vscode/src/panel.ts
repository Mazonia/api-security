import * as vscode from 'vscode';

export class MazAPIPanel {
    public static currentPanel: MazAPIPanel | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private _target: string;

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
        MazAPIPanel.currentPanel = new MazAPIPanel(panel, target);
    }

    private constructor(panel: vscode.WebviewPanel, target: string) {
        this._panel = panel;
        this._target = target;
        this._update(target);
        this._panel.onDidDispose(() => { MazAPIPanel.currentPanel = undefined; });
        this._panel.webview.onDidReceiveMessage(async (msg) => {
            if (msg.type === 'runScan') {
                await this._runScan(msg.target, msg.token);
            }
        });
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
                signal: AbortSignal.timeout(90000),
            });
            const data = await resp.json();
            this._panel.webview.postMessage({ type: 'scanResult', data });
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            this._panel.webview.postMessage({ type: 'scanError', message: msg });
        }
    }

    private _update(target: string) {
        this._panel.title = 'MazAPI Scanner';
        this._panel.webview.html = this._getHtml(target);
    }

    private _getHtml(target: string): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
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
#status{margin-top:10px;font-size:.85em;color:var(--vscode-descriptionForeground)}
.result{border-left:3px solid;padding:8px 12px;margin-bottom:6px;border-radius:0 4px 4px 0}
.result.vuln{border-color:#f85149;background:rgba(248,81,73,.08)}
.result.safe{border-color:#3fb950;background:rgba(63,185,80,.08)}
.result-title{font-weight:600;font-size:.9em}
.result-cat{font-size:.78em;color:var(--vscode-descriptionForeground);margin-top:2px}
.score{font-size:1.8em;font-weight:700;text-align:center;padding:10px 0}
</style>
</head>
<body>
<h1>&#128737; MazAPI Scanner</h1>
<div class="field">
  <label>Target URL</label>
  <input id="target" value="${target}" placeholder="https://api.example.com">
</div>
<div class="field">
  <label>Bearer Token (optional)</label>
  <input id="token" placeholder="eyJhbGciOiJIUzI1NiIs…">
</div>
<button id="btn-scan">&#9654; Run Full Scan</button>
<div id="status"></div>
<div id="results" style="margin-top:16px"></div>

<script>
const vscode = acquireVsCodeApi();
document.getElementById('btn-scan').addEventListener('click', () => {
  const target = document.getElementById('target').value.trim();
  const token  = document.getElementById('token').value.trim();
  if (!target) { document.getElementById('status').textContent = 'Enter a target URL'; return; }
  vscode.postMessage({ type: 'runScan', target, token });
});
window.addEventListener('message', e => {
  const msg = e.data;
  const status  = document.getElementById('status');
  const results = document.getElementById('results');
  if (msg.type === 'scanStarted') {
    status.textContent  = 'Scanning… (up to 60 seconds)';
    results.innerHTML   = '';
    document.getElementById('btn-scan').disabled = true;
  }
  if (msg.type === 'scanError') {
    status.textContent = 'Error: ' + msg.message + ' — is the MazAPI backend running at localhost:9000?';
    document.getElementById('btn-scan').disabled = false;
  }
  if (msg.type === 'scanResult') {
    document.getElementById('btn-scan').disabled = false;
    status.textContent = '';
    const d = msg.data;
    const sc = d.score ?? 0;
    const color = sc === 100 ? '#3fb950' : sc >= 70 ? '#e3b341' : '#f85149';
    let html = '<div class="score" style="color:'+color+'">'+sc+'%</div>';
    html += '<p style="text-align:center;font-size:.82em;color:var(--vscode-descriptionForeground);margin-bottom:14px">'
          + (d.total_vulnerable||0) + ' vulnerabilities / ' + (d.total_tests||0) + ' tests</p>';
    for (const cat of (d.categories||[])) {
      for (const t of (cat.tests||[])) {
        const cls = t.vulnerable ? 'vuln' : 'safe';
        html += '<div class="result '+cls+'"><div class="result-title">'+(t.vulnerable?'✗':'✓')+' '+t.test+'</div>'
              + '<div class="result-cat">'+cat.category+'</div>'
              + '<div class="result-cat">'+t.actual+'</div></div>';
      }
    }
    results.innerHTML = html;
  }
});
</script>
</body>
</html>`;
    }
}
