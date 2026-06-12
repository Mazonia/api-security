import * as vscode from 'vscode';
import { execFile } from 'child_process';
import * as path from 'path';
import { scanFileForIssues, ScanFinding } from './scanner';
import { MazAPIPanel } from './panel';
import {
    EndpointsProvider, FindingsProvider, ChainsProvider, correlateChains,
    FindingsFilter, DEFAULT_FILTER, isDefaultFilter,
} from './treeview';

// Is this .env file actually committed/tracked by git? A tracked .env with secrets is a
// real exposure; a gitignored one is the correct home for them. `git ls-files --error-unmatch`
// exits 0 only when the path is tracked. Non-.env files never need this (returns false fast).
function isEnvTrackedByGit(uri: vscode.Uri): Promise<boolean> {
    const fsPath = uri.fsPath;
    if (!/(?:^|[\\/])\.env(?:\.[a-z]+)?$/i.test(fsPath)) return Promise.resolve(false);
    const folder = vscode.workspace.getWorkspaceFolder(uri);
    const cwd = folder ? folder.uri.fsPath : path.dirname(fsPath);
    return new Promise((resolve) => {
        execFile('git', ['ls-files', '--error-unmatch', fsPath], { cwd }, (err) => {
            resolve(!err); // exit 0 (no err) ⇒ tracked ⇒ committed
        });
    });
}

let findingsProvider: FindingsProvider;
let endpointsProvider: EndpointsProvider;
let chainsProvider: ChainsProvider;
let diagnosticCollection: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;
let extensionUri: vscode.Uri;

// Debounce map: uri string → timeout handle
const changeTimers = new Map<string, ReturnType<typeof setTimeout>>();

// Languages scanned by auto-scan
const SCAN_LANGS = new Set([
    'javascript','javascriptreact','typescript','typescriptreact',
    'python','json','yaml','plaintext','env','dotenv',
    'php','ruby','go','java','kotlin','swift','rust','csharp',
    'shellscript','toml','ini','properties',
]);

function isScannable(doc: vscode.TextDocument): boolean {
    return SCAN_LANGS.has(doc.languageId) || /\.(env|cfg|ini|toml|properties)$/i.test(doc.fileName);
}

// ── CodeLens provider — "▶ Scan with MazAPI" above any API URL line ──────────

class MazAPICodeLensProvider implements vscode.CodeLensProvider {
    private _onDidChange = new vscode.EventEmitter<void>();
    readonly onDidChangeCodeLenses = this._onDidChange.event;

    /** Called after a scan so finding-based lenses refresh without an edit. */
    refresh() { this._onDidChange.fire(); }

    // Matches any http(s) URL that looks like an API endpoint
    private static readonly URL_RE = /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|[a-z0-9][a-z0-9-]*\.[a-z]{2,})(?::\d+)?(?:\/[^\s"'`)\]]*)?/gi;

    private static readonly SEV_ICON: Record<string, string> = {
        CRITICAL: '$(error)', HIGH: '$(error)', MEDIUM: '$(warning)', LOW: '$(info)',
    };

    provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
        const lenses: vscode.CodeLens[] = [];

        // ── Quick-Fix lenses: one above each finding line that has a fix ──────────
        const fixSeen = new Set<number>();
        for (const f of findingsProvider.getRawFindings(document.uri)) {
            if (!f.fix || !f.range || f.kind === 'endpoint') continue;
            const line = f.range.start.line;
            if (fixSeen.has(line)) continue;
            fixSeen.add(line);
            const icon = MazAPICodeLensProvider.SEV_ICON[f.severity] ?? '$(warning)';
            lenses.push(new vscode.CodeLens(
                new vscode.Range(line, 0, line, 0),
                {
                    title:     `${icon} MazAPI: ${f.severity} ${f.label ?? 'finding'} — Quick Fix`,
                    command:   'mazapi.showFix',
                    arguments: [document.uri, f.range, f.label ?? f.message, f.fix, f.category],
                    tooltip:   f.fix,
                }
            ));
        }

        // ── URL lenses: inline "Scan with MazAPI" above every URL line ────────────
        const text = document.getText();
        const re = new RegExp(MazAPICodeLensProvider.URL_RE.source, 'gi');
        const seen = new Set<number>();
        let m: RegExpExecArray | null;
        while ((m = re.exec(text)) !== null) {
            const pos = document.positionAt(m.index);
            if (seen.has(pos.line)) continue;
            const lineText = document.lineAt(pos.line).text;
            // Skip comment-only lines
            if (/^\s*(?:#|\/\/)/.test(lineText)) continue;
            seen.add(pos.line);
            const url = m[0].replace(/["'`]/g, '').replace(/[)>\].,;]+$/, '');
            lenses.push(new vscode.CodeLens(
                new vscode.Range(pos.line, 0, pos.line, 0),
                {
                    title:     '$(shield) Scan with MazAPI',
                    command:   'mazapi.openPanel',
                    arguments: [url],
                    tooltip:   `Test ${url} for API security issues`,
                }
            ));
        }
        return lenses;
    }
}

let codeLensProvider: MazAPICodeLensProvider;

export function activate(context: vscode.ExtensionContext) {
    extensionUri = context.extensionUri;
    diagnosticCollection = vscode.languages.createDiagnosticCollection('mazapi');
    context.subscriptions.push(diagnosticCollection);

    findingsProvider  = new FindingsProvider();
    endpointsProvider = new EndpointsProvider();
    chainsProvider    = new ChainsProvider();
    vscode.window.registerTreeDataProvider('mazapi.findings',  findingsProvider);
    vscode.window.registerTreeDataProvider('mazapi.endpoints', endpointsProvider);
    vscode.window.registerTreeDataProvider('mazapi.chains',    chainsProvider);

    // ── CodeLens: Quick-Fix above findings + "Scan with MazAPI" above URLs ────
    codeLensProvider = new MazAPICodeLensProvider();
    context.subscriptions.push(
        vscode.languages.registerCodeLensProvider(
            [
                { language: 'javascript' }, { language: 'javascriptreact' },
                { language: 'typescript' }, { language: 'typescriptreact' },
                { language: 'python' },     { language: 'json' },
                { language: 'yaml' },       { language: 'plaintext' },
            ],
            codeLensProvider
        )
    );

    // ── Command: Scan current file ────────────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('mazapi.scanFile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('MazAPI: No file open.');
                return;
            }
            await runFileScan(editor.document);
        })
    );

    // ── Command: Scan workspace ───────────────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('mazapi.scanWorkspace', async () => {
            const files = await vscode.workspace.findFiles(
                '**/*.{js,ts,py,env,json,yml,yaml,cfg,ini,toml}',
                '**/{node_modules,.git,__pycache__,dist,build,out}/**'
            );
            vscode.window.withProgress(
                { location: vscode.ProgressLocation.Notification, title: 'MazAPI: Scanning workspace…', cancellable: false },
                async (progress) => {
                    const allFindings: ScanFinding[] = [];
                    for (let i = 0; i < files.length; i++) {
                        progress.report({ increment: (i / files.length) * 100 });
                        const doc = await vscode.workspace.openTextDocument(files[i]);
                        const envCommitted = await isEnvTrackedByGit(doc.uri);
                        const findings = scanFileForIssues(doc.getText(), doc.languageId, doc.uri, envCommitted);
                        allFindings.push(...findings);
                        applyDiagnostics(doc.uri, findings);
                    }
                    findingsProvider.refresh(allFindings.filter(f => f.kind !== 'endpoint'));
                    endpointsProvider.refresh(allFindings.filter(f => f.kind === 'endpoint'));
                    recomputeChains();
                    updateStatusBar(findingsProvider.getTotalIssueCount());
                    const chains = chainsProvider.getChainCount();
                    vscode.window.showInformationMessage(
                        `MazAPI: ${findingsProvider.getTotalIssueCount()} issue(s) · ${allFindings.filter(f => f.kind === 'endpoint').length} endpoint(s)` +
                        (chains ? ` · ${chains} attack chain(s)` : '') + ` across ${files.length} files.`
                    );
                }
            );
        })
    );

    // ── Command: Scan selected endpoint ──────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('mazapi.scanEndpoint', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) return;
            const selection = editor.selection;
            const text = editor.document.getText(selection).trim() ||
                         editor.document.getText(editor.document.lineAt(selection.active.line).range).trim();

            const urlMatch = text.match(/https?:\/\/[^\s"'`]+/);
            if (!urlMatch) {
                vscode.window.showWarningMessage('MazAPI: No URL found on this line. Select or place cursor on a URL.');
                return;
            }
            const url = urlMatch[0].replace(/["'`].*$/, '');
            MazAPIPanel.createOrShow(context.extensionUri, url);
        })
    );

    // ── Command: Open panel — accepts optional URL to pre-fill target ─────────
    context.subscriptions.push(
        vscode.commands.registerCommand('mazapi.openPanel', (url?: string) => {
            MazAPIPanel.createOrShow(context.extensionUri, url || '');
        })
    );

    // ── Auto-scan: on open ────────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(async (doc) => {
            if (!isAutoScanEnabled() || !isScannable(doc)) return;
            await runFileScan(doc, true);
        })
    );

    // ── Auto-scan: debounced on change (600 ms) ───────────────────────────────
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument((event) => {
            if (!isAutoScanEnabled() || !isScannable(event.document)) return;
            if (!event.contentChanges.length) return;
            const key = event.document.uri.toString();
            const existing = changeTimers.get(key);
            if (existing) clearTimeout(existing);
            changeTimers.set(key, setTimeout(async () => {
                changeTimers.delete(key);
                await runFileScan(event.document, true);
            }, 600));
        })
    );

    // ── Auto-scan: on save ────────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (doc) => {
            if (!isAutoScanEnabled() || !isScannable(doc)) return;
            const key = doc.uri.toString();
            const t = changeTimers.get(key);
            if (t) { clearTimeout(t); changeTimers.delete(key); }
            await runFileScan(doc, true);
        })
    );

    // ── Auto-scan: clean up findings when a file is closed ───────────────────
    context.subscriptions.push(
        vscode.workspace.onDidCloseTextDocument((doc) => {
            diagnosticCollection.delete(doc.uri);
            findingsProvider.updateFile(doc.uri, []);
            endpointsProvider.updateFile(doc.uri, []);
            recomputeChains();
            updateStatusBar(findingsProvider.getTotalIssueCount());
        })
    );

    // ── Auto-scan: scan active editor immediately on activation ───────────────
    if (isAutoScanEnabled()) {
        const active = vscode.window.activeTextEditor?.document;
        if (active && isScannable(active)) {
            setTimeout(() => runFileScan(active, true), 400);
        }
    }

    // ── Command: Export SARIF from last panel scan ────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('mazapi.exportSARIF', () => {
            if (MazAPIPanel.currentPanel) {
                MazAPIPanel.currentPanel.postToWebview({ type: 'triggerExport', format: 'sarif' });
            } else {
                vscode.window.showWarningMessage('MazAPI: No scan results — run a scan first.');
            }
        })
    );

    // ── Command: Export HTML report from last panel scan ──────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('mazapi.exportHTML', () => {
            if (MazAPIPanel.currentPanel) {
                MazAPIPanel.currentPanel.postToWebview({ type: 'triggerExport', format: 'html' });
            } else {
                vscode.window.showWarningMessage('MazAPI: No scan results — run a scan first.');
            }
        })
    );

    // ── Command: Configure webhook ────────────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('mazapi.configureWebhook', async () => {
            const url = await vscode.window.showInputBox({
                prompt: 'Enter Slack/Teams webhook URL',
                placeHolder: 'https://hooks.slack.com/services/…',
                value: vscode.workspace.getConfiguration('mazapi').get<string>('webhookUrl') || '',
            });
            if (url !== undefined) {
                await vscode.workspace.getConfiguration('mazapi').update('webhookUrl', url, vscode.ConfigurationTarget.Global);
                vscode.window.showInformationMessage('MazAPI: Webhook URL saved.');
            }
        })
    );

    // ── Command: Configure findings filter ───────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('mazapi.filter.configure', async () => {
            const cur = findingsProvider.getFilter();

            // ── Step 1: choose which finding kinds to show ────────────────────
            const kindItems: (vscode.QuickPickItem & { key: keyof FindingsFilter })[] = [
                { label: '$(key) API Keys & Hardcoded Secrets',   key: 'showKeys',      picked: cur.showKeys },
                { label: '$(shield) Weak Auth & Crypto Issues',   key: 'showWeakAuth',  picked: cur.showWeakAuth },
                { label: '$(person) PII Patterns',                key: 'showPII',       picked: cur.showPII },
                { label: '$(globe) Hardcoded External URLs',      key: 'showUrls',      picked: cur.showUrls },
                { label: '$(link) Detected API Endpoints',        key: 'showEndpoints', picked: cur.showEndpoints,
                  description: 'informational — these are not vulnerabilities' },
            ];

            const picked = await vscode.window.showQuickPick(kindItems, {
                title:       'MazAPI Findings Filter — which types to show?',
                placeHolder: 'Select finding types to show (uncheck to hide)',
                canPickMany: true,
            });
            if (!picked) return; // cancelled

            // ── Step 2: choose minimum severity ──────────────────────────────
            const sevItems: (vscode.QuickPickItem & { value: FindingsFilter['minSeverity'] })[] = [
                { label: 'All findings (LOW and above)',  value: 'LOW',      description: cur.minSeverity === 'LOW'      ? '← active' : '' },
                { label: 'MEDIUM and above',              value: 'MEDIUM',   description: cur.minSeverity === 'MEDIUM'   ? '← active' : '' },
                { label: 'HIGH and above',                value: 'HIGH',     description: cur.minSeverity === 'HIGH'     ? '← active' : '' },
                { label: 'CRITICAL only',                 value: 'CRITICAL', description: cur.minSeverity === 'CRITICAL' ? '← active' : '' },
            ];

            const sevPick = await vscode.window.showQuickPick(sevItems, {
                title:       'MazAPI Findings Filter — minimum severity to show?',
                placeHolder: 'Only findings at or above this severity will appear',
            });
            if (!sevPick) return; // cancelled

            // Build new filter from selections
            const selectedKeys = new Set(picked.map(p => p.key));
            const next: FindingsFilter = {
                showKeys:      selectedKeys.has('showKeys'),
                showWeakAuth:  selectedKeys.has('showWeakAuth'),
                showPII:       selectedKeys.has('showPII'),
                showUrls:      selectedKeys.has('showUrls'),
                showEndpoints: selectedKeys.has('showEndpoints'),
                minSeverity:   sevPick.value,
            };

            applyFilter(next);
        })
    );

    // ── Command: Reset findings filter ────────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('mazapi.filter.reset', () => {
            applyFilter({ ...DEFAULT_FILTER });
            vscode.window.showInformationMessage('MazAPI: Filter reset — showing all findings.');
        })
    );

    // ── Command: Show Quick Fix for a finding (diff-style preview) ────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('mazapi.showFix',
            async (uri: vscode.Uri, range: vscode.Range, label: string, fix: string, category: string) => {
                const md = new vscode.MarkdownString(undefined, true);
                md.isTrusted = true;
                md.appendMarkdown(`### $(lightbulb) ${label}\n\n`);
                md.appendMarkdown(`**${category}**\n\n`);
                md.appendMarkdown(`${fix}\n`);
                const choice = await vscode.window.showInformationMessage(
                    `MazAPI fix — ${label}: ${fix}`,
                    { modal: false },
                    'Go to code', 'Insert fix comment',
                );
                if (choice === 'Go to code') {
                    await vscode.window.showTextDocument(uri, { selection: range });
                } else if (choice === 'Insert fix comment') {
                    // Non-destructive: drop a TODO-style comment with the remediation above the line
                    const doc = await vscode.workspace.openTextDocument(uri);
                    const indent = (doc.lineAt(range.start.line).text.match(/^\s*/) ?? [''])[0];
                    const cmt = commentPrefix(doc.languageId);
                    const edit = new vscode.WorkspaceEdit();
                    edit.insert(uri, new vscode.Position(range.start.line, 0),
                        `${indent}${cmt} MazAPI fix: ${fix}\n`);
                    await vscode.workspace.applyEdit(edit);
                    await vscode.window.showTextDocument(uri, { selection: range });
                }
            })
    );

    // ── Command: Open the Security Dashboard webview ──────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('mazapi.openDashboard', () => {
            DashboardPanel.show(findingsProvider.getAllFindings(), chainsProvider.getChainCount());
        })
    );

    // ── Status bar — shows live letter grade, click to open dashboard ─────────
    statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    updateStatusBar(0);
    statusBar.show();
    context.subscriptions.push(statusBar);
}

// Comment prefix per language for the "insert fix comment" action
function commentPrefix(langId: string): string {
    switch (langId) {
        case 'python': case 'ruby': case 'shellscript': case 'yaml': case 'dockerfile':
        case 'properties': case 'ini': case 'toml': return '#';
        default: return '//';
    }
}

// ── Letter grade from the severity mix of currently-visible findings ───────────
function computeGrade(findings: ScanFinding[]): { grade: string; color: string } {
    const real = findings.filter(f => f.kind !== 'endpoint');
    const crit = real.filter(f => f.severity === 'CRITICAL').length;
    const high = real.filter(f => f.severity === 'HIGH').length;
    const med  = real.filter(f => f.severity === 'MEDIUM').length;
    // Weighted penalty — criticals dominate, then highs, then mediums
    const penalty = crit * 40 + high * 12 + med * 3;
    let grade: string, color: string;
    if (crit > 0 || penalty >= 60)      { grade = 'F'; color = 'statusBarItem.errorBackground'; }
    else if (penalty >= 30)             { grade = 'D'; color = 'statusBarItem.warningBackground'; }
    else if (penalty >= 12)             { grade = 'C'; color = 'statusBarItem.warningBackground'; }
    else if (penalty >= 4)              { grade = 'B'; color = ''; }
    else if (penalty > 0)               { grade = 'A'; color = ''; }
    else                                { grade = 'A+'; color = ''; }
    return { grade, color };
}

function recomputeChains() {
    const all = findingsProvider.getAllFindings();
    chainsProvider.setChains(correlateChains(all));
    codeLensProvider?.refresh();
}

function applyFilter(f: FindingsFilter) {
    findingsProvider.setFilter(f);
    const active = !isDefaultFilter(f);
    vscode.commands.executeCommand('setContext', 'mazapi.filterActive', active);
    updateStatusBar(findingsProvider.getTotalIssueCount());
}

function isAutoScanEnabled(): boolean {
    const cfg = vscode.workspace.getConfiguration('mazapi');
    // autoScan is the new setting; fall back to legacy autoScanOnSave
    return cfg.get<boolean>('autoScan') ?? cfg.get<boolean>('autoScanOnSave') ?? true;
}

function updateStatusBar(issueCount: number) {
    statusBar.command = 'mazapi.openDashboard';
    if (issueCount === 0) {
        statusBar.text            = '$(shield) MazAPI A+';
        statusBar.tooltip         = 'MazAPI: no issues in open files — click to open the Security Dashboard';
        statusBar.backgroundColor = undefined;
        return;
    }
    const { grade, color } = computeGrade(findingsProvider.getAllFindings());
    const chains = chainsProvider?.getChainCount() ?? 0;
    statusBar.text            = `$(shield) MazAPI ${grade} $(warning) ${issueCount}` + (chains ? ` $(flame) ${chains}` : '');
    statusBar.tooltip         = `MazAPI security grade ${grade} — ${issueCount} issue(s)` +
                                (chains ? `, ${chains} attack chain(s)` : '') +
                                ' across open files. Click to open the Security Dashboard.';
    statusBar.backgroundColor = color ? new vscode.ThemeColor(color) : undefined;
}

async function runFileScan(doc: vscode.TextDocument, silent = false) {
    const envCommitted = await isEnvTrackedByGit(doc.uri);
    const findings = scanFileForIssues(doc.getText(), doc.languageId, doc.uri, envCommitted);
    applyDiagnostics(doc.uri, findings);

    // Per-file update: findings from other open files are preserved
    findingsProvider.updateFile(doc.uri, findings.filter(f => f.kind !== 'endpoint'));
    endpointsProvider.updateFile(doc.uri, findings.filter(f => f.kind === 'endpoint'));

    // Re-correlate attack chains across all open files, then refresh status bar
    recomputeChains();
    updateStatusBar(findingsProvider.getTotalIssueCount());

    if (!silent) {
        const issues = findings.filter(f => f.kind !== 'endpoint');
        if (findings.length === 0) {
            vscode.window.showInformationMessage('MazAPI: No issues found in this file.');
        } else {
            vscode.window.showWarningMessage(
                `MazAPI: ${issues.length} issue(s) · ${findings.filter(f => f.kind === 'endpoint').length} endpoint(s) detected.`,
                'Open Scanner'
            ).then(btn => { if (btn === 'Open Scanner') vscode.commands.executeCommand('mazapi.openPanel'); });
        }
    }
}

function applyDiagnostics(uri: vscode.Uri, findings: ScanFinding[]) {
    // Endpoints go in the tree panel only — don't pollute the Problems panel with informational URLs
    const diagnostics: vscode.Diagnostic[] = findings
        .filter(f => f.kind !== 'endpoint')
        .map(f => {
            const range = f.range ?? new vscode.Range(0, 0, 0, 0);
            const sev = f.severity === 'CRITICAL' || f.severity === 'HIGH'
                ? vscode.DiagnosticSeverity.Error
                : vscode.DiagnosticSeverity.Warning;
            const d = new vscode.Diagnostic(range, `[MazAPI] ${f.message}`, sev);
            d.source = 'MazAPI Scanner';
            d.code   = f.category;
            return d;
        });
    diagnosticCollection.set(uri, diagnostics);
}

// ── Security Dashboard webview ──────────────────────────────────────────────────
// A single reusable panel showing an SVG severity pie, headline counts, and a
// client-side sortable findings table. Self-contained HTML — no external libraries.

class DashboardPanel {
    private static current: vscode.WebviewPanel | undefined;

    static show(findings: ScanFinding[], chainCount: number) {
        const real = findings.filter(f => f.kind !== 'endpoint');
        const html = DashboardPanel.render(real, chainCount);
        if (DashboardPanel.current) {
            DashboardPanel.current.webview.html = html;
            DashboardPanel.current.reveal(vscode.ViewColumn.Active);
            return;
        }
        const panel = vscode.window.createWebviewPanel(
            'mazapiDashboard', 'MazAPI Security Dashboard',
            vscode.ViewColumn.Active, { enableScripts: true, retainContextWhenHidden: true },
        );
        panel.webview.html = html;
        panel.webview.onDidReceiveMessage(async (msg) => {
            if (msg?.type === 'open' && msg.fsPath) {
                const uri = vscode.Uri.file(msg.fsPath);
                const sel = new vscode.Range(msg.line ?? 0, 0, msg.line ?? 0, 0);
                await vscode.window.showTextDocument(uri, { selection: sel });
            } else if (msg?.type === 'exportHtml') {
                await DashboardPanel.exportReport(real, chainCount);
            }
        });
        panel.onDidDispose(() => { DashboardPanel.current = undefined; });
        DashboardPanel.current = panel;
    }

    private static async exportReport(findings: ScanFinding[], chainCount: number) {
        const uri = await vscode.window.showSaveDialog({
            filters: { 'HTML Report': ['html'] },
            defaultUri: vscode.Uri.file('mazapi-workspace-report.html'),
        });
        if (!uri) return;
        const html = DashboardPanel.render(findings, chainCount, true);
        await vscode.workspace.fs.writeFile(uri, Buffer.from(html, 'utf8'));
        vscode.window.showInformationMessage(`MazAPI: report written to ${uri.fsPath}`);
    }

    private static render(findings: ScanFinding[], chainCount: number, forExport = false): string {
        const esc = (s: string) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        const counts = {
            CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
            HIGH:     findings.filter(f => f.severity === 'HIGH').length,
            MEDIUM:   findings.filter(f => f.severity === 'MEDIUM').length,
            LOW:      findings.filter(f => f.severity === 'LOW').length,
        };
        const total = findings.length;
        const { grade } = computeGrade(findings);
        const SEV_COLOR: Record<string, string> = { CRITICAL: '#ff4d6a', HIGH: '#f85149', MEDIUM: '#f5a623', LOW: '#58a6ff' };

        // ── SVG donut: one arc per severity bucket ──────────────────────────────
        const R = 70, C = 90, STROKE = 26, CIRC = 2 * Math.PI * R;
        let offset = 0;
        const arcs = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const)
            .filter(s => counts[s] > 0)
            .map(s => {
                const frac = total ? counts[s] / total : 0;
                const len  = frac * CIRC;
                const seg  = `<circle cx="${C}" cy="${C}" r="${R}" fill="none" stroke="${SEV_COLOR[s]}" stroke-width="${STROKE}" ` +
                             `stroke-dasharray="${len.toFixed(2)} ${(CIRC - len).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}" ` +
                             `transform="rotate(-90 ${C} ${C})"><title>${s}: ${counts[s]}</title></circle>`;
                offset += len;
                return seg;
            }).join('');
        const donut = total
            ? `<svg width="180" height="180" viewBox="0 0 180 180">
                 <circle cx="${C}" cy="${C}" r="${R}" fill="none" stroke="#1f2733" stroke-width="${STROKE}"/>
                 ${arcs}
                 <text x="${C}" y="${C - 4}" text-anchor="middle" font-size="34" font-weight="800" fill="#e6edf3">${grade}</text>
                 <text x="${C}" y="${C + 18}" text-anchor="middle" font-size="12" fill="#8b949e">${total} issue${total !== 1 ? 's' : ''}</text>
               </svg>`
            : `<div style="color:#00c896;font-size:1.1em;padding:40px 0">$(check) No issues</div>`;

        const cards = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(s =>
            `<div class="card"><div class="num" style="color:${SEV_COLOR[s]}">${counts[s]}</div><div class="lbl">${s}</div></div>`
        ).join('') +
        `<div class="card"><div class="num" style="color:#ff4d6a">${chainCount}</div><div class="lbl">ATTACK CHAINS</div></div>`;

        const rows = findings
            .slice()
            .sort((a, b) => ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[b.severity] - { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[a.severity]))
            .map(f => {
                const file = f.uri ? f.uri.fsPath.split(/[\\/]/).pop() : '';
                const line = (f.range?.start.line ?? 0) + 1;
                const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[f.severity];
                const click = !forExport && f.uri
                    ? `data-fs="${esc(f.uri.fsPath)}" data-line="${f.range?.start.line ?? 0}" class="clickable"`
                    : '';
                return `<tr ${click} data-sev="${rank}">
                    <td><span class="sev" style="color:${SEV_COLOR[f.severity]}">${f.severity}</span></td>
                    <td>${esc(f.label ?? f.message.slice(0, 60))}</td>
                    <td class="kind">${esc(f.kind)}</td>
                    <td class="cat">${esc(f.category)}</td>
                    <td class="loc">${esc(file ?? '')}:${line}</td>
                </tr>`;
            }).join('');

        const script = forExport ? '' : `<script>
            const vscode = acquireVsCodeApi();
            document.querySelectorAll('tr.clickable').forEach(tr => tr.addEventListener('click', () =>
                vscode.postMessage({ type: 'open', fsPath: tr.dataset.fs, line: +tr.dataset.line })));
            document.getElementById('exportBtn')?.addEventListener('click', () => vscode.postMessage({ type: 'exportHtml' }));
            let sortAsc = false;
            document.querySelectorAll('th[data-sort]').forEach(th => th.addEventListener('click', () => {
                const key = th.dataset.sort, tb = document.querySelector('tbody');
                const rows = [...tb.querySelectorAll('tr')];
                rows.sort((a,b) => {
                    let av, bv;
                    if (key === 'sev') { av = +a.dataset.sev; bv = +b.dataset.sev; }
                    else { av = a.querySelector('td:nth-child(' + (key==='label'?2:key==='kind'?3:key==='loc'?5:4) + ')').innerText.toLowerCase();
                           bv = b.querySelector('td:nth-child(' + (key==='label'?2:key==='kind'?3:key==='loc'?5:4) + ')').innerText.toLowerCase(); }
                    return (av < bv ? -1 : av > bv ? 1 : 0) * (sortAsc ? 1 : -1);
                });
                sortAsc = !sortAsc; rows.forEach(r => tb.appendChild(r));
            }));
        </script>`;

        const exportBtn = forExport ? '' : `<button id="exportBtn">Export as HTML…</button>`;

        return `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
            body{font-family:-apple-system,"Segoe UI",sans-serif;background:#0a0e17;color:#e6edf3;margin:0;padding:24px}
            h1{font-size:1.3em;margin:0 0 4px} .sub{color:#8b949e;font-size:.85em;margin-bottom:20px}
            .top{display:flex;gap:28px;align-items:center;flex-wrap:wrap;margin-bottom:24px}
            .cards{display:flex;gap:12px;flex-wrap:wrap} .card{background:#0f1623;border:1px solid #1f2733;border-radius:10px;padding:14px 18px;min-width:92px;text-align:center}
            .num{font-size:1.8em;font-weight:800} .lbl{font-size:.68em;color:#8b949e;letter-spacing:.06em;margin-top:3px}
            table{width:100%;border-collapse:collapse;font-size:.84em} th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #1a2230}
            th{color:#8b949e;font-size:.78em;text-transform:uppercase;letter-spacing:.05em;cursor:pointer;user-select:none}
            th[data-sort]:hover{color:#00d4ff} tr.clickable{cursor:pointer} tr.clickable:hover{background:#121a28}
            .sev{font-weight:800;font-size:.82em} .kind,.cat,.loc{color:#8b949e} .loc{font-family:monospace;font-size:.92em}
            button{background:#00d4ff;color:#04121b;border:none;border-radius:7px;padding:8px 14px;font-weight:700;cursor:pointer;margin-top:6px}
            button:hover{background:#33ddff}
        </style></head><body>
            <h1>$(shield) MazAPI Security Dashboard</h1>
            <div class="sub">Grade ${grade} · ${total} finding${total !== 1 ? 's' : ''} across open files${chainCount ? ` · ${chainCount} attack chain(s)` : ''} · ${new Date().toLocaleString()}</div>
            <div class="top"><div>${donut}</div><div class="cards">${cards}</div></div>
            ${exportBtn}
            <table><thead><tr>
                <th data-sort="sev">Severity</th><th data-sort="label">Finding</th>
                <th data-sort="kind">Kind</th><th data-sort="cat">Category</th><th data-sort="loc">Location</th>
            </tr></thead><tbody>${rows || '<tr><td colspan="5" style="color:#00c896;padding:20px">No findings 🎉</td></tr>'}</tbody></table>
            ${script}
        </body></html>`;
    }
}

export function deactivate() {
    for (const t of changeTimers.values()) clearTimeout(t);
    changeTimers.clear();
    diagnosticCollection.dispose();
}
