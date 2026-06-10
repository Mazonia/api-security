import * as vscode from 'vscode';
import { scanFileForIssues, ScanFinding } from './scanner';
import { MazAPIPanel } from './panel';
import { EndpointsProvider, FindingsProvider, FindingsFilter, DEFAULT_FILTER, isDefaultFilter } from './treeview';

let findingsProvider: FindingsProvider;
let endpointsProvider: EndpointsProvider;
let diagnosticCollection: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;

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
    // Matches any http(s) URL that looks like an API endpoint
    private static readonly URL_RE = /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|[a-z0-9][a-z0-9-]*\.[a-z]{2,})(?::\d+)?(?:\/[^\s"'`)\]]*)?/gi;

    provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
        const lenses: vscode.CodeLens[] = [];
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

export function activate(context: vscode.ExtensionContext) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('mazapi');
    context.subscriptions.push(diagnosticCollection);

    findingsProvider  = new FindingsProvider();
    endpointsProvider = new EndpointsProvider();
    vscode.window.registerTreeDataProvider('mazapi.findings',  findingsProvider);
    vscode.window.registerTreeDataProvider('mazapi.endpoints', endpointsProvider);

    // ── CodeLens: inline "Scan with MazAPI" button above every URL line ───────
    context.subscriptions.push(
        vscode.languages.registerCodeLensProvider(
            [
                { language: 'javascript' }, { language: 'typescript' },
                { language: 'python' },     { language: 'json' },
                { language: 'yaml' },       { language: 'plaintext' },
            ],
            new MazAPICodeLensProvider()
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
                        const findings = scanFileForIssues(doc.getText(), doc.languageId, doc.uri);
                        allFindings.push(...findings);
                        applyDiagnostics(doc.uri, findings);
                    }
                    findingsProvider.refresh(allFindings.filter(f => f.kind !== 'endpoint'));
                    endpointsProvider.refresh(allFindings.filter(f => f.kind === 'endpoint'));
                    updateStatusBar(findingsProvider.getTotalIssueCount());
                    vscode.window.showInformationMessage(
                        `MazAPI: ${findingsProvider.getTotalIssueCount()} issue(s) · ${allFindings.filter(f => f.kind === 'endpoint').length} endpoint(s) across ${files.length} files.`
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

    // ── Status bar — shows live finding count, click to scan current file ─────
    statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    updateStatusBar(0);
    statusBar.show();
    context.subscriptions.push(statusBar);
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
    if (issueCount === 0) {
        statusBar.text    = '$(shield) MazAPI';
        statusBar.tooltip = 'MazAPI Scanner — click to scan current file';
        statusBar.color   = undefined;
        statusBar.command = 'mazapi.scanFile';
    } else {
        statusBar.text    = `$(shield) MazAPI $(warning) ${issueCount}`;
        statusBar.tooltip = `MazAPI: ${issueCount} security issue(s) across open files — click to scan current file`;
        statusBar.color   = new vscode.ThemeColor('statusBarItem.warningForeground');
        statusBar.command = 'mazapi.scanFile';
    }
}

async function runFileScan(doc: vscode.TextDocument, silent = false) {
    const findings = scanFileForIssues(doc.getText(), doc.languageId, doc.uri);
    applyDiagnostics(doc.uri, findings);

    // Per-file update: findings from other open files are preserved
    findingsProvider.updateFile(doc.uri, findings.filter(f => f.kind !== 'endpoint'));
    endpointsProvider.updateFile(doc.uri, findings.filter(f => f.kind === 'endpoint'));

    // Status bar always reflects the workspace total, not just this file
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

export function deactivate() {
    for (const t of changeTimers.values()) clearTimeout(t);
    changeTimers.clear();
    diagnosticCollection.dispose();
}
