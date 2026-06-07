import * as vscode from 'vscode';
import { scanFileForIssues, ScanFinding } from './scanner';
import { MazAPIPanel } from './panel';
import { EndpointsProvider, FindingsProvider } from './treeview';

let findingsProvider: FindingsProvider;
let endpointsProvider: EndpointsProvider;
let diagnosticCollection: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;

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
                    findingsProvider.refresh(allFindings);
                    endpointsProvider.refresh(allFindings.filter(f => f.kind === 'endpoint'));
                    const issues = allFindings.filter(f => f.kind !== 'endpoint');
                    updateStatusBar(issues.length);
                    vscode.window.showInformationMessage(
                        `MazAPI: ${issues.length} issue(s) · ${allFindings.filter(f => f.kind === 'endpoint').length} endpoint(s) across ${files.length} files.`
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

    // ── Auto-scan on save (if enabled) ────────────────────────────────────────
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (doc) => {
            const cfg = vscode.workspace.getConfiguration('mazapi');
            if (cfg.get<boolean>('autoScanOnSave')) {
                await runFileScan(doc);
            }
        })
    );

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

    // ── Status bar — shows live finding count, click to scan current file ─────
    statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    updateStatusBar(0);
    statusBar.show();
    context.subscriptions.push(statusBar);
}

function updateStatusBar(issueCount: number) {
    if (issueCount === 0) {
        statusBar.text    = '$(shield) MazAPI';
        statusBar.tooltip = 'MazAPI Scanner — click to scan current file';
        statusBar.color   = undefined;
        statusBar.command = 'mazapi.scanFile';
    } else {
        statusBar.text    = `$(shield) MazAPI $(warning) ${issueCount}`;
        statusBar.tooltip = `MazAPI found ${issueCount} security issue(s) — click to scan current file`;
        statusBar.color   = new vscode.ThemeColor('statusBarItem.warningForeground');
        statusBar.command = 'mazapi.scanFile';
    }
}

async function runFileScan(doc: vscode.TextDocument) {
    const findings = scanFileForIssues(doc.getText(), doc.languageId, doc.uri);
    applyDiagnostics(doc.uri, findings);
    findingsProvider.refresh(findings);
    endpointsProvider.refresh(findings.filter(f => f.kind === 'endpoint'));
    const issues = findings.filter(f => f.kind !== 'endpoint');
    updateStatusBar(issues.length);
    if (findings.length === 0) {
        vscode.window.showInformationMessage('MazAPI: No issues found in this file.');
    } else {
        vscode.window.showWarningMessage(
            `MazAPI: ${issues.length} issue(s) · ${findings.filter(f => f.kind === 'endpoint').length} endpoint(s) detected.`,
            'Open Scanner'
        ).then(btn => { if (btn === 'Open Scanner') vscode.commands.executeCommand('mazapi.openPanel'); });
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
    diagnosticCollection.dispose();
}
