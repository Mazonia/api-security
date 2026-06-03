import * as vscode from 'vscode';
import { scanFileForIssues, ScanFinding } from './scanner';
import { MazAPIPanel } from './panel';
import { EndpointsProvider, FindingsProvider } from './treeview';

let findingsProvider: FindingsProvider;
let endpointsProvider: EndpointsProvider;
let diagnosticCollection: vscode.DiagnosticCollection;

export function activate(context: vscode.ExtensionContext) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('mazapi');
    context.subscriptions.push(diagnosticCollection);

    findingsProvider  = new FindingsProvider();
    endpointsProvider = new EndpointsProvider();
    vscode.window.registerTreeDataProvider('mazapi.findings',  findingsProvider);
    vscode.window.registerTreeDataProvider('mazapi.endpoints', endpointsProvider);

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
                '**/*.{js,ts,py,env,json}',
                '**/node_modules/**'
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
                    vscode.window.showInformationMessage(
                        `MazAPI: Found ${allFindings.length} issue(s) across ${files.length} files.`
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

    // ── Command: Open panel ───────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('mazapi.openPanel', () => {
            MazAPIPanel.createOrShow(context.extensionUri, '');
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
                MazAPIPanel.currentPanel['_panel'].webview.postMessage({ type: 'triggerExport', format: 'sarif' });
            } else {
                vscode.window.showWarningMessage('MazAPI: No scan results — run a scan first.');
            }
        })
    );

    // ── Command: Export HTML report from last panel scan ──────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('mazapi.exportHTML', () => {
            if (MazAPIPanel.currentPanel) {
                MazAPIPanel.currentPanel['_panel'].webview.postMessage({ type: 'triggerExport', format: 'html' });
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

    // ── Status bar item ───────────────────────────────────────────────────────
    const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBar.text = '$(shield) MazAPI';
    statusBar.tooltip = 'MazAPI Scanner — click to scan current file';
    statusBar.command = 'mazapi.scanFile';
    statusBar.show();
    context.subscriptions.push(statusBar);
}

async function runFileScan(doc: vscode.TextDocument) {
    const findings = scanFileForIssues(doc.getText(), doc.languageId, doc.uri);
    applyDiagnostics(doc.uri, findings);
    findingsProvider.refresh(findings);
    endpointsProvider.refresh(findings.filter(f => f.kind === 'endpoint'));
    if (findings.length === 0) {
        vscode.window.showInformationMessage('MazAPI: No issues found in this file.');
    } else {
        vscode.window.showWarningMessage(
            `MazAPI: Found ${findings.length} issue(s). See Problems panel.`,
            'Open Results'
        ).then(btn => { if (btn === 'Open Results') vscode.commands.executeCommand('mazapi.openPanel'); });
    }
}

function applyDiagnostics(uri: vscode.Uri, findings: ScanFinding[]) {
    const diagnostics: vscode.Diagnostic[] = findings.map(f => {
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
