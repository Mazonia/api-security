import * as vscode from 'vscode';
import * as path from 'path';
import { ScanFinding } from './scanner';

// Icon per finding kind
function findingIcon(f: ScanFinding): vscode.ThemeIcon {
    const isCritical = f.severity === 'CRITICAL' || f.severity === 'HIGH';
    const color = new vscode.ThemeColor(isCritical ? 'errorForeground' : 'editorWarning.foreground');
    switch (f.kind) {
        case 'hardcoded-key': return new vscode.ThemeIcon('key', color);
        case 'pii':           return new vscode.ThemeIcon('person', color);
        case 'weak-auth':     return new vscode.ThemeIcon('shield', color);
        default:              return new vscode.ThemeIcon('warning', color);
    }
}

// ── Leaf: individual finding ──────────────────────────────────────────────────

class FindingItem extends vscode.TreeItem {
    constructor(public readonly finding: ScanFinding) {
        // For API key findings: show "Pattern Name · masked-key"
        // For others: show the pattern label
        let label = finding.label || finding.message.slice(0, 60);
        if (finding.kind === 'hardcoded-key' && finding.maskedValue) {
            label = `${finding.label}  ${finding.maskedValue}`;
        }
        super(label, vscode.TreeItemCollapsibleState.None);

        // file:line in the description column
        if (finding.uri && finding.range) {
            const filename = path.basename(finding.uri.fsPath);
            this.description = `${filename}:${finding.range.start.line + 1}`;
        }

        // Rich tooltip: service name, severity, masked key, fix
        const md = new vscode.MarkdownString(undefined, true);
        md.isTrusted = true;
        if (finding.kind === 'hardcoded-key') {
            md.appendMarkdown(`### $(key) ${finding.label}\n`);
            if (finding.service) {
                md.appendMarkdown(`**Service:** ${finding.service}\n\n`);
            }
            if (finding.maskedValue) {
                md.appendMarkdown(`**Key (masked):** \`${finding.maskedValue}\`\n\n`);
            }
        } else {
            md.appendMarkdown(`### ${finding.label || finding.message.slice(0, 60)}\n`);
        }
        md.appendMarkdown(`**Severity:** ${finding.severity}\n\n`);
        if (finding.fix) {
            md.appendMarkdown(`**Fix:** ${finding.fix}`);
        }
        this.tooltip = md;
        this.iconPath = findingIcon(finding);

        // Click → jump to the finding in the source file
        if (finding.uri && finding.range) {
            this.command = {
                command:   'vscode.open',
                title:     'Go to finding',
                arguments: [finding.uri, { selection: finding.range }],
            };
        }
        this.contextValue = 'mazapi-finding';
    }
}

// ── Parent: file group ────────────────────────────────────────────────────────

class FileGroupItem extends vscode.TreeItem {
    constructor(
        public readonly fileUri: vscode.Uri,
        public readonly findings: ScanFinding[]
    ) {
        const filename = path.basename(fileUri.fsPath);
        super(filename, vscode.TreeItemCollapsibleState.Expanded);

        const severe = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;
        this.description = `${findings.length} issue${findings.length !== 1 ? 's' : ''}` +
                           (severe ? ` · ${severe} critical/high` : '');
        this.tooltip     = fileUri.fsPath;
        this.resourceUri = fileUri;
        this.iconPath    = new vscode.ThemeIcon(
            severe ? 'error' : 'warning',
            new vscode.ThemeColor(severe ? 'errorForeground' : 'editorWarning.foreground')
        );
        this.contextValue = 'mazapi-file-group';
    }
}

// ── Findings tree provider (two-level: file → findings) ──────────────────────

export class FindingsProvider implements vscode.TreeDataProvider<FileGroupItem | FindingItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
    private groups: Map<string, { uri: vscode.Uri; findings: ScanFinding[] }> = new Map();

    refresh(findings: ScanFinding[]) {
        this.groups = new Map();
        for (const f of findings) {
            if (!f.uri) continue;
            const key = f.uri.fsPath;
            if (!this.groups.has(key)) {
                this.groups.set(key, { uri: f.uri, findings: [] });
            }
            this.groups.get(key)!.findings.push(f);
        }
        this._onDidChangeTreeData.fire(undefined);
    }

    getTreeItem(el: FileGroupItem | FindingItem) { return el; }

    getChildren(el?: FileGroupItem | FindingItem): (FileGroupItem | FindingItem)[] {
        if (!el) {
            // Root level — one entry per file that has findings
            return Array.from(this.groups.values()).map(g => new FileGroupItem(g.uri, g.findings));
        }
        if (el instanceof FileGroupItem) {
            return el.findings.map(f => new FindingItem(f));
        }
        return [];
    }
}

// ── Endpoints tree provider ───────────────────────────────────────────────────

export class EndpointsProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
    private endpoints: ScanFinding[] = [];

    refresh(endpoints: ScanFinding[]) {
        this.endpoints = endpoints;
        this._onDidChangeTreeData.fire(undefined);
    }
    getTreeItem(el: vscode.TreeItem) { return el; }
    getChildren(): vscode.TreeItem[] {
        return this.endpoints.map(e => {
            const url  = e.value || e.message.slice(0, 60);
            const item = new vscode.TreeItem(url);
            item.iconPath = new vscode.ThemeIcon('link', new vscode.ThemeColor('textLink.foreground'));
            item.tooltip  = `$(shield) Scan this endpoint\n\n${url}`;
            const filename = e.uri ? path.basename(e.uri.fsPath) : '';
            const line     = e.range ? `:${e.range.start.line + 1}` : '';
            item.description = filename + line;
            // Click → open MazAPI panel with the URL pre-filled
            item.command = {
                command:   'mazapi.openPanel',
                title:     'Scan this endpoint',
                arguments: [url],
            };
            return item;
        });
    }
}
