import * as vscode from 'vscode';
import * as path from 'path';
import { ScanFinding } from './scanner';

// ── Filter state ──────────────────────────────────────────────────────────────

export interface FindingsFilter {
    showKeys:      boolean;  // hardcoded-key
    showUrls:      boolean;  // hardcoded-url
    showEndpoints: boolean;  // endpoint (informational)
    showWeakAuth:  boolean;  // weak-auth
    showPII:       boolean;  // pii
    minSeverity:   'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export const DEFAULT_FILTER: FindingsFilter = {
    showKeys: true, showUrls: true, showEndpoints: true,
    showWeakAuth: true, showPII: true, minSeverity: 'LOW',
};

const SEV_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

export function isDefaultFilter(f: FindingsFilter): boolean {
    return f.showKeys && f.showUrls && f.showEndpoints &&
           f.showWeakAuth && f.showPII && f.minSeverity === 'LOW';
}

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
    private filter: FindingsFilter = { ...DEFAULT_FILTER };

    // ── Filter API ────────────────────────────────────────────────────────────

    setFilter(f: FindingsFilter) {
        this.filter = { ...f };
        this._onDidChangeTreeData.fire(undefined);
    }

    getFilter(): FindingsFilter { return { ...this.filter }; }

    private applyFilter(findings: ScanFinding[]): ScanFinding[] {
        const minRank = SEV_RANK[this.filter.minSeverity] ?? 1;
        return findings.filter(f => {
            if (!this.filter.showKeys      && f.kind === 'hardcoded-key')  return false;
            if (!this.filter.showUrls      && f.kind === 'hardcoded-url')  return false;
            if (!this.filter.showEndpoints && f.kind === 'endpoint')       return false;
            if (!this.filter.showWeakAuth  && f.kind === 'weak-auth')      return false;
            if (!this.filter.showPII       && f.kind === 'pii')            return false;
            if ((SEV_RANK[f.severity] ?? 1) < minRank)                     return false;
            return true;
        });
    }

    // ── Data API ──────────────────────────────────────────────────────────────

    /** Replace findings for one file only — preserves other files' results. */
    updateFile(uri: vscode.Uri, findings: ScanFinding[]) {
        if (findings.length === 0) this.groups.delete(uri.fsPath);
        else this.groups.set(uri.fsPath, { uri, findings });
        this._onDidChangeTreeData.fire(undefined);
    }

    /** Full replacement — used by the workspace scan command. */
    refresh(findings: ScanFinding[]) {
        this.groups = new Map();
        for (const f of findings) {
            if (!f.uri) continue;
            const key = f.uri.fsPath;
            if (!this.groups.has(key)) this.groups.set(key, { uri: f.uri, findings: [] });
            this.groups.get(key)!.findings.push(f);
        }
        this._onDidChangeTreeData.fire(undefined);
    }

    /** Total visible issue count across all files (respects active filter, excludes endpoints). */
    getTotalIssueCount(): number {
        let n = 0;
        for (const { findings } of this.groups.values()) {
            n += this.applyFilter(findings).filter(f => f.kind !== 'endpoint').length;
        }
        return n;
    }

    /** All raw findings for a URI (unfiltered — used for diagnostics). */
    getRawFindings(uri: vscode.Uri): ScanFinding[] {
        return this.groups.get(uri.fsPath)?.findings ?? [];
    }

    getTreeItem(el: FileGroupItem | FindingItem) { return el; }

    getChildren(el?: FileGroupItem | FindingItem): (FileGroupItem | FindingItem)[] {
        if (!el) {
            const items: FileGroupItem[] = [];
            for (const g of this.groups.values()) {
                const filtered = this.applyFilter(g.findings);
                if (filtered.length) items.push(new FileGroupItem(g.uri, filtered));
            }
            return items;
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
    private byFile: Map<string, ScanFinding[]> = new Map();

    /** Replace endpoints for one file only. */
    updateFile(uri: vscode.Uri, endpoints: ScanFinding[]) {
        if (endpoints.length === 0) this.byFile.delete(uri.fsPath);
        else this.byFile.set(uri.fsPath, endpoints);
        this._onDidChangeTreeData.fire(undefined);
    }

    /** Full replacement — used by workspace scan. */
    refresh(endpoints: ScanFinding[]) {
        this.byFile = new Map();
        for (const e of endpoints) {
            if (!e.uri) continue;
            const arr = this.byFile.get(e.uri.fsPath) ?? [];
            arr.push(e);
            this.byFile.set(e.uri.fsPath, arr);
        }
        this._onDidChangeTreeData.fire(undefined);
    }

    private get endpoints(): ScanFinding[] {
        return Array.from(this.byFile.values()).flat();
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
