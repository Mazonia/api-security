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
    if (f.isGitignoredEnv) {
        return new vscode.ThemeIcon('key', new vscode.ThemeColor('charts.green'));
    }
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
        if (finding.isGitignoredEnv) {
            label = `[SECURE] ${label}`;
        }
        super(label, vscode.TreeItemCollapsibleState.None);

        // file:line in the description column
        if (finding.uri && finding.range) {
            const filename = path.basename(finding.uri.fsPath);
            this.description = `${filename}:${finding.range.start.line + 1}` + (finding.isGitignoredEnv ? ' (safely in .env)' : '');
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

        const allSecure = findings.every(f => f.isGitignoredEnv);
        const severe = findings.filter(f => (f.severity === 'CRITICAL' || f.severity === 'HIGH') && !f.isGitignoredEnv).length;
        
        if (allSecure) {
            this.description = `${findings.length} secret${findings.length !== 1 ? 's' : ''} (safely in .env)`;
            this.iconPath = new vscode.ThemeIcon('shield', new vscode.ThemeColor('charts.green'));
        } else {
            this.description = `${findings.length} issue${findings.length !== 1 ? 's' : ''}` +
                               (severe ? ` · ${severe} critical/high` : '');
            this.iconPath = new vscode.ThemeIcon(
                severe ? 'error' : 'warning',
                new vscode.ThemeColor(severe ? 'errorForeground' : 'editorWarning.foreground')
            );
        }
        
        this.tooltip      = fileUri.fsPath;
        this.resourceUri  = fileUri;
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

    /** Every finding across every tracked file (unfiltered — used for chain correlation & dashboard). */
    getAllFindings(): ScanFinding[] {
        const out: ScanFinding[] = [];
        for (const { findings } of this.groups.values()) out.push(...findings);
        return out;
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

// ── Attack-chain correlation ────────────────────────────────────────────────────
// Individual findings are dangerous; certain *combinations* are catastrophic. A chain
// fires only when every one of its required predicates is satisfied somewhere in the
// workspace finding set. Each chain pulls the specific findings that triggered it so
// they can be shown as children and the user can jump straight to the code.

export interface AttackChain {
    id:        string;
    title:     string;
    narrative: string;          // "An attacker who found these could…"
    severity:  'CRITICAL' | 'HIGH';
    findings:  ScanFinding[];   // the concrete findings that satisfied this chain
}

// A predicate matches a finding by its category or label substring.
type ChainPredicate = (f: ScanFinding) => boolean;

interface ChainDef {
    id:        string;
    title:     string;
    narrative: string;
    severity:  'CRITICAL' | 'HIGH';
    requires:  ChainPredicate[];   // every predicate must match at least one finding
}

const has = (...needles: string[]): ChainPredicate =>
    (f) => needles.some(n => f.category.includes(n) || (f.label ?? '').toLowerCase().includes(n.toLowerCase()));

const CHAIN_DEFS: ChainDef[] = [
    {
        id: 'account-takeover',
        title: 'FULL ACCOUNT TAKEOVER',
        narrative: 'Mass assignment lets an attacker set privilege fields (role, is_admin) on their own object, ' +
                   'while a hardcoded/weak auth secret lets them mint or forge the token to reach it — together they grant full control of any account.',
        severity: 'CRITICAL',
        requires: [has('CWE-915', 'Mass Assignment'), has('CWE-798', 'CWE-321', 'JWT Hardcoded', 'Broken Authentication')],
    },
    {
        id: 'data-breach',
        title: 'DATA BREACH',
        narrative: 'Verbose errors / stack traces reveal internal structure and an unauthenticated operational endpoint ' +
                   'or hardcoded DB credential gives the attacker the access path — together they enable bulk exfiltration of records.',
        severity: 'CRITICAL',
        requires: [has('CWE-209', 'Stack Trace', 'CWE-532'), has('Unauthenticated Operational', 'Hardcoded DB', 'CWE-798')],
    },
    {
        id: 'token-theft-xss',
        title: 'TOKEN THEFT VIA XSS',
        narrative: 'An auth token kept in localStorage is readable by any script on the page; combine that with a code-injection ' +
                   'or prototype-pollution sink and an attacker can run JS that steals the token and impersonates the user.',
        severity: 'HIGH',
        requires: [has('Sensitive Token in Browser Storage', 'localStorage'), has('CWE-95', 'CWE-1321', 'eval', 'Prototype Pollution')],
    },
    {
        id: 'ssrf-to-cloud',
        title: 'SSRF → CLOUD CREDENTIAL THEFT',
        narrative: 'A server-side request driven by user input can be pointed at the cloud metadata service (169.254.169.254); ' +
                   'with TLS verification disabled the attacker can also MITM outbound calls — together they expose cloud IAM credentials.',
        severity: 'CRITICAL',
        requires: [has('CWE-918', 'SSRF'), has('CWE-295', 'certificate', 'CORS Wildcard', 'CWE-942')],
    },
    {
        id: 'auth-bypass-escalation',
        title: 'PRIVILEGE ESCALATION',
        narrative: 'An unthrottled auth route enables credential stuffing to obtain any account, and an environment-gated ' +
                   'security control means protections may be off in the reachable environment — together they yield admin access.',
        severity: 'HIGH',
        requires: [has('Auth Route Missing Rate Limiting', 'API4:2023'), has('Security Control Gated by Environment', 'CWE-1188', 'alg:none', 'Broken Authentication')],
    },
];

/** Correlate a flat list of workspace findings into any attack chains they satisfy. */
export function correlateChains(allFindings: ScanFinding[]): AttackChain[] {
    const chains: AttackChain[] = [];
    for (const def of CHAIN_DEFS) {
        const matched: ScanFinding[] = [];
        const satisfied = def.requires.every(pred => {
            const hit = allFindings.find(pred);
            if (hit) { matched.push(hit); return true; }
            return false;
        });
        if (satisfied) {
            // de-dupe in case one finding satisfied two predicates
            const seen = new Set<ScanFinding>();
            const unique = matched.filter(f => (seen.has(f) ? false : (seen.add(f), true)));
            chains.push({ id: def.id, title: def.title, narrative: def.narrative, severity: def.severity, findings: unique });
        }
    }
    return chains;
}

// ── Attack-chains tree provider (chain → constituent findings) ──────────────────

class ChainParentItem extends vscode.TreeItem {
    constructor(public readonly chain: AttackChain) {
        super(`⚠ ${chain.title} (${chain.findings.length} findings)`, vscode.TreeItemCollapsibleState.Expanded);
        this.description = chain.severity;
        const md = new vscode.MarkdownString(undefined, true);
        md.appendMarkdown(`### $(flame) ${chain.title}\n\n**Severity:** ${chain.severity}\n\n${chain.narrative}`);
        this.tooltip  = md;
        this.iconPath = new vscode.ThemeIcon('flame', new vscode.ThemeColor('errorForeground'));
        this.contextValue = 'mazapi-chain';
    }
}

export class ChainsProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
    private chains: AttackChain[] = [];

    setChains(chains: AttackChain[]) {
        this.chains = chains;
        this._onDidChangeTreeData.fire(undefined);
    }

    getChainCount(): number { return this.chains.length; }

    getTreeItem(el: vscode.TreeItem) { return el; }

    getChildren(el?: vscode.TreeItem): vscode.TreeItem[] {
        if (!el) {
            if (!this.chains.length) {
                const empty = new vscode.TreeItem('No attack chains detected');
                empty.iconPath = new vscode.ThemeIcon('shield', new vscode.ThemeColor('charts.green'));
                empty.tooltip  = 'An attack chain appears when two or more findings combine into a known exploit path.';
                return [empty];
            }
            return this.chains.map(c => new ChainParentItem(c));
        }
        if (el instanceof ChainParentItem) {
            return el.chain.findings.map(f => new FindingItem(f));
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
