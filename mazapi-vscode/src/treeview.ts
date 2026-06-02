import * as vscode from 'vscode';
import { ScanFinding } from './scanner';

class FindingItem extends vscode.TreeItem {
    constructor(finding: ScanFinding) {
        super(finding.message.slice(0, 60), vscode.TreeItemCollapsibleState.None);
        this.tooltip    = finding.message + (finding.fix ? '\n\nFix: ' + finding.fix : '');
        this.description = finding.severity;
        this.iconPath   = new vscode.ThemeIcon(
            finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
                ? 'error' : 'warning'
        );
        if (finding.range) {
            this.command = {
                command:   'vscode.open',
                title:     'Open',
                arguments: [finding.range],
            };
        }
    }
}

export class FindingsProvider implements vscode.TreeDataProvider<FindingItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
    private findings: ScanFinding[] = [];

    refresh(findings: ScanFinding[]) {
        this.findings = findings;
        this._onDidChangeTreeData.fire(undefined);
    }
    getTreeItem(el: FindingItem) { return el; }
    getChildren(): FindingItem[] {
        return this.findings.map(f => new FindingItem(f));
    }
}

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
            const item = new vscode.TreeItem(e.value || e.message.slice(0, 60));
            item.iconPath    = new vscode.ThemeIcon('link');
            item.description = e.category;
            item.tooltip     = e.value;
            item.command     = {
                command:   'mazapi.openPanel',
                title:     'Scan this endpoint',
                arguments: [e.value],
            };
            return item;
        });
    }
}
