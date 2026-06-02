import * as vscode from 'vscode';

export type FindingKind = 'hardcoded-key' | 'hardcoded-url' | 'endpoint' | 'weak-auth';

export interface ScanFinding {
    kind:     FindingKind;
    message:  string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    category: string;
    range?:   vscode.Range;
    value?:   string;
    fix?:     string;
}

// ── Pattern definitions ───────────────────────────────────────────────────────

const KEY_PATTERNS: { name: string; pattern: RegExp; severity: 'CRITICAL' | 'HIGH'; category: string; fix: string }[] = [
    {
        name: 'Google API Key',
        pattern: /AIza[0-9A-Za-z_-]{35}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Store in environment variable (process.env.GOOGLE_API_KEY) and add to .gitignore',
    },
    {
        name: 'OpenAI / Stripe Secret Key',
        pattern: /sk-[A-Za-z0-9]{32,}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Move to .env file, load via dotenv, never commit to source control',
    },
    {
        name: 'GitHub Personal Access Token',
        pattern: /ghp_[A-Za-z0-9]{36}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Revoke immediately at github.com/settings/tokens, use GITHUB_TOKEN env var',
    },
    {
        name: 'AWS Access Key',
        pattern: /AKIA[0-9A-Z]{16}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials / CVE-2021-22967 class',
        fix: 'Revoke in AWS IAM immediately. Use IAM roles or AWS Secrets Manager instead',
    },
    {
        name: 'Generic hardcoded API key/token',
        pattern: /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([A-Za-z0-9._\-]{20,80})["']/gi,
        severity: 'HIGH',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Extract to environment variable or secrets manager',
    },
    {
        name: 'JWT Hardcoded Secret',
        pattern: /(?:jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*["']([^"']{4,60})["']/gi,
        severity: 'CRITICAL',
        category: 'CVE-2019-9599 class / CWE-321 - Hardcoded Cryptographic Key',
        fix: 'Generate a strong random secret (openssl rand -hex 32) and load from environment',
    },
];

const URL_PATTERNS: { pattern: RegExp; severity: 'MEDIUM' | 'LOW'; category: string }[] = [
    {
        pattern: /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?\/[^\s"'`]+/g,
        severity: 'LOW',
        category: 'CWE-441 - Hardcoded Internal URL (debug endpoint)',
    },
    {
        pattern: /https?:\/\/[a-z0-9.-]+\/(?:api|v\d+|graphql|rest)\/[^\s"'`]{5,}/g,
        severity: 'LOW',
        category: 'API Endpoint detected (review for exposure)',
    },
];

const WEAK_AUTH_PATTERNS: { name: string; pattern: RegExp; severity: 'HIGH' | 'CRITICAL'; category: string; fix: string }[] = [
    {
        name: 'MD5 password hashing',
        pattern: /md5\s*\(/gi,
        severity: 'HIGH',
        category: 'CWE-327 - Weak Cryptographic Algorithm (MD5)',
        fix: 'Use bcrypt, argon2, or PBKDF2 for password hashing',
    },
    {
        name: 'SHA1 password hashing',
        pattern: /sha1\s*\(/gi,
        severity: 'HIGH',
        category: 'CWE-327 - Weak Cryptographic Algorithm (SHA-1)',
        fix: 'Use bcrypt or argon2id for passwords; SHA-256+ for non-password hashing',
    },
    {
        name: 'Algorithm none in JWT',
        pattern: /alg.*none|algorithm.*none/gi,
        severity: 'CRITICAL',
        category: 'CVE-2015-9235 - JWT Algorithm None Bypass',
        fix: 'Explicitly reject tokens with alg:none. Use HS256 minimum, RS256 preferred',
    },
    {
        name: 'Hardcoded admin password',
        pattern: /password\s*[:=]\s*["'](?:admin|password|123456|secret|test|pass)["']/gi,
        severity: 'CRITICAL',
        category: 'CWE-521 - Weak Password Requirements',
        fix: 'Never hardcode passwords. Use secure defaults and require user to set password',
    },
    {
        name: 'SQL query string concatenation',
        pattern: /(?:SELECT|INSERT|UPDATE|DELETE).*\+\s*(?:req\.|request\.|params\.|body\.|query\.|\$_GET|\$_POST)/gi,
        severity: 'CRITICAL',
        category: 'CVE-2019-14234 class / CWE-89 - SQL Injection',
        fix: 'Use parameterised queries or an ORM. Never concatenate user input into SQL',
    },
];

// ── Main scan function ────────────────────────────────────────────────────────

export function scanFileForIssues(
    text: string,
    langId: string,
    uri: vscode.Uri
): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const lines = text.split('\n');

    function rangeOf(match: RegExpExecArray, source: string): vscode.Range {
        let pos = 0, lineNum = 0;
        for (const line of lines) {
            const lineEnd = pos + line.length;
            if (match.index >= pos && match.index <= lineEnd) {
                const col = match.index - pos;
                return new vscode.Range(lineNum, col, lineNum, col + match[0].length);
            }
            pos = lineEnd + 1;
            lineNum++;
        }
        return new vscode.Range(0, 0, 0, 0);
    }

    // Check for hardcoded API keys / secrets
    for (const { name, pattern, severity, category, fix } of KEY_PATTERNS) {
        pattern.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = pattern.exec(text)) !== null) {
            const value = (m[1] || m[0]).slice(0, 40);
            findings.push({
                kind:     'hardcoded-key',
                message:  `${name} detected: "${value}…" — never commit credentials to source code`,
                severity,
                category,
                range:    rangeOf(m, text),
                value:    m[1] || m[0],
                fix,
            });
        }
    }

    // Check for hardcoded URLs
    for (const { pattern, severity, category } of URL_PATTERNS) {
        pattern.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = pattern.exec(text)) !== null) {
            findings.push({
                kind:     category.includes('Endpoint') ? 'endpoint' : 'hardcoded-url',
                message:  `Hardcoded URL: ${m[0].slice(0, 60)}`,
                severity,
                category,
                range:    rangeOf(m, text),
                value:    m[0],
            });
        }
    }

    // Check for weak authentication patterns
    for (const { name, pattern, severity, category, fix } of WEAK_AUTH_PATTERNS) {
        pattern.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = pattern.exec(text)) !== null) {
            findings.push({
                kind:    'weak-auth',
                message: `${name}: ${m[0].slice(0, 60)}`,
                severity,
                category,
                range:   rangeOf(m, text),
                fix,
            });
        }
    }

    return findings;
}
