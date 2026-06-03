import * as vscode from 'vscode';

export type FindingKind = 'hardcoded-key' | 'hardcoded-url' | 'endpoint' | 'weak-auth' | 'pii';

export interface Compliance {
    pci_dss?:  string[];
    gdpr?:     string[];
    iso27001?: string[];
}

export interface ScanFinding {
    kind:        FindingKind;
    message:     string;
    severity:    'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    category:    string;
    range?:      vscode.Range;
    value?:      string;
    fix?:        string;
    compliance?: Compliance;
}

const COMPLIANCE_MAP: Record<string, Compliance> = {
    'CWE-798 - Hardcoded Credentials':                   { pci_dss: ['8.2.1','6.2.4'], gdpr: ['Art. 32(1)(b)'],          iso27001: ['A.9.4.3','A.10.1.1'] },
    'CWE-321 - Hardcoded Cryptographic Key':             { pci_dss: ['8.2.1','6.2.4'], gdpr: ['Art. 32(1)(b)'],          iso27001: ['A.10.1.1','A.9.4.3'] },
    'CWE-321 - Private Key in Source Code':              { pci_dss: ['8.2.1'],          gdpr: ['Art. 32'],                iso27001: ['A.10.1.1'] },
    'CWE-798 - Hardcoded DB Credentials':                { pci_dss: ['8.2.1','2.2.7'], gdpr: ['Art. 32'],                iso27001: ['A.9.4.3'] },
    'CVE-2019-9599 class / CWE-321 - Hardcoded Cryptographic Key': { pci_dss: ['8.2.1'], gdpr: ['Art. 32'], iso27001: ['A.10.1.1'] },
    'CVE-2015-9235 - JWT Algorithm None Bypass':         { pci_dss: ['8.2.1','6.2.4'], gdpr: ['Art. 32(1)(b)'],          iso27001: ['A.9.4.3'] },
    'CWE-327 - Weak Cryptographic Algorithm (MD5)':      { pci_dss: ['4.2.1','8.3.2'], gdpr: ['Art. 32(1)(a)'],          iso27001: ['A.10.1.1'] },
    'CWE-327 - Weak Cryptographic Algorithm (SHA-1)':    { pci_dss: ['4.2.1','8.3.2'], gdpr: ['Art. 32(1)(a)'],          iso27001: ['A.10.1.1'] },
    'CWE-521 - Weak Password Requirements':              { pci_dss: ['8.3.6'],          gdpr: ['Art. 32'],                iso27001: ['A.9.4.3'] },
    'CVE-2019-14234 class / CWE-89 - SQL Injection':     { pci_dss: ['6.2.4'],          gdpr: ['Art. 32'],                iso27001: ['A.14.2.5'] },
    'CWE-78 - OS Command Injection':                     { pci_dss: ['6.2.4'],          gdpr: ['Art. 32'],                iso27001: ['A.14.2.5'] },
    'CWE-319 - Cleartext Transmission':                  { pci_dss: ['4.2.1'],          gdpr: ['Art. 32(1)(a)'],          iso27001: ['A.13.2.3'] },
    'CWE-295 - Improper Certificate Validation':         { pci_dss: ['4.2.1'],          gdpr: ['Art. 32(1)(a)'],          iso27001: ['A.13.2.3'] },
    'CWE-95 - Code Injection via eval()':                { pci_dss: ['6.2.4'],          gdpr: ['Art. 32'],                iso27001: ['A.14.2.5'] },
    'CWE-312 - PII / Sensitive Data Pattern in Code':    { pci_dss: ['3.4.1','4.2.1'], gdpr: ['Art. 5','Art. 25','Art. 32'], iso27001: ['A.18.1.4','A.8.2.3'] },
};

function getCompliance(category: string): Compliance | undefined {
    for (const [key, val] of Object.entries(COMPLIANCE_MAP)) {
        if (category === key || category.startsWith(key.split(' - ')[0])) return val;
    }
    return undefined;
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
    {
        name: 'Slack Token',
        pattern: /xox[baprs]-[0-9A-Za-z-]{10,48}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Revoke at api.slack.com/apps, store in environment variable',
    },
    {
        name: 'Stripe Live Secret Key',
        pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Roll the key in the Stripe dashboard immediately; never ship live keys client-side',
    },
    {
        name: 'Twilio API Key',
        pattern: /SK[0-9a-fA-F]{32}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Revoke in Twilio console, load from environment',
    },
    {
        name: 'Private Key block',
        pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
        severity: 'CRITICAL',
        category: 'CWE-321 - Private Key in Source Code',
        fix: 'Remove the private key from source; store in a secrets manager or key vault',
    },
    {
        name: 'Hardcoded Bearer token',
        pattern: /["']Bearer\s+[A-Za-z0-9._\-]{20,}["']/g,
        severity: 'HIGH',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Do not hardcode tokens; fetch them at runtime and store securely',
    },
    {
        name: 'Hardcoded DB connection string',
        pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^\s"'`]*:[^\s"'`@]+@[^\s"'`]+/gi,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded DB Credentials',
        fix: 'Move the connection string (with password) to an environment variable',
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
    {
        name: 'Command execution with user input',
        pattern: /(?:exec|execSync|spawn|system|popen|os\.system|child_process)\s*\([^)]*(?:req\.|request\.|params\.|body\.|input)/gi,
        severity: 'CRITICAL',
        category: 'CWE-78 - OS Command Injection',
        fix: 'Avoid shell execution with user input; use execFile with an argument array and validate input',
    },
    {
        name: 'Insecure HTTP URL (cleartext)',
        pattern: /["']http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-z0-9.-]+/gi,
        severity: 'HIGH',
        category: 'CWE-319 - Cleartext Transmission',
        fix: 'Use https:// — cleartext HTTP exposes data and tokens to network interception',
    },
    {
        name: 'TLS certificate verification disabled',
        pattern: /(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false)|InsecureSkipVerify\s*:\s*true)/gi,
        severity: 'HIGH',
        category: 'CWE-295 - Improper Certificate Validation',
        fix: 'Never disable TLS verification in production; fix the root certificate issue instead',
    },
    {
        name: 'Eval of dynamic input',
        pattern: /\beval\s*\([^)]*(?:req\.|request\.|params\.|body\.|input|user)/gi,
        severity: 'CRITICAL',
        category: 'CWE-95 - Code Injection via eval()',
        fix: 'Never eval() user input; use JSON.parse or a safe parser instead',
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
                kind:       'hardcoded-key',
                message:    `${name} detected: "${value}…" — never commit credentials to source code`,
                severity,
                category,
                range:      rangeOf(m, text),
                value:      m[1] || m[0],
                fix,
                compliance: getCompliance(category),
            });
        }
    }

    // Check for hardcoded URLs
    for (const { pattern, severity, category } of URL_PATTERNS) {
        pattern.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = pattern.exec(text)) !== null) {
            findings.push({
                kind:       category.includes('Endpoint') ? 'endpoint' : 'hardcoded-url',
                message:    `Hardcoded URL: ${m[0].slice(0, 60)}`,
                severity,
                category,
                range:      rangeOf(m, text),
                value:      m[0],
                compliance: getCompliance(category),
            });
        }
    }

    // Check for weak authentication patterns
    for (const { name, pattern, severity, category, fix } of WEAK_AUTH_PATTERNS) {
        pattern.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = pattern.exec(text)) !== null) {
            findings.push({
                kind:       'weak-auth',
                message:    `${name}: ${m[0].slice(0, 60)}`,
                severity,
                category,
                range:      rangeOf(m, text),
                fix,
                compliance: getCompliance(category),
            });
        }
    }

    // Check for PII patterns hardcoded in source (email regex, SSN regex, CC pattern, phone)
    const PII_CODE_PATTERNS: { name: string; pattern: RegExp; fix: string }[] = [
        { name: 'Hardcoded email address',      pattern: /["']([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']/g,  fix: 'Remove hardcoded emails; load from env or config' },
        { name: 'Hardcoded credit card number', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g, fix: 'Never hardcode card numbers; use tokenisation' },
        { name: 'Hardcoded SSN',                pattern: /\b\d{3}-\d{2}-\d{4}\b/g,                                           fix: 'Remove SSN from source code' },
        { name: 'Hardcoded password (plain)',   pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'](?!x{3})[^"']{6,}["']/gi,     fix: 'Never hardcode passwords; load from secrets manager' },
    ];
    const PII_CATEGORY = 'CWE-312 - PII / Sensitive Data Pattern in Code';
    for (const { name, pattern, fix } of PII_CODE_PATTERNS) {
        pattern.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = pattern.exec(text)) !== null) {
            findings.push({
                kind:       'pii',
                message:    `${name}: ${m[0].slice(0, 50)} — PII must not be hardcoded in source`,
                severity:   'HIGH',
                category:   PII_CATEGORY,
                range:      rangeOf(m, text),
                value:      m[0],
                fix,
                compliance: getCompliance(PII_CATEGORY),
            });
        }
    }

    return findings;
}
