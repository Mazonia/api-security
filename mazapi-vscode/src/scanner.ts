import * as vscode from 'vscode';

export type FindingKind = 'hardcoded-key' | 'hardcoded-url' | 'endpoint' | 'weak-auth' | 'pii';

export interface Compliance {
    pci_dss?:  string[];
    gdpr?:     string[];
    iso27001?: string[];
}

export interface ScanFinding {
    kind:         FindingKind;
    message:      string;
    label?:       string;        // Human-readable pattern name e.g. "Google API Key"
    service?:     string;        // Identified service e.g. "Google Cloud / Firebase"
    maskedValue?: string;        // Partially masked key e.g. "AIzaSy****5kXZ"
    severity:     'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    category:     string;
    range?:       vscode.Range;
    uri?:         vscode.Uri;    // Source file URI for navigation
    value?:       string;
    fix?:         string;
    compliance?:  Compliance;
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

// ── Helper: mask a raw key value for safe display ────────────────────────────

function maskKey(raw: string): string {
    const s = raw.replace(/^["'\s]+|["'\s]+$/g, '');
    if (s.length <= 10) return s.slice(0, 3) + '****';
    if (s.length <= 20) return s.slice(0, 6) + '****' + s.slice(-3);
    return s.slice(0, 8) + '****' + s.slice(-4);
}

// ── Pattern definitions ───────────────────────────────────────────────────────
// Ordered most-specific first so overlapping prefixes (sk-ant vs sk-) match correctly.

const KEY_PATTERNS: {
    name: string; service: string; pattern: RegExp;
    severity: 'CRITICAL' | 'HIGH'; category: string; fix: string;
}[] = [
    {
        name: 'Anthropic / Claude API Key',
        service: 'Anthropic (Claude AI)',
        pattern: /sk-ant-(?:api03|admin)-[A-Za-z0-9_-]{90,}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Revoke at console.anthropic.com/settings/keys, load from environment variable',
    },
    {
        name: 'OpenAI Project API Key',
        service: 'OpenAI',
        pattern: /sk-proj-[A-Za-z0-9_-]{40,}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Revoke at platform.openai.com/api-keys, use OPENAI_API_KEY env var',
    },
    {
        name: 'OpenAI API Key',
        service: 'OpenAI',
        pattern: /sk-[A-Za-z0-9]{48}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Revoke at platform.openai.com/api-keys, use OPENAI_API_KEY env var',
    },
    {
        name: 'Stripe Live Secret Key',
        service: 'Stripe (Live — billing live data)',
        pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Roll immediately in Stripe Dashboard > Developers > API keys',
    },
    {
        name: 'Stripe Test Secret Key',
        service: 'Stripe (Test)',
        pattern: /sk_test_[0-9a-zA-Z]{24,}/g,
        severity: 'HIGH',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Move to .env even for test keys — they enable account enumeration',
    },
    {
        name: 'Stripe Restricted Key (Live)',
        service: 'Stripe (Live — restricted)',
        pattern: /rk_live_[0-9a-zA-Z]{24,}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Roll immediately in Stripe Dashboard > Developers > Restricted keys',
    },
    {
        name: 'Google API Key',
        service: 'Google Cloud / Firebase / Maps / YouTube',
        pattern: /AIza[0-9A-Za-z_-]{35}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Restrict key in Google Cloud Console and store in environment variable',
    },
    {
        name: 'GitHub Personal Access Token',
        service: 'GitHub',
        pattern: /ghp_[A-Za-z0-9]{36}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Revoke immediately at github.com/settings/tokens, use GITHUB_TOKEN env var',
    },
    {
        name: 'GitHub App / Installation Token',
        service: 'GitHub Apps',
        pattern: /(?:ghs|ghu)_[A-Za-z0-9]{36}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'These expire but must not be committed — rotate and use secrets storage',
    },
    {
        name: 'GitLab Personal Access Token',
        service: 'GitLab',
        pattern: /glpat-[A-Za-z0-9_-]{20}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Revoke at gitlab.com/-/user_settings/personal_access_tokens, use env var',
    },
    {
        name: 'AWS Access Key ID',
        service: 'Amazon Web Services (AWS)',
        pattern: /AKIA[0-9A-Z]{16}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials / CVE-2021-22967 class',
        fix: 'Deactivate in AWS IAM > Security credentials immediately; use IAM roles',
    },
    {
        name: 'Slack Bot/App Token',
        service: 'Slack',
        pattern: /xox[baprs]-[0-9A-Za-z-]{10,48}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Revoke at api.slack.com/apps, store in environment variable',
    },
    {
        name: 'SendGrid API Key',
        service: 'SendGrid / Twilio Email',
        pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Delete and regenerate at app.sendgrid.com/settings/api_keys',
    },
    {
        name: 'Twilio API Key SID',
        service: 'Twilio',
        pattern: /SK[0-9a-fA-F]{32}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Revoke in Twilio console at console.twilio.com/user/api-keys',
    },
    {
        name: 'Hugging Face API Token',
        service: 'Hugging Face',
        pattern: /hf_[A-Za-z0-9]{34}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Revoke at huggingface.co/settings/tokens, use HF_TOKEN env var',
    },
    {
        name: 'Mapbox API Token',
        service: 'Mapbox',
        pattern: /pk\.eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+/g,
        severity: 'HIGH',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Restrict token scope and origin in Mapbox account settings',
    },
    {
        name: 'Notion Integration Secret',
        service: 'Notion',
        pattern: /secret_[A-Za-z0-9]{43}/g,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Revoke at notion.so/my-integrations and store in environment variable',
    },
    {
        name: 'Private Key block',
        service: 'SSH / TLS / Code Signing',
        pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
        severity: 'CRITICAL',
        category: 'CWE-321 - Private Key in Source Code',
        fix: 'Remove the private key from source; store in a secrets manager or key vault',
    },
    {
        name: 'JWT Hardcoded Secret',
        service: 'JWT / Auth Middleware',
        pattern: /(?:jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*["']([^"']{4,60})["']/gi,
        severity: 'CRITICAL',
        category: 'CVE-2019-9599 class / CWE-321 - Hardcoded Cryptographic Key',
        fix: 'Generate a strong random secret (openssl rand -hex 32) and load from environment',
    },
    {
        name: 'Hardcoded DB connection string',
        service: 'Database (credentials embedded)',
        pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^\s"'`]*:[^\s"'`@]+@[^\s"'`]+/gi,
        severity: 'CRITICAL',
        category: 'CWE-798 - Hardcoded DB Credentials',
        fix: 'Move the connection string (with password) to an environment variable',
    },
    {
        name: 'Hardcoded Bearer Token',
        service: 'HTTP Authorization',
        pattern: /["']Bearer\s+[A-Za-z0-9._\-]{20,}["']/g,
        severity: 'HIGH',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Do not hardcode tokens; fetch them at runtime and store securely',
    },
    {
        name: 'Generic API Key / Token',
        service: 'Unknown service',
        pattern: /(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([A-Za-z0-9._\-]{20,80})["']/gi,
        severity: 'HIGH',
        category: 'CWE-798 - Hardcoded Credentials',
        fix: 'Extract to environment variable or secrets manager',
    },
];

const URL_PATTERNS: { pattern: RegExp; severity: 'MEDIUM' | 'LOW'; category: string }[] = [
    {
        // localhost / loopback endpoints hardcoded in source (informational — endpoints tree only)
        pattern: /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d+(?:\/[^\s"'`)\]]*)?/g,
        severity: 'LOW',
        category: 'Hardcoded Internal Endpoint (localhost)',
    },
    {
        // External URLs with a path — must have a real registered domain (at least one dot),
        // excluding SVG/XML namespaces, test/example domains, and template placeholders
        pattern: /https?:\/\/(?!(?:www\.w3\.org|schemas\.|json-schema\.org|xmlns|schema\.org|openapi\.org))(?:[a-z0-9][a-z0-9-]*\.)+[a-z]{2,}(?::\d+)?\/(?!\{)[^\s"'`)\]]{4,}/g,
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
        // Only flag when code ACCEPTS none as a valid algorithm in jwt.decode/verify — not test payloads
        name: 'JWT alg:none accepted as valid algorithm',
        pattern: /algorithms?\s*=\s*\[?\s*["']none["']/gi,
        severity: 'CRITICAL',
        category: 'CVE-2015-9235 - JWT Algorithm None Bypass',
        fix: 'Remove "none" from the accepted algorithms list. Reject any token where alg=none.',
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
        // Only flag cleartext HTTP to real external domains (must have TLD, exclude test/example
        // domains, Docker internal hostnames, XML/SVG namespaces, and loopback addresses)
        name: 'Insecure HTTP URL to external service (cleartext)',
        pattern: /["']http:\/\/(?!(?:localhost|127\.|0\.0\.0\.0|www\.w3\.org|schemas\.|xmlns))(?:[a-z0-9][a-z0-9-]*\.)+(?!(?:example|test|invalid|local|internal|localhost)\b)[a-z]{2,}(?:[:/][^\s"'`]*)?["']/gi,
        severity: 'HIGH',
        category: 'CWE-319 - Cleartext Transmission',
        fix: 'Use https:// — cleartext HTTP exposes data and credentials to network interception',
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

// Files that are security testing infrastructure, scanners, report generators,
// or third-party vendor / minified files — skip soft heuristic patterns there
function isSecurityToolingFile(fsPath: string): boolean {
    const p = fsPath.replace(/\\/g, '/');
    return /(?:owasp_tests\/|testing.engine\/|generate_report\.py|report_generator\.py|demo\.py|evaluate\.py|\.claude\/|monitoring\/main\.py|\/test_[a-z]|_test\.py|\.min\.[jt]s$|\/static\/[^/]+\.js$|\/vendor\/)/i.test(p);
}

// Pure config/env files — scan for real secrets but skip URL-as-endpoint heuristics
// (these files legitimately contain URLs as configuration values, not hardcoded API calls)
function isConfigFile(fsPath: string): boolean {
    const p = fsPath.replace(/\\/g, '/');
    return /(?:\.env$|\.env\.|settings\.(?:json|local\.json)|docker-compose|\.gitignore|\.claudeignore|package-lock\.json)/i.test(p);
}

// Lines that are clearly inside HTML/XML template strings — skip credential pattern there
function isHtmlTemplateLine(line: string): boolean {
    return /^\s*<[a-zA-Z]/.test(line) || />\s*(?:SECRET_KEY|PASSWORD|TOKEN)\s*=/.test(line);
}

export function scanFileForIssues(
    text: string,
    langId: string,
    uri: vscode.Uri
): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const lines = text.split('\n');
    const isTooling  = isSecurityToolingFile(uri.fsPath);
    const isConfig   = isConfigFile(uri.fsPath);

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

    // Check for hardcoded API keys / secrets (run on all files including tooling)
    for (const { name, service, pattern, severity, category, fix } of KEY_PATTERNS) {
        pattern.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = pattern.exec(text)) !== null) {
            const line = lines[rangeOf(m, text).start.line] || '';
            // Skip matches inside HTML template strings (educational code examples in report generators)
            if (isHtmlTemplateLine(line)) continue;
            const rawVal = m[1] || m[0];
            findings.push({
                kind:         'hardcoded-key',
                message:      `${name} detected — service: ${service}`,
                label:        name,
                service,
                maskedValue:  maskKey(rawVal),
                severity,
                category,
                range:        rangeOf(m, text),
                uri,
                value:        rawVal,
                fix,
                compliance:   getCompliance(category),
            });
        }
    }

    // Check for hardcoded URLs — skip in security-tooling files and pure config files
    if (!isTooling && !isConfig) {
        for (const { pattern, severity, category } of URL_PATTERNS) {
            pattern.lastIndex = 0;
            let m: RegExpExecArray | null;
            while ((m = pattern.exec(text)) !== null) {
                // Skip test/example domains and known infrastructure/schema registries
                if (/(?:example\.com|evil\.com|attacker\.|test\.(?:com|org|net)|foo\.com|bar\.com|schemastore\.org|getpostman\.com|npmjs\.org|slack\.com|github\.com|githubusercontent\.com|shields\.io|owasp\.org)/i.test(m[0])) continue;
                findings.push({
                    kind:       category.toLowerCase().includes('endpoint') ? 'endpoint' : 'hardcoded-url',
                    message:    `Hardcoded URL: ${m[0].slice(0, 70)}`,
                    label:      m[0].slice(0, 60),
                    severity,
                    category,
                    range:      rangeOf(m, text),
                    uri,
                    value:      m[0],
                    compliance: getCompliance(category),
                });
            }
        }
    }

    // Check for weak authentication patterns — skip in security-tooling files
    if (!isTooling) {
        for (const { name, pattern, severity, category, fix } of WEAK_AUTH_PATTERNS) {
            pattern.lastIndex = 0;
            let m: RegExpExecArray | null;
            while ((m = pattern.exec(text)) !== null) {
                const line = lines[rangeOf(m, text).start.line] || '';
                // Skip lines that are inside HTML template strings or comment-only lines
                if (isHtmlTemplateLine(line)) continue;
                if (/^\s*#/.test(line) || /^\s*\/\//.test(line)) continue;
                findings.push({
                    kind:       'weak-auth',
                    message:    `${name}: ${m[0].slice(0, 70)}`,
                    label:      name,
                    severity,
                    category,
                    range:      rangeOf(m, text),
                    uri,
                    fix,
                    compliance: getCompliance(category),
                });
            }
        }
    }

    // Check for PII patterns hardcoded in source (email regex, SSN regex, CC pattern, phone)
    const PII_CODE_PATTERNS: { name: string; pattern: RegExp; fix: string }[] = [
        {
            // Real emails only: local part ≥4 chars, exclude placeholder/example/test domains
            name: 'Hardcoded email address',
            pattern: /["']([a-zA-Z0-9._%+\-]{4,}@(?!(?:example|test|placeholder|domain|sample|foo|bar|acme|localhost|corp)\.)[a-zA-Z0-9\-]+\.[a-zA-Z]{2,})["']/g,
            fix: 'Remove hardcoded emails; load from env or config',
        },
        {
            name: 'Hardcoded credit card number',
            pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g,
            fix: 'Never hardcode card numbers; use tokenisation',
        },
        {
            name: 'Hardcoded SSN',
            pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
            fix: 'Remove SSN from source code',
        },
        {
            // Must be a real-looking password (not a probe/test placeholder like "x" or "pass")
            name: 'Hardcoded password (plain)',
            pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'](?!(?:x{1,3}|pass|test|demo|sample|placeholder)["'])[^"']{8,}["']/gi,
            fix: 'Never hardcode passwords; load from secrets manager',
        },
    ];
    const PII_CATEGORY = 'CWE-312 - PII / Sensitive Data Pattern in Code';
    for (const { name, pattern, fix } of (isTooling ? [] : PII_CODE_PATTERNS)) {
        pattern.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = pattern.exec(text)) !== null) {
            findings.push({
                kind:       'pii',
                message:    `${name}: ${m[0].slice(0, 50)} — PII must not be hardcoded in source`,
                label:      name,
                severity:   'HIGH',
                category:   PII_CATEGORY,
                range:      rangeOf(m, text),
                uri,
                value:      m[0],
                fix,
                compliance: getCompliance(PII_CATEGORY),
            });
        }
    }

    return findings;
}
