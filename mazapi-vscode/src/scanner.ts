import * as vscode from 'vscode';

export type FindingKind = 'hardcoded-key' | 'hardcoded-url' | 'endpoint' | 'weak-auth' | 'pii';

export interface Compliance {
    pci_dss?: string[];
    gdpr?: string[];
    iso27001?: string[];
}

export interface ScanFinding {
    kind: FindingKind;
    message: string;
    label?: string;        // Human-readable pattern name e.g. "Google API Key"
    service?: string;        // Identified service e.g. "Google Cloud / Firebase"
    maskedValue?: string;        // Partially masked key e.g. "AIzaSy****5kXZ"
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    category: string;
    range?: vscode.Range;
    uri?: vscode.Uri;    // Source file URI for navigation
    value?: string;
    fix?: string;
    compliance?: Compliance;
    isGitignoredEnv?: boolean;
}

const COMPLIANCE_MAP: Record<string, Compliance> = {
    'CWE-798 - Hardcoded Credentials': { pci_dss: ['8.2.1', '6.2.4'], gdpr: ['Art. 32(1)(b)'], iso27001: ['A.9.4.3', 'A.10.1.1'] },
    'CWE-321 - Hardcoded Cryptographic Key': { pci_dss: ['8.2.1', '6.2.4'], gdpr: ['Art. 32(1)(b)'], iso27001: ['A.10.1.1', 'A.9.4.3'] },
    'CWE-321 - Private Key in Source Code': { pci_dss: ['8.2.1'], gdpr: ['Art. 32'], iso27001: ['A.10.1.1'] },
    'CWE-798 - Hardcoded DB Credentials': { pci_dss: ['8.2.1', '2.2.7'], gdpr: ['Art. 32'], iso27001: ['A.9.4.3'] },
    'CVE-2019-9599 class / CWE-321 - Hardcoded Cryptographic Key': { pci_dss: ['8.2.1'], gdpr: ['Art. 32'], iso27001: ['A.10.1.1'] },
    'CVE-2015-9235 - JWT Algorithm None Bypass': { pci_dss: ['8.2.1', '6.2.4'], gdpr: ['Art. 32(1)(b)'], iso27001: ['A.9.4.3'] },
    'CWE-327 - Weak Cryptographic Algorithm (MD5)': { pci_dss: ['4.2.1', '8.3.2'], gdpr: ['Art. 32(1)(a)'], iso27001: ['A.10.1.1'] },
    'CWE-327 - Weak Cryptographic Algorithm (SHA-1)': { pci_dss: ['4.2.1', '8.3.2'], gdpr: ['Art. 32(1)(a)'], iso27001: ['A.10.1.1'] },
    'CWE-521 - Weak Password Requirements': { pci_dss: ['8.3.6'], gdpr: ['Art. 32'], iso27001: ['A.9.4.3'] },
    'CVE-2019-14234 class / CWE-89 - SQL Injection': { pci_dss: ['6.2.4'], gdpr: ['Art. 32'], iso27001: ['A.14.2.5'] },
    'CWE-78 - OS Command Injection': { pci_dss: ['6.2.4'], gdpr: ['Art. 32'], iso27001: ['A.14.2.5'] },
    'CWE-319 - Cleartext Transmission': { pci_dss: ['4.2.1'], gdpr: ['Art. 32(1)(a)'], iso27001: ['A.13.2.3'] },
    'CWE-295 - Improper Certificate Validation': { pci_dss: ['4.2.1'], gdpr: ['Art. 32(1)(a)'], iso27001: ['A.13.2.3'] },
    'CWE-95 - Code Injection via eval()': { pci_dss: ['6.2.4'], gdpr: ['Art. 32'], iso27001: ['A.14.2.5'] },
    'CWE-312 - PII / Sensitive Data Pattern in Code': { pci_dss: ['3.4.1', '4.2.1'], gdpr: ['Art. 5', 'Art. 25', 'Art. 32'], iso27001: ['A.18.1.4', 'A.8.2.3'] },
    'CWE-942 / API8:2023 - CORS Wildcard Misconfiguration': { pci_dss: ['6.2.4'], gdpr: ['Art. 32'], iso27001: ['A.14.2.5', 'A.13.1.3'] },
    'CWE-532 - Sensitive Data in Application Logs': { pci_dss: ['3.4.1', '10.3.3'], gdpr: ['Art. 5(1)(f)', 'Art. 32'], iso27001: ['A.12.4.1', 'A.18.1.3'] },
    'CWE-502 - Insecure Deserialization': { pci_dss: ['6.2.4'], gdpr: ['Art. 32'], iso27001: ['A.14.2.5'] },
    'CWE-611 - XML External Entity (XXE) Injection': { pci_dss: ['6.2.4'], gdpr: ['Art. 32'], iso27001: ['A.14.2.5'] },
    'CWE-918 - Server-Side Request Forgery (SSRF)': { pci_dss: ['6.2.4', '6.3.3'], gdpr: ['Art. 32'], iso27001: ['A.13.1.3', 'A.14.2.5'] },
    'CWE-338 - Insecure Randomness for Security': { pci_dss: ['6.2.4', '8.3.2'], gdpr: ['Art. 32(1)(a)'], iso27001: ['A.10.1.1'] },
    'CWE-22 - Path Traversal via User Input': { pci_dss: ['6.2.4'], gdpr: ['Art. 32'], iso27001: ['A.14.2.5'] },
    'CWE-915 - Mass Assignment': { pci_dss: ['6.2.4'], gdpr: ['Art. 5(1)(c)', 'Art. 25'], iso27001: ['A.14.2.5'] },
    'CWE-94 / API8:2023 - Debug Mode in Production': { pci_dss: ['6.3.3', '2.2.7'], gdpr: ['Art. 32'], iso27001: ['A.12.1.4', 'A.14.1.3'] },
    'CWE-209 - Stack Trace / Verbose Error in Response': { pci_dss: ['6.2.4'], gdpr: ['Art. 32'], iso27001: ['A.14.2.5', 'A.12.4.1'] },
    'CWE-1321 - Prototype Pollution': { pci_dss: ['6.2.4'], gdpr: ['Art. 32'], iso27001: ['A.14.2.5'] },
    'API9:2023 - GraphQL Introspection Enabled': { pci_dss: ['6.3.3'], gdpr: ['Art. 32'], iso27001: ['A.12.6.1', 'A.14.1.3'] },
    'CWE-614 - Cookie Missing Secure / HttpOnly Flag': { pci_dss: ['6.2.4', '8.3.1'], gdpr: ['Art. 32'], iso27001: ['A.9.4.2', 'A.14.2.5'] },
    'CWE-312 - Sensitive Token in Browser Storage': { pci_dss: ['3.4.1'], gdpr: ['Art. 32'], iso27001: ['A.9.4.2', 'A.18.1.3'] },
    'API8:2023 - Unauthenticated Operational Endpoint': { pci_dss: ['6.3.3', '2.2.7'], gdpr: ['Art. 32'], iso27001: ['A.12.6.1', 'A.13.1.3'] },
    'CWE-1188 - Security Control Gated by Environment': { pci_dss: ['6.3.3'], gdpr: ['Art. 32'], iso27001: ['A.14.1.3', 'A.12.1.4'] },
    'CWE-208 - Timing Attack via Non-Constant-Time Comparison': { pci_dss: ['8.3.2'], gdpr: ['Art. 32(1)(a)'], iso27001: ['A.10.1.1', 'A.14.2.5'] },
    'API4:2023 - Auth Route Missing Rate Limiting': { pci_dss: ['8.3.4', '6.3.1'], gdpr: ['Art. 32'], iso27001: ['A.9.4.2', 'A.12.6.1'] },
    'API9:2023 - Multiple API Versions Without Deprecation': { pci_dss: ['6.3.3'], gdpr: ['Art. 32'], iso27001: ['A.12.6.1', 'A.8.1.1'] },
    'AI-BOM - LLM SDK / Call Site': { pci_dss: ['6.2.4'], gdpr: ['Art. 25', 'Art. 32'], iso27001: ['A.14.2.5'] },
    'AI-BOM - AI Agent Framework (LangChain/CrewAI)': { pci_dss: ['6.2.4'], gdpr: ['Art. 25', 'Art. 32'], iso27001: ['A.14.2.5'] },
    'AI-BOM - Model Context Protocol (MCP) Server Configuration': { pci_dss: ['6.2.4'], gdpr: ['Art. 25', 'Art. 32'], iso27001: ['A.14.2.5'] },
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

// ── Service discovery: examine surrounding context for service name keywords ──

const SERVICE_HINTS: [RegExp, string][] = [
    [/paystack/i, 'Paystack'],
    [/hubtel/i, 'Hubtel'],
    [/flutterwave/i, 'Flutterwave'],
    [/africastalking|africa[_-]?talk/i, "Africa's Talking"],
    [/mtn[_-]?momo|momoapi|mtn[_-]?open/i, 'MTN Mobile Money (MoMo)'],
    [/vodafone[_-]?(?:ghana|cash)|vodacash/i, 'Vodafone Ghana / VodaCash'],
    [/airteltigo|airtel[_-]?ghana/i, 'AirtelTigo Ghana'],
    [/interswitch/i, 'Interswitch'],
    [/openai/i, 'OpenAI'],
    [/anthropic|claude[_-]?api/i, 'Anthropic (Claude AI)'],
    [/groq/i, 'Groq'],
    [/perplexity/i, 'Perplexity AI'],
    [/openrouter/i, 'OpenRouter'],
    [/replicate/i, 'Replicate'],
    [/cohere/i, 'Cohere'],
    [/mistral/i, 'Mistral AI'],
    [/elevenlabs|xi[_-]?api/i, 'ElevenLabs'],
    [/together[_-]?ai/i, 'Together AI'],
    [/deepgram/i, 'Deepgram'],
    [/assemblyai/i, 'AssemblyAI'],
    [/google|firebase|gcp|googleapis/i, 'Google Cloud / Firebase'],
    [/aws|amazon[_-]?(?:web|s3|ec2|lambda|bedrock)/i, 'Amazon Web Services (AWS)'],
    [/azure|microsoft[_-]?(?:cognitive|openai)/i, 'Microsoft Azure'],
    [/digitalocean|do[_-]?token/i, 'DigitalOcean'],
    [/vercel/i, 'Vercel'],
    [/cloudflare/i, 'Cloudflare'],
    [/fly[_-]?(?:io|token)/i, 'Fly.io'],
    [/render[_-]?(?:api|token)/i, 'Render'],
    [/railway/i, 'Railway'],
    [/stripe/i, 'Stripe'],
    [/paypal/i, 'PayPal'],
    [/braintree/i, 'Braintree'],
    [/square/i, 'Square'],
    [/razorpay/i, 'Razorpay'],
    [/flutterwave/i, 'Flutterwave'],
    [/twilio/i, 'Twilio'],
    [/sendgrid/i, 'SendGrid'],
    [/mailchimp/i, 'Mailchimp'],
    [/mailgun/i, 'Mailgun'],
    [/brevo|sendinblue/i, 'Brevo (Sendinblue)'],
    [/postmark/i, 'Postmark'],
    [/resend/i, 'Resend'],
    [/sparkpost/i, 'SparkPost'],
    [/elastic[_-]?(?:email|search)/i, 'Elastic Email / Elasticsearch'],
    [/slack/i, 'Slack'],
    [/telegram/i, 'Telegram'],
    [/discord/i, 'Discord'],
    [/twitter|x[_-]?(?:api|bearer)|bearer[_-]?token/i, 'Twitter / X'],
    [/facebook|meta[_-]?(?:api|access)/i, 'Meta / Facebook'],
    [/instagram/i, 'Instagram'],
    [/linkedin/i, 'LinkedIn'],
    [/github/i, 'GitHub'],
    [/gitlab/i, 'GitLab'],
    [/bitbucket/i, 'Bitbucket'],
    [/newrelic|new[_-]?relic/i, 'New Relic'],
    [/posthog/i, 'PostHog'],
    [/datadog/i, 'Datadog'],
    [/sentry/i, 'Sentry'],
    [/mixpanel/i, 'Mixpanel'],
    [/amplitude/i, 'Amplitude'],
    [/segment/i, 'Segment'],
    [/loggly/i, 'Loggly'],
    [/papertrail/i, 'Papertrail'],
    [/splunk/i, 'Splunk'],
    [/huggingface|hf[_-]?token/i, 'Hugging Face'],
    [/mapbox/i, 'Mapbox'],
    [/notion/i, 'Notion'],
    [/airtable/i, 'Airtable'],
    [/contentful/i, 'Contentful'],
    [/hubspot/i, 'HubSpot'],
    [/salesforce/i, 'Salesforce'],
    [/zendesk/i, 'Zendesk'],
    [/freshdesk/i, 'Freshdesk'],
    [/intercom/i, 'Intercom'],
    [/shopify/i, 'Shopify'],
    [/woocommerce|woo[_-]?commerce/i, 'WooCommerce'],
    [/supabase/i, 'Supabase'],
    [/planetscale/i, 'PlanetScale'],
    [/neon[_-]?(?:db|postgres)/i, 'Neon (Postgres)'],
    [/cloudinary/i, 'Cloudinary'],
    [/imgix/i, 'Imgix'],
    [/shodan/i, 'Shodan'],
    [/pagerduty/i, 'PagerDuty'],
    [/okta/i, 'Okta'],
    [/auth0/i, 'Auth0'],
    [/keycloak/i, 'Keycloak'],
    [/npm[_-]?token/i, 'npm'],
    [/pypi/i, 'PyPI'],
    [/jwt[_-]?secret|secret[_-]?key/i, 'JWT / Auth Middleware'],
    [/vonage|nexmo/i, 'Vonage (Nexmo)'],
    [/messagebird/i, 'MessageBird'],
    [/infobip/i, 'Infobip'],
    [/plaid/i, 'Plaid'],
    [/yoti/i, 'Yoti'],
    [/smile[_-]?id|smileidentity/i, 'Smile Identity'],
    [/paysimple/i, 'PaySimple'],
    [/expensify/i, 'Expensify'],
    [/algolia/i, 'Algolia'],
    [/typesense/i, 'Typesense'],
    [/pinecone/i, 'Pinecone'],
    [/weaviate/i, 'Weaviate'],
    [/qdrant/i, 'Qdrant'],
    [/pusher/i, 'Pusher'],
    [/ably/i, 'Ably'],
    [/livekit/i, 'LiveKit'],
    [/agora/i, 'Agora'],
    [/daily[_-]?(?:co|api)/i, 'Daily.co'],
    [/deepl/i, 'DeepL'],
    [/weather[_-]?api|openweather/i, 'OpenWeatherMap'],
    [/exchange[_-]?(?:rate|api)|fixer[_-]?io/i, 'Exchange Rate / Fixer.io'],
];

function discoverService(contextText: string): string | null {
    for (const [re, svc] of SERVICE_HINTS) {
        if (re.test(contextText)) return svc;
    }
    return null;
}

// ── Pattern definitions ───────────────────────────────────────────────────────
// Ordered most-specific first so overlapping prefixes (sk-ant vs sk-) match correctly.

const KEY_PATTERNS: {
    name: string; service: string; pattern: RegExp;
    severity: 'CRITICAL' | 'HIGH'; category: string; fix: string;
    useDiscovery?: boolean;
}[] = [
        // ── African payment services ──────────────────────────────────────────────
        {
            name: 'Paystack Secret Key',
            service: 'Paystack',
            // Paystack secret keys share Stripe's sk_(live|test)_ shape, so we disambiguate by
            // requiring the word "paystack" in the variable name / nearby context. Quotes are
            // optional (dotenv files are unquoted). This runs BEFORE the generic Stripe pattern
            // so a PAYSTACK_SECRET_KEY=sk_live_… line is labelled Paystack, not Stripe.
            pattern: /paystack[_a-z]*\s*[:=]\s*["'`]?(sk_(?:live|test)_[A-Za-z0-9]{20,})["'`]?/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at dashboard.paystack.com > Settings > API Keys, use PAYSTACK_SECRET_KEY env var',
        },
        {
            name: 'Stripe / Paystack Publishable Key',
            service: 'Stripe or Paystack',
            pattern: /pk_(?:live|test)_[A-Za-z0-9]{20,}/g,
            severity: 'HIGH',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Publishable keys are lower risk but should be restricted: Stripe — allowed domains in Dashboard; Paystack — allowed domains in Settings',
            useDiscovery: true,
        },
        {
            name: 'Hubtel API Credentials',
            service: 'Hubtel',
            pattern: /(?:hubtel[_-]?(?:client[_-]?(?:id|secret)|api[_-]?key|secret))\s*[:=]\s*["']([A-Za-z0-9._-]{10,80})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at hubtel.com developer portal and move to environment variable',
        },
        {
            name: 'Flutterwave Live Secret Key',
            service: 'Flutterwave',
            pattern: /FLWSECK-[A-Za-z0-9-]{40,}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Roll key at dashboard.flutterwave.com > Settings > API Keys immediately',
        },
        {
            name: 'Flutterwave Test Secret Key',
            service: 'Flutterwave',
            pattern: /FLWSECK_TEST-[A-Za-z0-9-]{40,}/g,
            severity: 'HIGH',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Move test key to environment variable; do not commit to source control',
        },
        {
            name: "Africa's Talking API Key",
            service: "Africa's Talking",
            pattern: /(?:africastalking|at[_-]?api[_-]?key)\s*[:=]\s*["']([A-Za-z0-9._+\-]{10,80})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: "Revoke at account.africastalking.com, use AT_API_KEY env var",
        },
        {
            name: 'MTN MoMo API Credentials',
            service: 'MTN Mobile Money (MoMo)',
            pattern: /(?:mtn[_-]?momo|momoapi|mtn[_-]?(?:subscription[_-]?key|api[_-]?key))\s*[:=]\s*["']([A-Za-z0-9._\-]{10,80})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at momodeveloper.mtn.com, load from environment variable',
        },
        {
            name: 'Vodafone Ghana API Key',
            service: 'Vodafone Ghana / VodaCash',
            pattern: /(?:vodafone[_-]?(?:ghana|cash|api)[_-]?(?:key|secret|token))\s*[:=]\s*["']([A-Za-z0-9._\-]{10,80})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke key via Vodafone Ghana developer portal and use environment variable',
        },
        {
            name: 'Interswitch API Credentials',
            service: 'Interswitch',
            pattern: /(?:interswitch[_-]?(?:client[_-]?(?:id|secret)|api[_-]?key))\s*[:=]\s*["']([A-Za-z0-9._\-]{10,80})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at developer.interswitch.com and store in environment variable',
        },
        // ── AI / ML services ──────────────────────────────────────────────────────
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
            // Require string-literal context — bare SK+hex32 can appear in UUIDs and test data
            pattern: /["'`](SK[0-9a-fA-F]{32})["'`]/g,
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
        // ── More AI / ML ──────────────────────────────────────────────────────────
        {
            name: 'Groq API Key',
            service: 'Groq',
            // Groq keys are gsk_ + ~52 base62, but length varies — accept 20+ to avoid misses.
            pattern: /gsk_[A-Za-z0-9]{20,}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at console.groq.com/keys and use GROQ_API_KEY env var',
        },
        {
            name: 'Resend API Key',
            service: 'Resend',
            pattern: /\bre_[A-Za-z0-9_-]{32,48}\b/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at resend.com/api-keys and use RESEND_API_KEY env var',
        },
        {
            name: 'Perplexity AI API Key',
            service: 'Perplexity AI',
            pattern: /pplx-[A-Za-z0-9]{48}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at perplexity.ai/settings/api and use PERPLEXITY_API_KEY env var',
        },
        {
            name: 'OpenRouter API Key',
            service: 'OpenRouter',
            pattern: /sk-or-v1-[A-Za-z0-9]{64}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at openrouter.ai/keys and use OPENROUTER_API_KEY env var',
        },
        {
            name: 'Replicate API Token',
            service: 'Replicate',
            pattern: /r8_[A-Za-z0-9]{37}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at replicate.com/account/api-tokens and use REPLICATE_API_TOKEN env var',
        },
        {
            name: 'ElevenLabs API Key',
            service: 'ElevenLabs',
            pattern: /(?:elevenlabs|xi[_-]?api[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-]{32})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at elevenlabs.io/app/profile/api-key and use ELEVENLABS_API_KEY env var',
        },
        {
            name: 'Deepgram API Key',
            service: 'Deepgram',
            pattern: /(?:deepgram[_-]?api[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-]{40,})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at console.deepgram.com and use DEEPGRAM_API_KEY env var',
        },
        {
            name: 'Cohere API Key',
            service: 'Cohere',
            pattern: /(?:cohere[_-]?api[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-]{40,})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at dashboard.cohere.com/api-keys and use COHERE_API_KEY env var',
        },
        // ── Cloud / hosting ───────────────────────────────────────────────────────
        {
            name: 'DigitalOcean Personal Access Token',
            service: 'DigitalOcean',
            pattern: /dop_v1_[A-Za-z0-9]{43}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at cloud.digitalocean.com/account/api/tokens and use DO_TOKEN env var',
        },
        {
            name: 'Fly.io API Token',
            service: 'Fly.io',
            pattern: /fo1_[A-Za-z0-9_\-]{43}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke with `flyctl auth token` and store in secrets',
        },
        {
            name: 'Render API Key',
            service: 'Render',
            pattern: /rnd_[A-Za-z0-9]{43}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at render.com/account and use RENDER_API_KEY env var',
        },
        {
            name: 'Cloudflare API Token',
            service: 'Cloudflare',
            pattern: /(?:cloudflare[_-]?(?:api[_-]?token|api[_-]?key))\s*[:=]\s*["']([A-Za-z0-9_\-]{40,})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at dash.cloudflare.com/profile/api-tokens and use CLOUDFLARE_API_TOKEN env var',
        },
        {
            name: 'Vercel API Token',
            service: 'Vercel',
            pattern: /(?:vercel[_-]?(?:token|api[_-]?token))\s*[:=]\s*["']([A-Za-z0-9_\-]{24,})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at vercel.com/account/tokens and use VERCEL_TOKEN env var',
        },
        // ── Email / messaging services ────────────────────────────────────────────
        {
            name: 'Mailchimp API Key',
            service: 'Mailchimp',
            // Require string context — 32-char hex can appear in MD5 hashes and other contexts
            pattern: /["'`]([0-9a-f]{32}-us\d{1,2})["'`]/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at mailchimp.com/account/api-key-popup and use MAILCHIMP_API_KEY env var',
        },
        {
            name: 'Mailgun API Key',
            service: 'Mailgun',
            // Require string context — "key-" prefix is too common without quotes
            pattern: /["'`](key-[0-9a-zA-Z]{32})["'`]/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at app.mailgun.com/settings/api_security and use MAILGUN_API_KEY env var',
        },
        {
            name: 'Brevo (Sendinblue) API Key',
            service: 'Brevo (Sendinblue)',
            pattern: /xkeysib-[A-Za-z0-9_\-]{64}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at app.brevo.com/settings/keys/api and use BREVO_API_KEY env var',
        },

        // ── Payments ──────────────────────────────────────────────────────────────
        {
            name: 'Square Access Token',
            service: 'Square',
            pattern: /EAAAl[A-Za-z0-9_\-]{60,}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at developer.squareup.com and use SQUARE_ACCESS_TOKEN env var',
        },
        {
            name: 'Square Application Key',
            service: 'Square',
            pattern: /sq0atp-[A-Za-z0-9_\-]{22}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at developer.squareup.com and use environment variable',
        },
        {
            name: 'Razorpay Live Key',
            service: 'Razorpay',
            pattern: /rzp_live_[A-Za-z0-9]{20}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at dashboard.razorpay.com/app/keys and use RAZORPAY_KEY_SECRET env var',
        },
        {
            name: 'Razorpay Test Key',
            service: 'Razorpay',
            pattern: /rzp_test_[A-Za-z0-9]{20}/g,
            severity: 'HIGH',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Move test key to environment variable; do not commit to source control',
        },
        {
            name: 'Braintree Access Token',
            service: 'Braintree (PayPal)',
            pattern: /access_token\$(?:production|sandbox)\$[A-Za-z0-9_\-]+\$[A-Za-z0-9_\-]+/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at developer.paypal.com and use BRAINTREE_ACCESS_TOKEN env var',
        },
        // ── Monitoring / analytics ────────────────────────────────────────────────
        {
            name: 'New Relic Insert / Ingest Key',
            service: 'New Relic',
            pattern: /NR(?:AK|IQ)-[A-Za-z0-9]{42}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at one.newrelic.com/admin-portal/api-keys and use NEW_RELIC_LICENSE_KEY env var',
        },
        {
            name: 'PostHog API Key',
            service: 'PostHog',
            pattern: /phc_[A-Za-z0-9]{43}/g,
            severity: 'HIGH',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Rotate at app.posthog.com/project/settings and restrict key scope',
        },
        {
            name: 'Sentry DSN',
            service: 'Sentry',
            pattern: /https:\/\/[a-f0-9]{32}@(?:[a-z0-9]+\.)?(?:ingest\.)?sentry\.io\/\d+/g,
            severity: 'HIGH',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Sentry DSNs are semi-public but rotate at sentry.io > Project Settings > Keys to limit abuse',
        },
        {
            name: 'Datadog API Key',
            service: 'Datadog',
            pattern: /(?:datadog[_-]?api[_-]?key|dd[_-]?api[_-]?key)\s*[:=]\s*["']([a-f0-9]{32})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at app.datadoghq.com/organization-settings/api-keys and use DD_API_KEY env var',
        },
        // ── Social / messaging ────────────────────────────────────────────────────
        {
            name: 'Telegram Bot Token',
            service: 'Telegram',
            // Require string context — bare digit-colon-alphanum can appear in log lines / IDs
            pattern: /["'`](\d{9,10}:[A-Za-z0-9_\-]{35})["'`]/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke via @BotFather on Telegram and use TELEGRAM_BOT_TOKEN env var',
        },
        {
            name: 'Discord Bot Token',
            service: 'Discord',
            pattern: /[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Reset at discord.com/developers/applications and use DISCORD_BOT_TOKEN env var',
        },
        {
            name: 'Twitter / X Bearer Token',
            service: 'Twitter / X',
            pattern: /AAAA[A-Za-z0-9%_\-]{80,}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at developer.twitter.com/portal and use TWITTER_BEARER_TOKEN env var',
        },
        {
            name: 'Facebook / Meta Access Token',
            service: 'Meta / Facebook',
            // Real Facebook tokens are 100+ chars; 50+ minimum avoids matching short EAA-prefixed strings
            pattern: /EAA[A-Za-z0-9]{50,}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at developers.facebook.com > Tools > Access Token Debugger',
        },
        // ── DevOps / package registries ───────────────────────────────────────────
        {
            name: 'npm Access Token',
            service: 'npm',
            pattern: /npm_[A-Za-z0-9]{36}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at npmjs.com/settings/~/tokens and use NPM_TOKEN env var',
        },
        {
            name: 'PyPI API Token',
            service: 'PyPI',
            pattern: /pypi-[A-Za-z0-9_\-]{48}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at pypi.org/manage/account/token and use PYPI_TOKEN env var',
        },
        // ── CMS / SaaS ────────────────────────────────────────────────────────────
        {
            name: 'Shopify Admin API Token',
            service: 'Shopify',
            pattern: /shp(?:at|pa|ss|ca)_[A-Za-z0-9]{32}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at Shopify admin > Apps > Manage private apps and use env var',
        },
        {
            name: 'Airtable Personal Access Token',
            service: 'Airtable',
            pattern: /pat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at airtable.com/account and use AIRTABLE_API_KEY env var',
        },
        {
            name: 'Contentful Delivery/Management Token',
            service: 'Contentful',
            pattern: /CFPAT-[A-Za-z0-9_\-]{43}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at app.contentful.com > Settings > API Keys and use env var',
        },
        {
            name: 'HubSpot Private App Token',
            service: 'HubSpot',
            pattern: /pat-(?:na1|eu1|ap[1-9])-[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at app.hubspot.com/private-apps and use HUBSPOT_ACCESS_TOKEN env var',
        },
        {
            name: 'Supabase Service Role Key',
            service: 'Supabase',
            pattern: /(?:supabase[_-]?(?:service[_-]?role[_-]?key|anon[_-]?key))\s*[:=]\s*["'](eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Service role key gives full DB access — rotate at supabase.com/dashboard/project/settings/api',
        },
        {
            name: 'Algolia Admin API Key',
            service: 'Algolia',
            pattern: /(?:algolia[_-]?admin[_-]?(?:api[_-]?)?key)\s*[:=]\s*["']([A-Za-z0-9]{32})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at algolia.com/account/api-keys; use search-only key client-side',
        },
        {
            name: 'PlanetScale Service Token',
            service: 'PlanetScale',
            pattern: /pscale_tkn_[A-Za-z0-9_\-]{43}/g,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at app.planetscale.com/~/settings/service-tokens and use env var',
        },
        {
            name: 'Cloudinary API Secret',
            service: 'Cloudinary',
            pattern: /(?:cloudinary[_-]?(?:api[_-]?secret|url))\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Rotate at cloudinary.com/console and use CLOUDINARY_URL env var',
        },
        {
            name: 'Plaid API Secret',
            service: 'Plaid',
            pattern: /(?:plaid[_-]?(?:secret|api[_-]?secret))\s*[:=]\s*["']([A-Za-z0-9]{30,})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at dashboard.plaid.com/developers/keys and use PLAID_SECRET env var',
        },
        {
            name: 'Vonage (Nexmo) API Secret',
            service: 'Vonage (Nexmo)',
            pattern: /(?:nexmo|vonage)[_-]?api[_-]?secret\s*[:=]\s*["']([A-Za-z0-9]{16})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Rotate at dashboard.nexmo.com/settings and use env var',
        },
        {
            name: 'Smile Identity API Key',
            service: 'Smile Identity',
            pattern: /(?:smile[_-]?(?:id|identity)[_-]?(?:api[_-]?key|partner[_-]?id))\s*[:=]\s*["']([A-Za-z0-9._\-]{10,80})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at portal.smileidentity.com and use environment variable',
        },
        {
            name: 'Pusher App Secret',
            service: 'Pusher',
            pattern: /(?:pusher[_-]?(?:app[_-]?)?secret)\s*[:=]\s*["']([A-Za-z0-9]{20})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Rotate at dashboard.pusher.com and use PUSHER_APP_SECRET env var',
        },
        {
            name: 'DeepL Auth Key',
            service: 'DeepL',
            pattern: /(?:deepl[_-]?(?:auth[_-]?key|api[_-]?key))\s*[:=]\s*["']([A-Za-z0-9_\-:]{30,})["']/gi,
            severity: 'CRITICAL',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Revoke at deepl.com/account/summary and use DEEPL_AUTH_KEY env var',
        },
        // ── Private key / crypto ──────────────────────────────────────────────────
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
            // secret_key covered by JWT pattern; avoid duplicate findings
            pattern: /(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([A-Za-z0-9._\-]{20,80})["']/gi,
            severity: 'HIGH',
            category: 'CWE-798 - Hardcoded Credentials',
            fix: 'Extract to environment variable or secrets manager',
            useDiscovery: true,
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

const WEAK_AUTH_PATTERNS: { name: string; pattern: RegExp; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'; category: string; fix: string }[] = [
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
    // ── New patterns ──────────────────────────────────────────────────────────
    {
        name: 'CORS wildcard configuration',
        pattern: /(?:cors\s*\(\s*(?:\{[^}]*origin\s*:\s*['"][*]['"]|['"]\*['"]\s*\))|Access-Control-Allow-Origin['":\s,]+['"]\*['"])/gi,
        severity: 'HIGH',
        category: 'CWE-942 / API8:2023 - CORS Wildcard Misconfiguration',
        fix: 'Restrict CORS to specific trusted origins; never use "*" for APIs that handle authenticated requests',
    },
    {
        name: 'Sensitive data written to logs',
        pattern: /(?:console\.(?:log|debug|info|warn|error)|logger\.(?:info|debug|warn|error|critical)|logging\.(?:info|debug|warning|error|critical)|print)\s*\([^)]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential|auth|bearer)/gi,
        severity: 'HIGH',
        category: 'CWE-532 - Sensitive Data in Application Logs',
        fix: 'Never log passwords, tokens, or keys; redact them before logging: log({ user, token: "[REDACTED]" })',
    },
    {
        name: 'Insecure deserialization (pickle / yaml)',
        pattern: /(?:pickle\.(?:loads?|Unpickler)|cPickle\.loads?|marshal\.loads?|yaml\.load\s*\((?![^)]*SafeLoader))/gi,
        severity: 'CRITICAL',
        category: 'CWE-502 - Insecure Deserialization',
        fix: 'Replace pickle with JSON for untrusted data; use yaml.safe_load() instead of yaml.load()',
    },
    {
        name: 'XML External Entity (XXE) injection risk',
        pattern: /(?:ElementTree\.(?:parse|fromstring|fromstringlist|XML)\s*\(|etree\.(?:parse|fromstring|XML)\s*\(|lxml\.etree\.parse\s*\()/gi,
        severity: 'CRITICAL',
        category: 'CWE-611 - XML External Entity (XXE) Injection',
        fix: 'Use defusedxml instead of stdlib xml modules; or disable external entity resolution explicitly',
    },
    {
        name: 'Server-Side Request Forgery (SSRF) — user-controlled URL',
        pattern: /(?:fetch|axios\.(?:get|post|put|delete|request)|requests\.(?:get|post|put|delete)|http\.(?:get|post)|urllib\.request\.urlopen|urllib2\.urlopen)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|args\.|data\.|getParameter)/gi,
        severity: 'CRITICAL',
        category: 'CWE-918 - Server-Side Request Forgery (SSRF)',
        fix: 'Validate and allowlist URLs before making server-side requests; never pass raw user input to HTTP clients',
    },
    {
        name: 'Insecure randomness for security-sensitive value',
        pattern: /(?:(?:token|otp|nonce|csrf|salt|key|secret|password)\s*(?:=|:)\s*[^;{,\n]*Math\.random\s*\(\)|Math\.random\s*\(\)[^;{,\n]*(?:token|otp|nonce|csrf|salt|key|secret)|random\.(?:random|randint|choice|choices|sample)\s*\([^)]*\)[^;{,\n]*(?:token|otp|secret|key)|(?:token|otp|secret|key)[^;{,\n]*random\.(?:random|randint|choice))/gi,
        severity: 'HIGH',
        category: 'CWE-338 - Insecure Randomness for Security',
        fix: 'Use crypto.randomBytes() (Node.js), secrets module (Python), or SecureRandom (Java) for security-sensitive values',
    },
    {
        name: 'Path traversal via user-supplied input',
        pattern: /(?:fs\.readFile(?:Sync)?|fs\.createReadStream|fs\.open(?:Sync)?|open\s*\(|path\.(?:join|resolve))\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|args\.get|getParameter|_GET|_POST)/gi,
        severity: 'CRITICAL',
        category: 'CWE-22 - Path Traversal via User Input',
        fix: 'Sanitise file paths with path.basename(); use an allowlist of permitted paths; never pass raw user input to file I/O',
    },
    {
        name: 'Mass assignment — req.body passed directly to ORM',
        pattern: /(?:\.create\s*\(\s*req\.body|\.(?:update(?:One|Many|ById|All)?|save)\s*\([^)]*\$set\s*:\s*req\.body|Object\.assign\s*\(\s*\w+\s*,\s*req\.body|\.save\s*\(\s*req\.body|Model\.(?:create|build)\s*\(\s*req\.body)/gi,
        severity: 'HIGH',
        category: 'CWE-915 - Mass Assignment',
        fix: 'Explicitly pick allowed fields from req.body: const { name, email } = req.body — never pass the whole body to the ORM',
    },
    {
        name: 'Debug / verbose mode enabled in code',
        pattern: /(?:app\.(?:debug|run)\s*(?:=\s*True|\([^)]*debug\s*=\s*True)|DEBUG\s*=\s*True(?!\w)|"debug"\s*:\s*true\b|debug\s*:\s*true\b)/gi,
        severity: 'HIGH',
        category: 'CWE-94 / API8:2023 - Debug Mode in Production',
        fix: 'Set DEBUG=False in production; use environment variables to control debug flags — never hardcode True',
    },
    {
        name: 'Stack trace / error internals exposed in response',
        pattern: /(?:res\.(?:json|send)\s*\([^)]*(?:err\.stack|err\.message|error\.stack|exception\.toString|traceback\.format_exc)|jsonify\s*\(\s*(?:str\s*\(e\)|traceback|error\.args|e\.message|e\.args)|render_template\s*\([^)]*error\s*=\s*(?:str|repr)\s*\(e\))/gi,
        severity: 'HIGH',
        category: 'CWE-209 - Stack Trace / Verbose Error in Response',
        fix: 'Return a generic error message to clients; log the full stack trace server-side only',
    },
    {
        name: 'Prototype pollution via user-controlled merge',
        pattern: /(?:_\.merge|lodash\.merge|deepmerge|_.extend|_.defaultsDeep|Object\.assign\s*\(\s*(?:\{\}|obj|target)\s*,\s*(?:req\.body|req\.query|userInput|data))/gi,
        severity: 'HIGH',
        category: 'CWE-1321 - Prototype Pollution',
        fix: 'Use Object.create(null) targets for merges; validate that keys do not include __proto__, constructor, or prototype',
    },
    {
        name: 'GraphQL introspection enabled in production',
        pattern: /introspection\s*:\s*true/gi,
        severity: 'HIGH',
        category: 'API9:2023 - GraphQL Introspection Enabled',
        fix: 'Disable introspection in production: introspection: process.env.NODE_ENV !== "production"',
    },
    {
        name: 'Cookie set without HttpOnly / Secure flags',
        pattern: /res\.cookie\s*\(\s*['"][^'"]+['"]\s*,[^,)]+(?:,\s*\{[^}]*\})?(?<!\bhttpOnly\s*:\s*true)(?<!\bsecure\s*:\s*true)/gi,
        severity: 'HIGH',
        category: 'CWE-614 - Cookie Missing Secure / HttpOnly Flag',
        fix: 'Set { httpOnly: true, secure: true, sameSite: "strict" } on all auth cookies',
    },
    {
        name: 'Auth token stored in localStorage (insecure)',
        pattern: /localStorage\.setItem\s*\(\s*['"](?:token|jwt|access_?token|auth|id_?token|refresh_?token|bearer)['"]/gi,
        severity: 'HIGH',
        category: 'CWE-312 - Sensitive Token in Browser Storage',
        fix: 'Store tokens in HttpOnly cookies, not localStorage — localStorage is readable by any JS on the page (XSS risk)',
    },
    // ── New categories (request F) ─────────────────────────────────────────────
    {
        name: 'Unauthenticated health / metrics / actuator endpoint',
        // Route registration for an ops endpoint — flag so the author confirms it is auth-gated
        pattern: /(?:app\.(?:get|use)|router\.get|@(?:app\.)?(?:route|get))\s*\(\s*["'`]\/(?:health(?:z|check)?|metrics|status|actuator(?:\/[a-z]+)?|debug|info|env)\b/gi,
        severity: 'MEDIUM',
        category: 'API8:2023 - Unauthenticated Operational Endpoint',
        fix: 'Gate /health, /metrics, /actuator behind auth or bind them to an internal-only interface — they leak version, config and dependency data',
    },
    {
        name: 'Environment-gated security control (disabled outside production)',
        // e.g. `if (process.env.NODE_ENV === 'production') app.use(helmet())` — control off in dev/test
        pattern: /(?:process\.env\.NODE_ENV\s*(?:===?|!==?)\s*["']production["']|NODE_ENV\s*==\s*["']production["']|app\.get\(["']env["']\)\s*===?\s*["']production["'])/g,
        severity: 'MEDIUM',
        category: 'CWE-1188 - Security Control Gated by Environment',
        fix: 'Apply security middleware (helmet, CSRF, rate limiting) in ALL environments; never gate protections behind NODE_ENV==="production"',
    },
    {
        name: 'Non-constant-time comparison of secret / token / HMAC',
        // == / === / !== comparing a token-like identifier — vulnerable to timing attacks
        pattern: /(?:\b(?:token|secret|api[_-]?key|apikey|password|passwd|hmac|signature|sig|digest|mac)\b\s*(?:===?|!==?)|(?:===?|!==?)\s*\b(?:token|secret|api[_-]?key|apikey|password|passwd|hmac|signature|sig|digest|mac)\b)/gi,
        severity: 'MEDIUM',
        category: 'CWE-208 - Timing Attack via Non-Constant-Time Comparison',
        fix: 'Compare secrets with crypto.timingSafeEqual (Node), hmac.compare_digest (Python), or MessageDigest.isEqual (Java) — never == / ===',
    },
    {
        name: 'Authentication route without rate-limit middleware',
        // login/register/token/reset route handler — flag so author confirms a limiter is attached
        pattern: /(?:app|router)\.(?:post|put)\s*\(\s*["'`]\/(?:[a-z0-9/_-]*\/)?(?:login|signin|sign-in|register|signup|sign-up|token|auth|authenticate|reset[_-]?password|forgot[_-]?password|otp|verify)\b/gi,
        severity: 'MEDIUM',
        category: 'API4:2023 - Auth Route Missing Rate Limiting',
        fix: 'Attach a rate limiter to auth routes: app.post("/login", rateLimit({ windowMs: 60000, max: 5 }), handler) — unthrottled auth enables credential stuffing',
    },
    // ── AI / LLM / Agent Surface Mapping (AI-BOM) ───────────────────────────────
    {
        name: 'AI Surface: LLM Client/SDK Call Site',
        pattern: /(?:new\s+(?:OpenAI|Anthropic|Mistral|CohereClient|Groq)|genai\.Client\s*\(|google\.generativeai\.generativemodel)/gi,
        severity: 'MEDIUM',
        category: 'AI-BOM - LLM SDK / Call Site',
        fix: 'Review key rotation, usage logs, and rate-limiting controls for this LLM SDK call site.',
    },
    {
        name: 'AI Surface: Agent Framework (LangChain/CrewAI/LangGraph)',
        pattern: /(?:from\s+langchain|from\s+langgraph|from\s+crewai|new\s+(?:ChatOpenAI|ChatAnthropic|StateGraph)|Crew\s*\(\s*agents\b|Agent\s*\(\s*role\b)/gi,
        severity: 'MEDIUM',
        category: 'AI-BOM - AI Agent Framework (LangChain/CrewAI)',
        fix: 'Verify tool permissions, user inputs, output sanitisation, and prompt injection filters for this AI agent.',
    },
    {
        name: 'AI Surface: Model Context Protocol (MCP) Server Configuration',
        pattern: /(?:new\s+McpServer\b|@modelcontextprotocol\/sdk|mcpServers\s*:\s*\{)/gi,
        severity: 'MEDIUM',
        category: 'AI-BOM - Model Context Protocol (MCP) Server Configuration',
        fix: 'Ensure this MCP server restricts filesystem / process access, validates tool arguments, and does not expose shadow APIs or keys.',
    },
];

// API versioning is detected separately because it is a whole-file condition
// (two different version prefixes coexisting), not a single-line regex match.
const API_VERSION_RE = /["'`]\/(?:api\/)?v(\d+)(?:\/|["'`])/g;

// ── Main scan function ────────────────────────────────────────────────────────

// Files that are security testing infrastructure, scanners, report generators,
// or third-party vendor / minified files — skip soft heuristic patterns there
function isSecurityToolingFile(fsPath: string): boolean {
    const p = fsPath.replace(/\\/g, '/');
    return /(?:owasp_tests\/|testing.engine\/|generate_report\.py|generate_training_data\.py|report_generator\.py|demo\.py|evaluate\.py|vulnbank\/|vulnerable-api\/|\.claude\/|monitoring\/main\.py|\/test_[a-z]|_test\.py|\.min\.[jt]s$|\/static\/[^/]+\.js$|\/vendor\/)/i.test(p);
}

// Pure config/env files — scan for real secrets but skip URL-as-endpoint heuristics
// (these files legitimately contain URLs as configuration values, not hardcoded API calls)
function isConfigFile(fsPath: string): boolean {
    const p = fsPath.replace(/\\/g, '/');
    return /(?:\.env$|\.env\.|settings\.(?:json|local\.json)|docker-compose|\.gitignore|\.claudeignore|package-lock\.json)/i.test(p);
}

// A .env / .env.* file. Secrets here are only a real exposure if the file is committed
// to git (tracked). A locally-gitignored .env is the *correct* place for secrets.
function isEnvFile(fsPath: string): boolean {
    const p = fsPath.replace(/\\/g, '/');
    // .env.example / .env.sample / .env.template are templates — never real secrets
    if (/\.env\.(?:example|sample|template|dist)$/i.test(p)) return false;
    return /(?:^|\/)\.env(?:\.[a-z]+)?$/i.test(p);
}

// Shannon entropy (bits/char) of a string — high-entropy values look like real secrets.
function shannonEntropy(s: string): number {
    if (!s) return 0;
    const freq: Record<string, number> = {};
    for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
    let h = 0;
    for (const ch in freq) {
        const p = freq[ch] / s.length;
        h -= p * Math.log2(p);
    }
    return h;
}

// A value is "secret-like" if it is long, high-entropy, and not an obvious non-secret
// (a path, a URL, a UUID-with-dashes word list, a sentence, etc.).
function looksLikeSecret(val: string): boolean {
    const v = val.trim();
    if (v.length < 20 || v.length > 200) return false;
    // must be a single token — real secrets have no spaces
    if (/\s/.test(v)) return false;
    // mostly base64/hex/url-safe character set
    if (!/^[A-Za-z0-9._+/=:\-]+$/.test(v)) return false;
    // reject things that are clearly not secrets
    if (/^(?:https?:|\/|\.\/|~\/|[a-z]:\\)/i.test(v)) return false;        // url / path
    if (/^\d+$/.test(v)) return false;                                       // pure number
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}/i.test(v)) return false;       // UUID (low risk on its own)
    // A recognised vendor prefix (re_, gsk_, sk-, key-, tok_, …) is itself strong evidence —
    // these are deliberately low-entropy-tolerant so short vendor keys aren't missed.
    if (hasSecretPrefix(v)) return v.length >= 12;
    // Kebab/snake-case identifiers (cache keys, queue names, feature flags, slugs) are
    // readable words joined by - or _, all lower-case. Real secrets are random tokens, not
    // words — e.g. "facilitator-offline-write-queue-v1" is a queue key, not a credential.
    const segs = v.split(/[-_]/);
    if (segs.length >= 3 && !/[A-Z]/.test(v) && segs.every(s => /^[a-z]{1,16}[0-9]{0,3}$/.test(s))) return false;
    const h = shannonEntropy(v);
    // base64-ish secrets sit ~4.0–6.0 bits/char; English words sit < 3.5
    const hasMixedCase = /[a-z]/.test(v) && /[A-Z]/.test(v);
    const hasDigit = /\d/.test(v);
    return h >= 3.6 && (hasMixedCase || hasDigit || v.length >= 32);
}

// Common vendor secret prefixes. If a value starts with one of these it is almost
// certainly a credential, regardless of entropy (covers vendors we have no named pattern
// for yet). The catch-all uses this to fire on short/low-entropy keys it would otherwise skip.
const SECRET_PREFIX_RE = /^(?:re_|sk_|sk-|pk_|rk_|gsk_|pplx-|hf_|ghp_|ghs_|ghu_|gho_|glpat-|xox[baprs]-|AKIA|ASIA|AIza|SG\.|key-|key_|tok_|token-|secret_|shpat_|shpss_|dop_v1_|sl\.|sntrys_|npm_|pat-|api_|access-|Bearer )/i;

function hasSecretPrefix(v: string): boolean {
    return SECRET_PREFIX_RE.test(v);
}

// Lines that are clearly inside HTML/XML template strings — skip credential pattern there
function isHtmlTemplateLine(line: string): boolean {
    return /^\s*<[a-zA-Z]/.test(line) || />\s*(?:SECRET_KEY|PASSWORD|TOKEN)\s*=/.test(line);
}

// ── Phase-2 context validator ──────────────────────────────────────────────────
// The regex layer is fast but context-blind. After a pattern matches, we look at the
// matched text and the surrounding ±2 lines and cancel the finding when the context
// makes it a near-certain false positive. Returns true if the finding should be KEPT.

const PLACEHOLDER_WORDS = /\b(?:example|placeholder|your[_-]?key[_-]?here|your[_-]?token|xxx+|dummy|sample|changeme|replace[_-]?me|todo|fixme|fake|test[_-]?key|<[a-z_]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|process\.env|os\.environ|getenv)\b/i;

function isTestPath(fsPath: string): boolean {
    const p = fsPath.replace(/\\/g, '/');
    return /(?:\/tests?\/|\/spec\/|\/__tests__\/|\.test\.[a-z]+$|\.spec\.[a-z]+$|_test\.[a-z]+$|test_[^/]+\.[a-z]+$|\.stories\.[a-z]+$|fixtures?\/|mocks?\/|\.example$|\.sample$)/i.test(p);
}

function passesContextValidation(
    kind: FindingKind,
    matchText: string,
    lineText: string,
    prevLine: string,
    nextLine: string,
    fsPath: string,
): boolean {
    // 1. Inside a comment (single-line // or #, or a block-comment continuation line *)
    if (/^\s*(?:\/\/|#|\*|\/\*)/.test(lineText)) return false;

    // 2. Test / fixture / mock / example files — high false-positive density, keep them quiet
    if (isTestPath(fsPath)) return false;

    // 3. The matched value (or its line) advertises itself as a placeholder / env reference
    const window = `${prevLine}\n${lineText}\n${nextLine}`;
    if (PLACEHOLDER_WORDS.test(matchText) || PLACEHOLDER_WORDS.test(lineText)) return false;
    // A value that is literally pulled from the environment is not a hardcoded secret
    if (/(?:process\.env|os\.environ|getenv|config\.get|import\.meta\.env|System\.getenv)/i.test(window)) return false;

    // 4. URL-specific: cancel loopback / template / private-host URLs (these are not exposures)
    if (kind === 'hardcoded-url' || kind === 'endpoint') {
        if (/localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\{[a-zA-Z_]+\}|\$\{|\{\{|%s|<[a-z]+>/i.test(matchText)) return false;
    }

    return true;
}

export function scanFileForIssues(
    text: string,
    langId: string,
    uri: vscode.Uri,
    // True when this file is an .env that IS tracked by git (i.e. committed — a real
    // exposure). When false, secrets in an .env are not flagged as errors.
    envCommitted: boolean = false
): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const lines = text.split('\n');
    const isTooling = isSecurityToolingFile(uri.fsPath);
    const isConfig = isConfigFile(uri.fsPath);
    const isEnv = isEnvFile(uri.fsPath);
    const isGitignoredEnv = isEnv && !envCommitted;

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

    // Surrounding-line helper for the Phase-2 context validator
    const lineAt = (n: number) => (n >= 0 && n < lines.length ? lines[n] : '');

    // Track which (line, value) pairs already produced a key finding, so the entropy
    // catch-all below doesn't double-report a secret a named pattern already caught.
    const reportedKeyAt = new Set<string>();

    // Check for hardcoded API keys / secrets (run on all files including tooling)
    for (const { name, service, pattern, severity, category, fix, useDiscovery } of KEY_PATTERNS) {
        pattern.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = pattern.exec(text)) !== null) {
            const ln = rangeOf(m, text).start.line;
            const line = lines[ln] || '';
            // In .env files the "env reference" rule is skipped — the value IS the secret.
            if (!isEnv && !passesContextValidation('hardcoded-key', m[0], line, lineAt(ln - 1), lineAt(ln + 1), uri.fsPath)) continue;
            if (isEnv && PLACEHOLDER_WORDS.test(m[0])) continue;
            const rawVal = (m[1] || m[0]).replace(/^["'`]|["'`]$/g, '');
            // Dedup: an earlier (more specific) pattern already claimed this value on this line.
            // Patterns are ordered specific→generic, so e.g. Paystack wins over generic Stripe
            // for the same sk_live_… value, and we don't emit a second mislabelled finding.
            if (reportedKeyAt.has(`${ln}:${rawVal}`)) continue;
            reportedKeyAt.add(`${ln}:${rawVal}`);
            // For generic patterns, try to identify service from surrounding context
            let resolvedService = service;
            if (useDiscovery) {
                const ctxStart = Math.max(0, m.index - 200);
                const ctxEnd = Math.min(text.length, m.index + m[0].length + 200);
                const ctx = text.slice(ctxStart, ctxEnd);
                resolvedService = discoverService(ctx) ?? service;
            }
            findings.push({
                kind: 'hardcoded-key',
                message: isGitignoredEnv 
                    ? `${name} detected in gitignored .env — service: ${resolvedService} (Not flagged as error)` 
                    : `${name} detected — service: ${resolvedService}`,
                label: name,
                service: resolvedService,
                maskedValue: maskKey(rawVal),
                severity,
                category,
                range: rangeOf(m, text),
                uri,
                value: rawVal,
                fix: isGitignoredEnv 
                    ? 'This secret is stored in a gitignored .env file, which is correct. No action required.' 
                    : fix,
                compliance: getCompliance(category),
                isGitignoredEnv,
            });
        }
    }

    // ── Entropy catch-all: any high-entropy value assigned to a variable ──────────
    // Named patterns above only catch *known* key shapes (sk-…, FLWSECK-…, etc.). This
    // catches custom/unknown secrets: `MY_SERVICE_TOKEN = "a8Kd…"`, `db_pass: 'X9f…'`, or
    // a bare `SECRET=…` line in a committed .env. The context validator + looksLikeSecret()
    // keep the noise down. Skipped in tooling files.
    if (!isTooling) {
        // <name> = "<value>"  |  <name>: '<value>'  |  ENV_STYLE=value (no quotes, .env)
        const ASSIGN_RE = isEnv
            ? /^\s*([A-Z][A-Z0-9_]{2,})\s*=\s*["']?([^"'\s#]{20,200})["']?\s*$/gm
            : /(?:^|[\s,{(])([A-Za-z_][A-Za-z0-9_]{2,})\s*[:=]\s*["'`]([A-Za-z0-9._+/=:\-]{20,200})["'`]/g;
        const NAME_HINTS = /(?:key|token|secret|password|passwd|pwd|cred|auth|api|access|private|signing|salt|cipher|session)/i;
        let em: RegExpExecArray | null;
        ASSIGN_RE.lastIndex = 0;
        while ((em = ASSIGN_RE.exec(text)) !== null) {
            const varName = em[1];
            const val = em[2];
            const eln = rangeOf(em, text).start.line;
            const line = lines[eln] || '';
            if (/^\s*(?:#|\/\/|\/\*|\*)/.test(line)) continue;
            if (isHtmlTemplateLine(line)) continue;
            if (reportedKeyAt.has(`${eln}:${val}`)) continue;           // named pattern already caught it
            if (PLACEHOLDER_WORDS.test(val) || PLACEHOLDER_WORDS.test(line)) continue;
            if (!looksLikeSecret(val)) continue;
            // Outside .env, require a secret-ish variable name OR very high entropy to fire —
            // keeps ordinary long string constants from lighting up.
            const nameSuggestsSecret = NAME_HINTS.test(varName);
            const prefixed = hasSecretPrefix(val);
            // A recognised vendor prefix fires unconditionally. Otherwise, outside .env we
            // require a secret-ish variable name OR very high entropy to keep noise down.
            if (!isEnv && !prefixed && !nameSuggestsSecret && shannonEntropy(val) < 4.2) continue;
            if (!isEnv && !passesContextValidation('hardcoded-key', val, line, lineAt(eln - 1), lineAt(eln + 1), uri.fsPath)) continue;
            const sev: 'CRITICAL' | 'HIGH' = (nameSuggestsSecret || prefixed) ? 'CRITICAL' : 'HIGH';
            findings.push({
                kind: 'hardcoded-key',
                message: isGitignoredEnv
                    ? `High-entropy secret assigned to "${varName}" in gitignored .env (Not flagged as error)`
                    : `High-entropy secret assigned to "${varName}" — looks like a hardcoded credential`,
                label: 'High-entropy secret',
                service: 'Unknown service (entropy-detected)',
                maskedValue: maskKey(val),
                severity: sev,
                category: 'CWE-798 - Hardcoded Credentials',
                range: rangeOf(em, text),
                uri,
                value: val,
                fix: isGitignoredEnv
                    ? 'This secret is stored in a gitignored .env file, which is correct. No action required.'
                    : (isEnv
                        ? 'This .env file is committed to git. Add it to .gitignore and rotate every secret it contains.'
                        : `Move "${varName}" to an environment variable or secrets manager and rotate the value.`),
                compliance: getCompliance('CWE-798 - Hardcoded Credentials'),
                isGitignoredEnv,
            });
            reportedKeyAt.add(`${eln}:${val}`);
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
                const uln = rangeOf(m, text).start.line;
                const ukind = category.toLowerCase().includes('endpoint') ? 'endpoint' : 'hardcoded-url';
                // Phase-2: cancel loopback / templated URLs and comment/test contexts
                if (!passesContextValidation(ukind, m[0], lines[uln] || '', lineAt(uln - 1), lineAt(uln + 1), uri.fsPath)) continue;
                findings.push({
                    kind: ukind,
                    message: `Hardcoded URL: ${m[0].slice(0, 70)}`,
                    label: m[0].slice(0, 60),
                    severity,
                    category,
                    range: rangeOf(m, text),
                    uri,
                    value: m[0],
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
                const wln = rangeOf(m, text).start.line;
                const line = lines[wln] || '';
                // In .env / config files, DEBUG=true (and similar flags) is legitimate
                // configuration, not an in-code misconfiguration — the recommended fix for the
                // in-code version is literally to control it via an environment variable.
                if (isConfig && name === 'Debug / verbose mode enabled in code') continue;
                // Skip lines that are inside HTML template strings or comment-only lines
                if (isHtmlTemplateLine(line)) continue;
                if (/^\s*#/.test(line) || /^\s*\/\//.test(line)) continue;
                // Phase-2: cancel comment/test/placeholder contexts
                if (!passesContextValidation('weak-auth', m[0], line, lineAt(wln - 1), lineAt(wln + 1), uri.fsPath)) continue;
                findings.push({
                    kind: 'weak-auth',
                    message: `${name}: ${m[0].slice(0, 70)}`,
                    label: name,
                    severity,
                    category,
                    range: rangeOf(m, text),
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
    // Config/env files (.env, docker-compose, settings.json) legitimately hold values like
    // an admin email or contact address — that is configuration, not PII hardcoded in code.
    for (const { name, pattern, fix } of (isTooling || isConfig ? [] : PII_CODE_PATTERNS)) {
        pattern.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = pattern.exec(text)) !== null) {
            findings.push({
                kind: 'pii',
                message: `${name}: ${m[0].slice(0, 50)} — PII must not be hardcoded in source`,
                label: name,
                severity: 'HIGH',
                category: PII_CATEGORY,
                range: rangeOf(m, text),
                uri,
                value: m[0],
                fix,
                compliance: getCompliance(PII_CATEGORY),
            });
        }
    }

    // ── Whole-file: multiple API versions coexisting without a deprecation marker ──
    // Two different /vN/ prefixes in one file usually means an older, less-hardened
    // version is still being routed. Report once, anchored at the first older-version line.
    if (!isTooling && !isConfig) {
        API_VERSION_RE.lastIndex = 0;
        const versions = new Map<number, vscode.Range>();
        let vm: RegExpExecArray | null;
        while ((vm = API_VERSION_RE.exec(text)) !== null) {
            const v = parseInt(vm[1], 10);
            if (!versions.has(v)) versions.set(v, rangeOf(vm, text));
        }
        const hasDeprecationNote = /\b(?:deprecat|sunset|end[_-]?of[_-]?life|@deprecated|legacy)\b/i.test(text);
        if (versions.size >= 2 && !hasDeprecationNote) {
            const sorted = [...versions.keys()].sort((a, b) => a - b);
            const oldest = sorted[0];
            const category = 'API9:2023 - Multiple API Versions Without Deprecation';
            findings.push({
                kind: 'weak-auth',
                message: `Multiple API versions in one file (v${sorted.join(', v')}) with no deprecation marker — older versions are a common shadow-API attack surface`,
                label: `Coexisting API versions: v${sorted.join(', v')}`,
                severity: 'MEDIUM',
                category,
                range: versions.get(oldest)!,
                uri,
                fix: 'Document a deprecation/sunset policy for older versions, or remove them. Ensure every active version enforces the same authn/authz controls.',
                compliance: getCompliance(category),
            });
        }
    }

    return findings;
}
