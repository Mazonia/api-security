/**
 * MazAPI Scanner — Content Script
 * Scans inline JS and same-origin external scripts for hardcoded API keys.
 * Ordered most-specific first so overlapping prefixes match correctly.
 */
(function () {
  // ── Service discovery hints ─────────────────────────────────────────────────
  const SERVICE_HINTS = [
    [/paystack/i,                                       'Paystack'],
    [/hubtel/i,                                         'Hubtel'],
    [/flutterwave/i,                                    'Flutterwave'],
    [/africastalking|africa[_-]?talk/i,                 "Africa's Talking"],
    [/mtn[_-]?momo|momoapi|mtn[_-]?open/i,             'MTN Mobile Money (MoMo)'],
    [/vodafone[_-]?(?:ghana|cash)|vodacash/i,           'Vodafone Ghana / VodaCash'],
    [/airteltigo|airtel[_-]?ghana/i,                    'AirtelTigo Ghana'],
    [/interswitch/i,                                    'Interswitch'],
    [/openai/i,                                         'OpenAI'],
    [/anthropic|claude[_-]?api/i,                       'Anthropic (Claude AI)'],
    [/groq/i,                                           'Groq'],
    [/perplexity/i,                                     'Perplexity AI'],
    [/openrouter/i,                                     'OpenRouter'],
    [/replicate/i,                                      'Replicate'],
    [/cohere/i,                                         'Cohere'],
    [/mistral/i,                                        'Mistral AI'],
    [/elevenlabs|xi[_-]?api/i,                          'ElevenLabs'],
    [/together[_-]?ai/i,                                'Together AI'],
    [/deepgram/i,                                       'Deepgram'],
    [/assemblyai/i,                                     'AssemblyAI'],
    [/google|firebase|gcp|googleapis/i,                 'Google Cloud / Firebase'],
    [/aws|amazon[_-]?(?:web|s3|ec2|lambda|bedrock)/i,   'Amazon Web Services (AWS)'],
    [/azure|microsoft[_-]?(?:cognitive|openai)/i,       'Microsoft Azure'],
    [/digitalocean|do[_-]?token/i,                      'DigitalOcean'],
    [/vercel/i,                                         'Vercel'],
    [/cloudflare/i,                                     'Cloudflare'],
    [/fly[_-]?(?:io|token)/i,                           'Fly.io'],
    [/render[_-]?(?:api|token)/i,                       'Render'],
    [/railway/i,                                        'Railway'],
    [/stripe/i,                                         'Stripe'],
    [/paypal/i,                                         'PayPal'],
    [/braintree/i,                                      'Braintree'],
    [/square/i,                                         'Square'],
    [/razorpay/i,                                       'Razorpay'],
    [/twilio/i,                                         'Twilio'],
    [/sendgrid/i,                                       'SendGrid'],
    [/mailchimp/i,                                      'Mailchimp'],
    [/mailgun/i,                                        'Mailgun'],
    [/brevo|sendinblue/i,                               'Brevo (Sendinblue)'],
    [/postmark/i,                                       'Postmark'],
    [/resend/i,                                         'Resend'],
    [/sparkpost/i,                                      'SparkPost'],
    [/slack/i,                                          'Slack'],
    [/telegram/i,                                       'Telegram'],
    [/discord/i,                                        'Discord'],
    [/twitter|x[_-]?(?:api|bearer)/i,                  'Twitter / X'],
    [/facebook|meta[_-]?(?:api|access)/i,               'Meta / Facebook'],
    [/instagram/i,                                      'Instagram'],
    [/linkedin/i,                                       'LinkedIn'],
    [/github/i,                                         'GitHub'],
    [/gitlab/i,                                         'GitLab'],
    [/newrelic|new[_-]?relic/i,                         'New Relic'],
    [/posthog/i,                                        'PostHog'],
    [/datadog/i,                                        'Datadog'],
    [/sentry/i,                                         'Sentry'],
    [/mixpanel/i,                                       'Mixpanel'],
    [/amplitude/i,                                      'Amplitude'],
    [/segment/i,                                        'Segment'],
    [/huggingface|hf[_-]?token/i,                      'Hugging Face'],
    [/mapbox/i,                                         'Mapbox'],
    [/notion/i,                                         'Notion'],
    [/airtable/i,                                       'Airtable'],
    [/contentful/i,                                     'Contentful'],
    [/hubspot/i,                                        'HubSpot'],
    [/salesforce/i,                                     'Salesforce'],
    [/zendesk/i,                                        'Zendesk'],
    [/shopify/i,                                        'Shopify'],
    [/supabase/i,                                       'Supabase'],
    [/planetscale/i,                                    'PlanetScale'],
    [/cloudinary/i,                                     'Cloudinary'],
    [/shodan/i,                                         'Shodan'],
    [/pagerduty/i,                                      'PagerDuty'],
    [/okta/i,                                           'Okta'],
    [/auth0/i,                                          'Auth0'],
    [/npm[_-]?token/i,                                  'npm'],
    [/pypi/i,                                           'PyPI'],
    [/vonage|nexmo/i,                                   'Vonage (Nexmo)'],
    [/plaid/i,                                          'Plaid'],
    [/smile[_-]?id|smileidentity/i,                     'Smile Identity'],
    [/pusher/i,                                         'Pusher'],
    [/deepl/i,                                          'DeepL'],
    [/algolia/i,                                        'Algolia'],
    [/pinecone/i,                                       'Pinecone'],
    [/openweather|weather[_-]?api/i,                    'OpenWeatherMap'],
    [/exchange[_-]?rate|fixer[_-]?io/i,                 'Fixer.io / Exchange Rate API'],
    [/jwt[_-]?secret|secret[_-]?key/i,                  'JWT / Auth Middleware'],
  ];

  function discoverService(contextText) {
    for (const [re, svc] of SERVICE_HINTS) {
      if (re.test(contextText)) return svc;
    }
    return null;
  }

  // ── Key patterns ────────────────────────────────────────────────────────────
  const KEY_PATTERNS = [
    // African payment services
    { name: 'Paystack Secret Key',          service: 'Paystack',
      re: /(?:paystack[_-]?(?:secret|sk|api[_-]?key|secret[_-]?key))\s*[:=]\s*["']((?:sk)_(?:live|test)_[A-Za-z0-9]{20,})["']/gi },
    { name: 'Paystack Public Key',          service: 'Paystack',
      re: /pk_(?:live|test)_[A-Za-z0-9]{20,}/g },
    { name: 'Hubtel API Credentials',       service: 'Hubtel',
      re: /(?:hubtel[_-]?(?:client[_-]?(?:id|secret)|api[_-]?key|secret))\s*[:=]\s*["']([A-Za-z0-9._-]{10,80})["']/gi },
    { name: 'Flutterwave Live Secret Key',  service: 'Flutterwave',
      re: /FLWSECK-[A-Za-z0-9-]{40,}/g },
    { name: 'Flutterwave Test Secret Key',  service: 'Flutterwave',
      re: /FLWSECK_TEST-[A-Za-z0-9-]{40,}/g },
    { name: 'Flutterwave Public Key',       service: 'Flutterwave',
      re: /FLWPUBK(?:_TEST)?-[A-Za-z0-9-]{40,}/g },
    { name: "Africa's Talking API Key",     service: "Africa's Talking",
      re: /(?:africastalking|at[_-]?api[_-]?key)\s*[:=]\s*["']([A-Za-z0-9._+\-]{10,80})["']/gi },
    { name: 'MTN MoMo API Key',             service: 'MTN Mobile Money (MoMo)',
      re: /(?:mtn[_-]?momo|momoapi|mtn[_-]?subscription[_-]?key)\s*[:=]\s*["']([A-Za-z0-9._\-]{10,80})["']/gi },
    { name: 'Vodafone Ghana API Key',       service: 'Vodafone Ghana / VodaCash',
      re: /(?:vodafone[_-]?(?:ghana|cash|api)[_-]?(?:key|secret|token))\s*[:=]\s*["']([A-Za-z0-9._\-]{10,80})["']/gi },
    { name: 'Interswitch API Credentials',  service: 'Interswitch',
      re: /(?:interswitch[_-]?(?:client[_-]?(?:id|secret)|api[_-]?key))\s*[:=]\s*["']([A-Za-z0-9._\-]{10,80})["']/gi },

    // AI / ML — most-specific prefixes first
    { name: 'Anthropic / Claude API Key',   service: 'Anthropic (Claude AI)',
      re: /sk-ant-(?:api03|admin)-[A-Za-z0-9_-]{90,}/g },
    { name: 'OpenAI Project API Key',       service: 'OpenAI',
      re: /sk-proj-[A-Za-z0-9_-]{40,}/g },
    { name: 'OpenAI API Key',               service: 'OpenAI',
      re: /sk-[A-Za-z0-9]{48}/g },
    { name: 'Groq API Key',                 service: 'Groq',
      re: /gsk_[A-Za-z0-9]{52}/g },
    { name: 'Perplexity AI API Key',        service: 'Perplexity AI',
      re: /pplx-[A-Za-z0-9]{48}/g },
    { name: 'OpenRouter API Key',           service: 'OpenRouter',
      re: /sk-or-v1-[A-Za-z0-9]{64}/g },
    { name: 'Replicate API Token',          service: 'Replicate',
      re: /r8_[A-Za-z0-9]{37}/g },
    { name: 'Hugging Face API Token',       service: 'Hugging Face',
      re: /hf_[A-Za-z0-9]{34}/g },
    { name: 'ElevenLabs API Key',           service: 'ElevenLabs',
      re: /(?:elevenlabs|xi[_-]?api[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-]{32})["']/gi },
    { name: 'Deepgram API Key',             service: 'Deepgram',
      re: /(?:deepgram[_-]?api[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-]{40,})["']/gi },
    { name: 'Cohere API Key',               service: 'Cohere',
      re: /(?:cohere[_-]?api[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-]{40,})["']/gi },

    // Payments
    { name: 'Stripe Live Secret Key',       service: 'Stripe (Live)',
      re: /sk_live_[0-9a-zA-Z]{24,}/g },
    { name: 'Stripe Test Secret Key',       service: 'Stripe (Test)',
      re: /sk_test_[0-9a-zA-Z]{24,}/g },
    { name: 'Stripe Restricted Key (Live)', service: 'Stripe (Live — restricted)',
      re: /rk_live_[0-9a-zA-Z]{24,}/g },
    { name: 'Square Access Token',          service: 'Square',
      re: /EAAAl[A-Za-z0-9_\-]{60,}/g },
    { name: 'Square Application Key',       service: 'Square',
      re: /sq0atp-[A-Za-z0-9_\-]{22}/g },
    { name: 'Razorpay Live Key',            service: 'Razorpay',
      re: /rzp_live_[A-Za-z0-9]{20}/g },
    { name: 'Razorpay Test Key',            service: 'Razorpay',
      re: /rzp_test_[A-Za-z0-9]{20}/g },
    { name: 'Braintree Access Token',       service: 'Braintree (PayPal)',
      re: /access_token\$(?:production|sandbox)\$[A-Za-z0-9_\-]+\$[A-Za-z0-9_\-]+/g },

    // Cloud
    { name: 'Google API Key',               service: 'Google Cloud / Firebase / Maps / YouTube',
      re: /AIza[0-9A-Za-z_-]{35}/g },
    { name: 'AWS Access Key ID',            service: 'Amazon Web Services (AWS)',
      re: /AKIA[0-9A-Z]{16}/g },
    { name: 'DigitalOcean PAT',             service: 'DigitalOcean',
      re: /dop_v1_[A-Za-z0-9]{43}/g },
    { name: 'Fly.io API Token',             service: 'Fly.io',
      re: /fo1_[A-Za-z0-9_\-]{43}/g },
    { name: 'Render API Key',               service: 'Render',
      re: /rnd_[A-Za-z0-9]{43}/g },
    { name: 'Cloudflare API Token',         service: 'Cloudflare',
      re: /(?:cloudflare[_-]?(?:api[_-]?token|api[_-]?key))\s*[:=]\s*["']([A-Za-z0-9_\-]{40,})["']/gi },

    // Source control / CI
    { name: 'GitHub Personal Access Token', service: 'GitHub',
      re: /ghp_[A-Za-z0-9]{36}/g },
    { name: 'GitHub App / Installation Token', service: 'GitHub Apps',
      re: /(?:ghs|ghu)_[A-Za-z0-9]{36}/g },
    { name: 'GitLab Personal Access Token', service: 'GitLab',
      re: /glpat-[A-Za-z0-9_-]{20}/g },
    { name: 'npm Access Token',             service: 'npm',
      re: /npm_[A-Za-z0-9]{36}/g },
    { name: 'PyPI API Token',               service: 'PyPI',
      re: /pypi-[A-Za-z0-9_\-]{48}/g },

    // Communication
    { name: 'Slack Bot/App Token',          service: 'Slack',
      re: /xox[baprs]-[0-9A-Za-z-]{10,48}/g },
    { name: 'SendGrid API Key',             service: 'SendGrid / Twilio Email',
      re: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g },
    { name: 'Twilio API Key SID',           service: 'Twilio',
      re: /SK[0-9a-fA-F]{32}/g },
    { name: 'Mailchimp API Key',            service: 'Mailchimp',
      re: /[0-9a-f]{32}-us\d{1,2}/g },
    { name: 'Mailgun API Key',              service: 'Mailgun',
      re: /key-[0-9a-zA-Z]{32}/g },
    { name: 'Brevo (Sendinblue) API Key',   service: 'Brevo (Sendinblue)',
      re: /xkeysib-[A-Za-z0-9_\-]{64}/g },
    { name: 'Resend API Key',               service: 'Resend',
      re: /re_[A-Za-z0-9]{24}/g },

    // Social / messaging
    { name: 'Telegram Bot Token',           service: 'Telegram',
      re: /\d{9,10}:[A-Za-z0-9_\-]{35}/g },
    { name: 'Discord Bot Token',            service: 'Discord',
      re: /[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}/g },
    { name: 'Twitter / X Bearer Token',     service: 'Twitter / X',
      re: /AAAA[A-Za-z0-9%_\-]{80,}/g },
    { name: 'Facebook / Meta Access Token', service: 'Meta / Facebook',
      re: /EAA[A-Za-z0-9]{20,}/g },

    // Monitoring
    { name: 'New Relic Key',                service: 'New Relic',
      re: /NR(?:AK|IQ)-[A-Za-z0-9]{42}/g },
    { name: 'PostHog API Key',              service: 'PostHog',
      re: /phc_[A-Za-z0-9]{43}/g },
    { name: 'Sentry DSN',                   service: 'Sentry',
      re: /https:\/\/[a-f0-9]{32}@(?:[a-z0-9]+\.)?(?:ingest\.)?sentry\.io\/\d+/g },

    // SaaS / CMS
    { name: 'Mapbox API Token',             service: 'Mapbox',
      re: /pk\.eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+/g },
    { name: 'Notion Integration Secret',    service: 'Notion',
      re: /secret_[A-Za-z0-9]{43}/g },
    { name: 'Shopify Admin API Token',      service: 'Shopify',
      re: /shp(?:at|pa|ss|ca)_[A-Za-z0-9]{32}/g },
    { name: 'Airtable Personal Access Token', service: 'Airtable',
      re: /pat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64}/g },
    { name: 'Contentful Token',             service: 'Contentful',
      re: /CFPAT-[A-Za-z0-9_\-]{43}/g },
    { name: 'HubSpot Private App Token',    service: 'HubSpot',
      re: /pat-(?:na1|eu1|ap[1-9])-[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}/g },
    { name: 'PlanetScale Service Token',    service: 'PlanetScale',
      re: /pscale_tkn_[A-Za-z0-9_\-]{43}/g },

    // Crypto / private keys
    { name: 'Private Key block',            service: 'SSH / TLS / Code Signing',
      re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },

    // Generic — with service discovery from context
    { name: 'JWT Hardcoded Secret',         service: 'JWT / Auth Middleware',
      re: /(?:jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*["']([^"']{4,60})["']/gi },
    { name: 'Hardcoded DB connection string', service: 'Database (credentials embedded)',
      re: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^\s"'`]*:[^\s"'`@]+@[^\s"'`]+/gi },
    { name: 'Hardcoded Bearer Token',       service: 'HTTP Authorization',
      re: /["']Bearer\s+[A-Za-z0-9._\-]{20,}["']/g },
    { name: 'Generic API Key / Token',      service: 'Unknown service',
      re: /(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*["']([A-Za-z0-9._\-]{20,80})["']/gi,
      useDiscovery: true },
  ];

  function maskKey(raw) {
    const s = (raw || '').replace(/^["'\s]+|["'\s]+$/g, '');
    if (s.length <= 10) return s.slice(0, 3) + '****';
    if (s.length <= 20) return s.slice(0, 6) + '****' + s.slice(-3);
    return s.slice(0, 8) + '****' + s.slice(-4);
  }

  function scanText(text, sourceLabel) {
    const found = [];
    for (const { name, service, re, useDiscovery } of KEY_PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        const raw = (m[1] || m[0]).replace(/^["'\s]+|["'\s]+$/g, '');
        if (raw.length < 10) continue;
        if (!found.some(k => k.value === raw)) {
          let resolvedService = service;
          if (useDiscovery) {
            const ctxStart = Math.max(0, m.index - 200);
            const ctxEnd   = Math.min(text.length, m.index + m[0].length + 200);
            const ctx      = text.slice(ctxStart, ctxEnd);
            resolvedService = discoverService(ctx) || service;
          }
          found.push({ name, service: resolvedService, value: raw, maskedValue: maskKey(raw), source: sourceLabel });
        }
      }
    }
    return found;
  }

  const seen = new Set();
  const allKeys = [];

  function merge(keys) {
    for (const k of keys) {
      if (!seen.has(k.value)) {
        seen.add(k.value);
        allKeys.push(k);
      }
    }
  }

  // 1. Scan all inline <script> tags immediately
  document.querySelectorAll('script:not([src])').forEach(s => {
    merge(scanText(s.textContent || '', location.href + ' (inline)'));
  });

  // 2. Re-fetch same-origin external scripts and scan them
  const externalSrcs = Array.from(document.querySelectorAll('script[src]'))
    .map(s => s.src)
    .filter(src => {
      try { return new URL(src).origin === location.origin; } catch { return false; }
    })
    .slice(0, 6);

  function sendKeys() {
    if (allKeys.length) {
      chrome.runtime.sendMessage({ type: 'CONTENT_FINDINGS', keys: allKeys, url: location.href });
    }
  }

  sendKeys();

  Promise.all(
    externalSrcs.map(src => fetch(src).then(r => r.text()).catch(() => ''))
  ).then(texts => {
    texts.forEach((text, i) => merge(scanText(text, externalSrcs[i])));
    sendKeys();
  });
})();
