/**
 * MazAPI Scanner — Content Script
 * Scans inline JS and same-origin external scripts for hardcoded API keys.
 * Ordered most-specific first so overlapping prefixes match correctly.
 */
(function () {
  const KEY_PATTERNS = [
    { name: 'Anthropic / Claude API Key',   service: 'Anthropic (Claude AI)',              re: /sk-ant-(?:api03|admin)-[A-Za-z0-9_-]{90,}/g },
    { name: 'OpenAI Project API Key',        service: 'OpenAI',                             re: /sk-proj-[A-Za-z0-9_-]{40,}/g },
    { name: 'OpenAI API Key',                service: 'OpenAI',                             re: /sk-[A-Za-z0-9]{48}/g },
    { name: 'Stripe Live Secret Key',        service: 'Stripe (Live — billing live data)',  re: /sk_live_[0-9a-zA-Z]{24,}/g },
    { name: 'Stripe Test Secret Key',        service: 'Stripe (Test)',                      re: /sk_test_[0-9a-zA-Z]{24,}/g },
    { name: 'Stripe Restricted Key (Live)',  service: 'Stripe (Live — restricted)',         re: /rk_live_[0-9a-zA-Z]{24,}/g },
    { name: 'Google API Key',                service: 'Google Cloud / Firebase / Maps / YouTube', re: /AIza[0-9A-Za-z_-]{35}/g },
    { name: 'GitHub Personal Access Token',  service: 'GitHub',                             re: /ghp_[A-Za-z0-9]{36}/g },
    { name: 'GitHub App / Installation Token', service: 'GitHub Apps',                      re: /(?:ghs|ghu)_[A-Za-z0-9]{36}/g },
    { name: 'GitLab Personal Access Token',  service: 'GitLab',                             re: /glpat-[A-Za-z0-9_-]{20}/g },
    { name: 'AWS Access Key ID',             service: 'Amazon Web Services (AWS)',          re: /AKIA[0-9A-Z]{16}/g },
    { name: 'Slack Bot/App Token',           service: 'Slack',                              re: /xox[baprs]-[0-9A-Za-z-]{10,48}/g },
    { name: 'SendGrid API Key',              service: 'SendGrid / Twilio Email',            re: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g },
    { name: 'Twilio API Key SID',            service: 'Twilio',                             re: /SK[0-9a-fA-F]{32}/g },
    { name: 'Hugging Face API Token',        service: 'Hugging Face',                       re: /hf_[A-Za-z0-9]{34}/g },
    { name: 'Mapbox API Token',              service: 'Mapbox',                             re: /pk\.eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+/g },
    { name: 'Notion Integration Secret',     service: 'Notion',                             re: /secret_[A-Za-z0-9]{43}/g },
    { name: 'Generic API Key / Token',       service: 'Unknown service',                    re: /(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([A-Za-z0-9._\-]{20,80})["']/gi },
  ];

  function maskKey(raw) {
    const s = (raw || '').replace(/^["'\s]+|["'\s]+$/g, '');
    if (s.length <= 10) return s.slice(0, 3) + '****';
    if (s.length <= 20) return s.slice(0, 6) + '****' + s.slice(-3);
    return s.slice(0, 8) + '****' + s.slice(-4);
  }

  function scanText(text, sourceLabel) {
    const found = [];
    for (const { name, service, re } of KEY_PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        const raw = (m[1] || m[0]).replace(/^["'\s]+|["'\s]+$/g, '');
        if (raw.length < 10) continue;
        if (!found.some(k => k.value === raw)) {
          found.push({ name, service, value: raw, maskedValue: maskKey(raw), source: sourceLabel });
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
    .slice(0, 6); // cap to avoid excessive requests

  function sendKeys() {
    if (allKeys.length) {
      chrome.runtime.sendMessage({ type: 'CONTENT_FINDINGS', keys: allKeys, url: location.href });
    }
  }

  // Send inline findings immediately, then update after external scripts are scanned
  sendKeys();

  Promise.all(
    externalSrcs.map(src => fetch(src).then(r => r.text()).catch(() => ''))
  ).then(texts => {
    texts.forEach((text, i) => merge(scanText(text, externalSrcs[i])));
    sendKeys();
  });
})();
