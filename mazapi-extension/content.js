/**
 * MazAPI Scanner — Content Script
 * Runs in the context of every visited page.
 * Scans inline JS for hardcoded API endpoints and keys.
 */
(function () {
  const findings = { hardcoded_urls: [], hardcoded_keys: [] };

  // Scan all inline <script> tags for API URLs and keys
  const scripts = document.querySelectorAll("script:not([src])");
  scripts.forEach((s) => {
    const text = s.textContent || "";

    // API endpoint patterns
    const urlPattern = /["'`](\/(?:api|v\d+|graphql|rest|auth)\/[^\s"'`?#]{3,80})["'`]/g;
    let m;
    while ((m = urlPattern.exec(text)) !== null) {
      if (!findings.hardcoded_urls.includes(m[1])) {
        findings.hardcoded_urls.push(m[1]);
      }
    }

    // API key patterns (common shapes)
    const keyPatterns = [
      /AIza[0-9A-Za-z_-]{35}/g,            // Google API key
      /sk-[A-Za-z0-9]{32,}/g,              // OpenAI / Stripe secret
      /ghp_[A-Za-z0-9]{36}/g,             // GitHub PAT
      /(?:api[_-]?key|apikey|token)\s*[:=]\s*["']([A-Za-z0-9._\-]{16,80})["']/gi,
    ];
    for (const pat of keyPatterns) {
      while ((m = pat.exec(text)) !== null) {
        const key = m[1] || m[0];
        if (!findings.hardcoded_keys.some(k => k.value === key)) {
          findings.hardcoded_keys.push({ value: key, pattern: pat.source.slice(0, 30) });
        }
      }
    }
  });

  // Send findings to background
  if (findings.hardcoded_urls.length || findings.hardcoded_keys.length) {
    chrome.runtime.sendMessage({ type: "CONTENT_FINDINGS", findings, url: location.href });
  }
})();
