// Web crawler: fetch page, extract inline scripts, referenced .js, sourcemaps,
// config endpoints. Breadth-limited, polite, timeout-guarded.

import { scanText } from './scan-text.js';
import { basename } from 'node:path';

const UA = 'vibe-locker/0.1 (security scanner; reporting leaks)';
const SKIP_EXT = /\.(png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|mp4|mp3|pdf|avif)(\?|$)/i;

async function fetchText(url, timeoutMs = 15000) {
  const res = await fetch(url, {
    headers: { 'user-agent': UA },
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) return { status: res.status, text: '' };
  const text = await res.text();
  return { status: res.status, text, type: res.headers.get('content-type') || '' };
}

export async function crawlSite(startUrl, { maxRequests = 60, timeoutMs = 15000, onProgress = () => {} } = {}) {
  const origin = new URL(startUrl).origin;
  const queue = [startUrl];
  const seen = new Set();
  const findings = [];
  const checked = [];
  let requests = 0;

  while (queue.length && requests < maxRequests) {
    const url = queue.shift();
    if (seen.has(url) || SKIP_EXT.test(url)) continue;
    seen.add(url);
    requests++;
    onProgress(requests, url);

    let r;
    try {
      r = await fetchText(url, timeoutMs);
    } catch (e) {
      checked.push({ url, error: String(e.message || e).slice(0, 80) });
      continue;
    }
    const { status, text, type } = r;
    checked.push({ url, status: status || 0, bytes: text.length, isJson: /json/.test(type || '') });
    if (!text) continue;

    // 1) scan the body itself
    for (const f of scanText(text, { webSource: true })) {
      findings.push({ ...f, url });
    }

    // 2) harvest references
    if (/html/i.test(type || '') || /<script|<link/i.test(text.slice(0, 4000))) {
      const refs = new Set();
      for (const m of text.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) refs.add(m[1]);
      for (const m of text.matchAll(/href=["']([^"']+\.(?:js|map))["']/gi)) refs.add(m[1]);
      for (const m of text.matchAll(/sourceMappingURL=([^\s*"';]+)/g)) refs.add(m[1]);
      for (const ref of refs) {
        try {
          const abs = new URL(ref, url).href;
          if (abs.startsWith(origin + '/')) queue.push(abs);
        } catch { /* relative junk */ }
      }
    } else if (url.endsWith('.js') || /javascript/i.test(type || '')) {
      // sourcemap of a bundle?
      const sm = text.match(/[#@]sourceMappingURL=([^\s*'"`]+)/);
      if (sm) {
        try {
          const abs = new URL(sm[1], url).href;
          if (abs.startsWith(origin + '/') && !seen.has(abs)) queue.push(abs);
        } catch { /* junk */ }
      }
    }
  }

  return { findings, requests, checked };
}

// risky config endpoints every static host happily serves
const PROBE_PATHS = [
  '.env',
  '.env.local',
  '.env.production',
  'backend/.env',
  'config.php',
  'wp-config.php',
  'config.json',
  'server.js',
  'server/index.js',
  'api/index.js',
  'package.json',
  'composer.json',
  'web.config',
  'app/settings.py',
  'backup.zip',
  'dump.sql',
  '.git/config',
];

export async function probeConfigFiles(origin, { timeoutMs = 12000, onProgress = () => {} } = {}) {
  const hits = [];
  for (const path of PROBE_PATHS) {
    const url = new URL(path, origin).href;
    onProgress(path);
    try {
      const r = await fetch(url, {
        method: 'GET',
        headers: { 'user-agent': UA },
        signal: AbortSignal.timeout(timeoutMs),
      });
      const text = r.ok ? await r.text() : '';
      const ct = (r.headers.get('content-type') || '').toLowerCase();
      const isErrorPage = /<(html|!doctype)/i.test(text.slice(0, 200)) && !/\.php|server|api|settings|config|package/i.test(path);
      if (r.ok && text.length > 20 && !isErrorPage) {
        // content-based confirmation: does it look like the file it claims to be?
        let real = true;
        if (path.endsWith('.json') || path === 'package.json') {
          try { JSON.parse(text); } catch { real = false; }
        } else if (path === '.git/config') {
          real = /\[core\]|\[remote/.test(text);
        } else if (/^\.env/.test(path)) {
          real = /^[A-Z_][A-Z0-9_]*=/m.test(text);
        }
        if (real) {
          const findings = scanText(text, { webSource: true }).map((f) => ({ ...f, url }));
          hits.push({ url, status: r.status, bytes: text.length, ct, exposed: true, findings });
        }
      }
    } catch { /* closed/timeout → not exposed */ }
  }
  return hits;
}
