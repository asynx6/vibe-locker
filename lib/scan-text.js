// Core text scanner: signatures + entropy-gated generics + placeholders +
// base64-decoded rescan (the atob("...") trick).

import { SIGNATURES, GENERIC } from './keys.js';

const PLACEHOLDER =
  /(your|my|sample|example|dummy|fake|placeholder|changeme|replace|insert|todo|test[_-]|none|null|redacted|xxx)/i;

function shannon(s) {
  const f = {};
  for (const c of s) f[c] = (f[c] || 0) + 1;
  let h = 0;
  for (const k in f) {
    const p = f[k] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function classes(s) {
  let n = 0;
  if (/[a-z]/.test(s)) n++;
  if (/[A-Z]/.test(s)) n++;
  if (/[0-9]/.test(s)) n++;
  if (/[^a-zA-Z0-9]/.test(s)) n++;
  return n;
}

export function looksReal(val) {
  const clean = val.replace(/^["'`]|["'`]$/g, '');
  if (clean.length < 16) return false;
  if (PLACEHOLDER.test(clean)) return false;
  const uniq = new Set(clean).size;
  // long strings (JWTs) naturally repeat more; short fakes must look random
  const minRatio = clean.length > 80 ? 0.25 : 0.45;
  if (uniq / clean.length < minRatio) return false;
  return true;
}

export function mask(v) {
  if (v.length <= 14) return v.slice(0, 4) + '…';
  return v.slice(0, 10) + '…' + v.slice(-4) + ` (len ${v.length})`;
}

// decode long base64 string literals, rescan their contents
function base64DecodedRanges(text) {
  const out = [];
  const re = /["'`]([A-Za-z0-9+/]{44,}={0,2})["'`]/g;
  let m;
  while ((m = re.exec(text))) {
    try {
      const dec = Buffer.from(m[1], 'base64').toString('utf8');
      if (dec.length > 16 && /^[\x20-\x7e]+$/.test(dec)) out.push({ decoded: dec, at: m.index });
    } catch { /* skip */ }
  }
  return out;
}

/**
 * @returns findings: [{sig_id, provider, sev, value, line, via, advice}]
 */
export function scanText(text, { webSource = false } = {}) {
  const findings = [];
  const spans = [];

  const lineOf = (idx) => {
    let line = 1;
    for (let i = 0; i < idx; i++) if (text.charCodeAt(i) === 10) line++;
    return line;
  };

  function overlap(start, len) {
    for (const s of spans) if (start < s.end && s.start < start + len) return true;
    spans.push({ start, end: start + len });
    return false;
  }

  function runRegex(re, meta, { entropyGate = false, via = null, at = 0 } = {}) {
    const rx = new RegExp(re.source, re.flags);
    let m;
    while ((m = rx.exec(text))) {
      const value = meta.id === 'generic-secret' ? m[3] : m[0];
      if (!looksReal(value)) continue;
      if (entropyGate && !(shannon(value) >= 3.2 && classes(value) >= 3)) continue;
      if (overlap(at + m.index, m[0].length)) continue;
      // allowlist: lines ending with vibe-locker:ignore are skipped (tests, fixtures)
      const lineStart = text.lastIndexOf('\n', at + m.index) + 1;
      const lineEnd = text.indexOf('\n', at + m.index);
      const line = text.slice(lineStart, lineEnd === -1 ? undefined : lineEnd);
      if (/vibe-locker:ignore\b/.test(line)) continue;
      let sev = meta.sev;
      if (webSource && sev === 'high') sev = 'critical'; // server-side token shipped to browsers
      findings.push({
        sig_id: meta.id,
        provider: meta.provider,
        sev,
        value,
        line: lineOf(at + m.index),
        via,
        advice: meta.advice || 'Rotate this credential and move it server-side.',
      });
      if (findings.length > 500) return; // sanity cap
    }
  }

  for (const sig of SIGNATURES) runRegex(sig.re, sig, { via: 'signature' });
  runRegex(GENERIC.re, GENERIC, { entropyGate: true, via: 'generic+entropy' });

  // pass 2: base64 string literals that decode into key-shaped content
  for (const b of base64DecodedRanges(text)) {
    for (const sig of SIGNATURES) {
      const rx = new RegExp(sig.re.source, sig.re.flags);
      const m = rx.exec(b.decoded);
      if (m && looksReal(sig.id === 'generic-secret' ? m[4] : m[0])) {
        if (overlap(b.at, 0)) continue;
        findings.push({
          sig_id: sig.id,
          provider: sig.provider,
          sev: 'critical',
          value: m[0],
          line: lineOf(b.at),
          via: 'base64-decoded',
          advice: sig.advice,
        });
      }
    }
  }

  return findings;
}
