// vibe-locker test suite — zero dependency: node test.js
// fake keys are runtime-generated sequences (see test-fixtures.mjs), never
// literals that could ever resemble real credentials.
import { KEYS, seq } from './test-fixtures.mjs';
import { scanText, looksReal, mask } from './lib/scan-text.js';
import { SIGNATURES } from './lib/keys.js';
import { renderReport } from './lib/report.js';

let pass = 0, fail = 0;
const ok = (cond, name) => {
  if (cond) pass++;
  else { fail++; console.error(`FAIL ${name}`); }
};

ok(scanText(`const key = "${KEYS.OA_FAKE}";`).some((f) => f.provider.includes('OpenAI') && f.sev === 'critical'), 'openai-project key detected');
ok(scanText(`fetch(url,{headers:{Authorization:"Bearer ${KEYS.OR_FAKE}"}})`).some((f) => f.provider === 'OpenRouter'), 'openrouter beats generic sk-');

// placeholder / fake immunity
ok(scanText('const k = "YOUR_OPENAI_KEY_HERE"').length === 0, 'YOUR_ placeholder ignored');
ok(scanText(`const k = "${'sk-' + 'x'.repeat(40)}"`).length === 0, 'repetitive fake ignored');
ok(scanText('apiKey: "sk-short123"').length === 0, 'too-short ignored');

// generic + entropy (unknown reseller key shapes)
const RESELLER = seq(32, 41);
ok(scanText(`const API_KEY = "${RESELLER}";`).some((f) => f.sig_id === 'generic-secret'), 'generic high-entropy caught');
ok(scanText('const api_key = "hello world my friend welcome"').length === 0, 'low-entropy generic rejected');

// signatures
ok(scanText(`x="${KEYS.GROQ_FAKE}"`).some((f) => f.provider === 'Groq'), 'groq');
ok(scanText(`x="${KEYS.GH_FAKE}"`).some((f) => f.provider === 'GitHub token'), 'github');
ok(scanText(`x="${KEYS.AWS_FAKE}"`).some((f) => f.provider === 'AWS access key ID'), 'aws');
ok(scanText(`x="${KEYS.GOOGLE_FAKE}"`).some((f) => f.provider.includes('Google')), 'google');
ok(scanText(`webhook("https://discord.com/api/webhooks/1234567890123/abcDEF-ghiJKL_mnoPQR")`).some((f) => f.provider === 'Discord webhook'), 'discord webhook'); // vibe-locker:ignore test fixture
ok(scanText(`t = "${KEYS.TG_FAKE}"`).some((f) => f.provider === 'Telegram bot token'), 'telegram bot');
ok(scanText(KEYS.STRIPE_LIVE).some((f) => f.sev === 'critical'), 'stripe live critical');
const pr = scanText(KEYS.STRIPE_PUB);
ok(pr.length === 1 && pr[0].sev === 'info', 'stripe publishable = info');

// web context upgrades severity
ok(scanText(`k="${KEYS.GOOGLE_FAKE}"`, { webSource: true }).some((f) => f.sev === 'critical'), 'webSource upgrade');

// base64 obfuscation
const b64 = Buffer.from(`OPENAI_KEY=${KEYS.OA_FAKE}`).toString('base64');
ok(scanText(`atob("${b64}")`).some((f) => f.via === 'base64-decoded'), 'base64 decoded rescan');

// occurrences & dedupe
const dup = scanText(`a="${KEYS.OA_FAKE}";b="${KEYS.OA_FAKE}";`);
ok(dup.length === 2 && dup[0].line === dup[1].line, 'both occurrences, same line');
ok(new Map(dup.map((f) => [f.value, f])).size === 1, 'dedupe by value works');

// line numbers
ok(scanText('l1\nl2\nx="' + KEYS.HS_FAKE + '";').find((f) => f.sig_id === 'openai')?.line === 3, 'line number correct');

// jwt & pem
ok(scanText(KEYS.JWT).some((f) => f.sig_id === 'jwt'), 'jwt detected');
ok(scanText('-----BEGIN RSA PRIVATE KEY-----').some((f) => f.sig_id === 'private-key'), 'pem header detected'); // vibe-locker:ignore

// ignore marker honored on finding lines
ok(scanText('x="sk-proj-HSbkv6FQZit4DNXgr2BLVepy9JTcmw7GRaju" // vibe-locker:ignore').length === 0, 'ignore marker works');

// looksReal direct
ok(looksReal(KEYS.HS_FAKE) === true, 'looksReal true case');
ok(looksReal('sk-1234') === false, 'looksReal short');
ok(looksReal('CHANGEMEabc123def456') === false, 'looksReal changeme');

// mask
const mk = mask(KEYS.OA_FAKE);
ok(!mk.includes(KEYS.OA_FAKE.slice(12, -4)) && mk.includes('…'), 'mask redacts middle');

// renderer
const rep = renderReport({ target: 'http://x.test', findings: dup, requests: 2, pages: 1, probes: [] });
ok(rep.includes('CRITICAL') && rep.includes('NEXT STEPS'), 'report renders');
ok(renderReport({ target: 'http://x.test', findings: [], requests: 1, pages: 1 }).includes('No leaked secrets'), 'clean report');

// all regex compile
let rxOk = true;
for (const s of SIGNATURES) { try { new RegExp(s.re.source, s.re.flags); } catch { rxOk = false; } }
ok(rxOk, 'signature regexes compile');

// false-positive sweep on realistic clean code
const clean = `
import { useState } from 'react';
export default function Chat(){
  const [m,setM]=useState([]);
  const token = "placeholder-value-not-a-secret-3210";
  async function send(text){
    const r = await fetch('/api/chat',{method:'POST',body:JSON.stringify({text})});
    return r.json();
  }
  return <div className="flex items-center justify-between">{m}</div>;
}
`;
ok(scanText(clean).filter((f) => f.sev !== 'info').length === 0, 'clean react code → zero findings');

console.log(`\n${fail === 0 ? '✔' : '✖'} ${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
