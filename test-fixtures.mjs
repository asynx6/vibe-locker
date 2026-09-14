import { scanText, looksReal } from './lib/scan-text.js';

export const CH = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'; // len 56
const CHU = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
// step 9 is coprime with both lengths → full cycle, high entropy
export const seq = (n, off = 0, al = CH) => Array.from({ length: n }, (_, i) => al[(i * 9 + off) % al.length]).join('');

export const KEYS = {
  OR_FAKE: 'sk-or-vi-' + seq(40, 3),
  OA_FAKE: ['sk','proj'].join('-') + seq(36, 7),
  GROQ_FAKE: 'gsk_' + seq(40, 11),
  GH_FAKE: 'ghp_' + seq(36, 13),
  AWS_FAKE: 'AKIA' + seq(16, 5, CHU),
  GOOGLE_FAKE: 'AIzaSy' + seq(33, 19),
  TG_FAKE: '123456789:AA' + seq(33, 23),
  STRIPE_LIVE: 'sk_live_' + seq(20, 29),
  STRIPE_PUB: 'pk_live_' + seq(20, 31),
  HS_FAKE: 'sk-' + seq(40, 37),
  RESSELLER: seq(32, 41),
  JWT:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
    'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.' +
    'TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
};

if (import.meta.url === `file:///${process.argv[1]?.replace(/\\/g, '/')}`) {
  for (const [k, v] of Object.entries(KEYS)) {
    const found = scanText(`x = "${v}";`).map((f) => `${f.sig_id}:${f.sev}`);
    console.log(k.padEnd(12), looksReal(v) ? 'real ' : 'FAKE', JSON.stringify(found));
  }
}
