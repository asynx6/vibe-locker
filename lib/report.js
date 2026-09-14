import { mask } from './scan-text.js';

const ICON = { critical: '🚨', high: '⚠️ ', info: 'ℹ️  ' };
const ORDER = { critical: 0, high: 1, info: 2 };

export function renderReport(scan, { json = false, showAll = false } = {}) {
  if (json) {
    return JSON.stringify(
      { ...scan, findings: scan.findings.map((f) => ({ ...f, value: mask(f.value) })) },
      null, 1,
    );
  }
  const findings = scan.findings
    .filter((f) => showAll || f.sev !== 'info')
    .sort((a, b) => ORDER[a.sev] - ORDER[b.sev]);

  const lines = [];
  const crit = findings.filter((f) => f.sev === 'critical').length;
  const high = findings.filter((f) => f.sev === 'high').length;

  lines.push('');
  lines.push(`  vibe-locker report — ${scan.target}`);
  lines.push(`  ${'─'.repeat(Math.max(28, scan.target.length))}`);
  if (scan.pages) lines.push(`  pages crawled: ${scan.pages} · requests: ${scan.requests}`);
  if (scan.files) lines.push(`  files scanned: ${scan.files}`);

  if (!findings.length) {
    lines.push('');
    lines.push('  ✅ No leaked secrets found.');
    lines.push('     (Not a guarantee — it checks signatures + entropy + common');
    lines.push('      config endpoints, not your whole codebase logic.)');
    lines.push('');
    return lines.join('\n');
  }

  lines.push('');
  lines.push(`  ${crit} critical · ${high} high`);
  lines.push('');

  const byKey = new Map();
  for (const f of findings) {
    const k = `${f.sig_id}|${f.value}`;
    if (!byKey.has(k)) byKey.set(k, f);
  }
  const uniq = [...byKey.values()];

  for (const f of uniq) {
    lines.push(`  ${ICON[f.sev]} [${f.sev.toUpperCase()}] ${f.provider} — ${mask(f.value)}`);
    if (f.url || f.file) lines.push(`      where : ${f.url || f.file}${f.line ? ` (line ${f.line})` : ''}`);
    if (f.via && f.via !== 'signature') lines.push(`      found : via ${f.via}`);
    lines.push(`      fix   : ${f.advice}`);
    lines.push('');
  }

  if (scan.probes?.length) {
    const exposed = scan.probes.filter((p) => p.exposed);
    if (exposed.length) {
      lines.push('  📂 Exposed config/source files (usually 404, here served):');
      for (const p of exposed) {
        const n = p.findings.length ? `contains ${p.findings.length} secret(s)` : 'file content visible';
        lines.push(`     - ${p.url} [${p.status}, ${p.bytes}B] → ${n}`);
      }
      lines.push('');
    }
  }

  lines.push('  NEXT STEPS');
  lines.push('   1. Rotate every credential above — treat it as public NOW.');
  lines.push('   2. Move secrets to server-side env vars, never into JS bundles.');
  lines.push('   3. Add this to CI so it never regresses: npx vibe-locker --git');
  lines.push('');
  return lines.join('\n');
}
