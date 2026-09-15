#!/usr/bin/env node
// vibe-locker — find leaked API keys in vibe-coded sites and repos, before
// strangers do. Zero dependency. MIT.
//
//   vibe-locker https://situs-ai-anda.com        # crawl site, scan bundles
//   vibe-locker ./my-project                     # scan a folder
//   vibe-locker --git                            # scan tracked files here
//   vibe-locker <target> --json                  # machine output
//   vibe-locker https://x.com --no-crawl         # only page + config probes

import { readdirSync, statSync, readFileSync, existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { execFileSync } from 'node:child_process';
import { scanText } from './lib/scan-text.js';
import { crawlSite, probeConfigFiles } from './lib/crawl.js';
import { renderReport } from './lib/report.js';

const argv = process.argv.slice(2);
const flags = new Set(argv.filter((a) => a.startsWith('--')));

// subcommand: vibe-locker mcp — JSON-RPC stdio server for MCP hosts
if (argv[0] === 'mcp') {
  await import('./mcp/server.mjs');
} else {
  await run();
}

async function run() {
const target = argv.find((a) => !a.startsWith('--') && a !== 'mcp');

if (!target && !flags.has('--git')) {
  console.log(`vibe-locker — leaked-key detector for AI-built sites & repos

usage:
  vibe-locker https://your-ai-site.com     crawl site + probe config files
  vibe-locker ./path                       scan every source file in a folder
  vibe-locker --git                        scan files tracked by git (cwd)
  vibe-locker <target> --json              JSON output
  options: --no-crawl  --max-pages N  --show-all  --timeout S`);
  process.exit(target === undefined && argv.length ? 1 : 0);
}

// ---------- folder / git mode ----------
const EXT_OK = /(^|\/)\.env[\w.]*$|\.(js|jsx|ts|tsx|mjs|cjs|html|htm|css|json|md|py|rb|php|go|rs|java|sh|bash|txt|yml|yaml|toml|ini|conf|sql|vue|svelte|swift|kt|dart)$/i;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'vendor', '__pycache__', '.venv', 'target']);
const MAX_FILE = 2 * 1024 * 1024;

function isScannable(p) {
  const name = p.split(/[\\/]/).pop().toLowerCase();
  return /^\.env[\w.]*$/.test(name) ||
    /\.(js|jsx|ts|tsx|mjs|cjs|html|htm|css|json|md|py|rb|php|go|rs|java|sh|bash|txt|yml|yaml|toml|ini|conf|sql|vue|svelte|swift|kt|dart)$/.test(name);
}

function* walk(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) yield* walk(join(dir, e.name));
    } else if (e.isFile() && isScannable(e.name)) {
      yield join(dir, e.name);
    }
  }
}

function scanFolder(root) {
  const findings = [];
  let files = 0;
  for (const f of walk(root)) {
    try {
      const st = statSync(f);
      if (st.size > MAX_FILE || st.size === 0) continue;
      const text = readFileSync(f, 'utf8');
      files++;
      for (const fd of scanText(text)) findings.push({ ...fd, file: relative(root, f).split(sep).join('/') });
    } catch { /* unreadable */ }
  }
  return { findings, files };
}

function gitFiles() {
  return execFileSync('git', ['ls-files'], { encoding: 'utf8', maxBuffer: 32 << 20 }).split('\n').filter(Boolean);
}

if (flags.has('--git')) {
  const files = gitFiles().filter((f) => EXT_OK.test(f));
  const findings = [];
  for (const f of files) {
    try {
      const text = readFileSync(f, 'utf8');
      for (const fd of scanText(text)) findings.push({ ...fd, file: f });
    } catch { /* gone */ }
  }
  console.log(renderReport({ target: 'git: working tree', findings, files: files.length }, { json: flags.has('--json'), showAll: flags.has('--show-all') }));
  process.exit(findings.some((f) => f.sev === 'critical') ? 2 : 0);
}

if (/^https?:\/\//i.test(target)) {
  // ---------- web mode ----------
  const url = new URL(target);
  const all = [];
  let crawlInfo = { findings: [], requests: 0, checked: [] };

  if (!flags.has('--no-crawl')) {
    const maxPages = Number(argv[argv.indexOf('--max-pages') + 1] || 0) || 40;
    const timeoutMs = (Number(argv[argv.indexOf('--timeout') + 1] || 0) || 15) * 1000;
    crawlInfo = await crawlSite(url.href, {
      maxRequests: maxPages * 3,
      timeoutMs,
      onProgress: (n, u) => process.stderr.write(`\r  crawling… ${n} ${u.slice(0, 60)}          `),
    });
    process.stderr.write('\r\x1b[K');
    all.push(...crawlInfo.findings);
  }

  const probes = await probeConfigFiles(url.origin, {
    onProgress: (p) => process.stderr.write(`\r  probing… /${p.padEnd(20)}     `),
  });
  process.stderr.write('\r\x1b[K');
  for (const pr of probes) all.push(...pr.findings);

  const uniqByValue = [...new Map(all.map((f) => [f.value, f])).values()];
  console.log(
    renderReport(
      {
        target: url.href,
        findings: uniqByValue,
        requests: crawlInfo.requests + probes.length + 1,
        pages: (crawlInfo.checked || []).length,
        probes,
      },
      { json: flags.has('--json'), showAll: flags.has('--show-all') },
    ),
  );
  process.exit(uniqByValue.some((f) => f.sev === 'critical') ? 2 : 0);
}

// ---------- folder mode ----------
if (!existsSync(target)) {
  console.error(`not found: ${target}`);
  process.exit(1);
}
const { findings, files } = scanFolder(target);
console.log(renderReport({ target, findings, files }, { json: flags.has('--json'), showAll: flags.has('--show-all') }));
process.exit(findings.some((f) => f.sev === 'critical') ? 2 : 0);
}
