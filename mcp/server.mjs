// vibe-locker MCP server over stdio (JSON-RPC 2.0), zero dependency.
// Lets Claude Desktop / OpenCode / Cursor / Cline ask an agent to
// "scan this site/repo for leaked keys" instead of copy-pasting CLI output.
//
//   vibe-locker mcp
//   → { "mcpServers": { "vibe-locker": { "command": "npx", "args": ["-y","vibe-locker","mcp"] } } }

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, extname } from 'node:path';
import { scanText } from '../lib/scan-text.js';
import { probeConfigFiles, crawlSite } from '../lib/crawl.js';
import { renderReport } from '../lib/report.js';

const TOOLS = [
  {
    name: 'vibe_locker_scan_text',
    description: 'Scan a text block (code, config, .env paste) for leaked API keys/secrets. Returns findings with provider, severity, masked value, and fix advice. Never echoes full secrets.',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string', description: 'source/config text to scan' } },
      required: ['text'],
    },
  },
  {
    name: 'vibe_locker_scan_dir',
    description: 'Scan a local folder for files containing leaked secrets (source, configs, .env). Read-only. Good for "check my project before I push".',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path'],
    },
  },
  {
    name: 'vibe_locker_scan_url',
    description: 'Scan a live website: fetches the page, its JS bundles and sourcemaps, and probes common config paths (/.env, /config.json…) for leaked keys. Use only on sites you own or may test.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string' },
        maxPages: { type: 'number', default: 40, maximum: 200 },
      },
      required: ['url'],
    },
  },
];

const EXT_OK = /(^|\/)\.env[\w.]*$|\.(js|jsx|ts|tsx|mjs|cjs|html|htm|css|json|md|py|rb|php|go|rs|java|sh|bash|txt|yml|yaml|toml|ini|conf|sql|vue|svelte|swift|kt|dart)$/i;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'vendor', '__pycache__', '.venv', 'target', 'out', 'coverage', '.cache']);

function* walk(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) yield* walk(join(dir, e.name));
    } else if (e.isFile() && EXT_OK.test(e.name)) {
      yield join(dir, e.name);
    }
  }
}

async function callTool(name, args) {
  if (name === 'vibe_locker_scan_text') {
    const findings = scanText(String(args.text), { webSource: false });
    return { findings, total: findings.length, critical: findings.filter((f) => f.sev === 'critical').length };
  }
  if (name === 'vibe_locker_scan_dir') {
    if (!existsSync(args.path)) throw new Error('no such path: ' + args.path);
    const findings = [];
    let scanned = 0;
    for (const file of walk(args.path)) {
      let text;
      try { text = readFileSync(file, 'utf8'); } catch { continue; }
      scanned++;
      for (const f of scanText(text, { file, webSource: false })) findings.push(f);
    }
    const scan = { target: args.path, findings, files: scanned };
    return { filesScanned: scanned, findings, total: findings.length, report: renderReport(scan) };
  }
  if (name === 'vibe_locker_scan_url') {
    const maxPages = Math.min(200, Number(args.maxPages) || 40);
    const crawl = await crawlSite(args.url, { maxRequests: maxPages, timeoutMs: 15000 });
    const findings = [...crawl.findings];
    const probes = await probeConfigFiles(new URL(args.url).origin, { timeoutMs: 12000 });
    const exposed = probes.filter((h) => h.exposed);
    for (const h of exposed) for (const f of h.findings) findings.push(f);
    const scan = { target: args.url, findings, pages: crawl.checked.length, requests: crawl.requests };
    return {
      pagesChecked: crawl.checked.length,
      requests: crawl.requests,
      exposedConfigs: exposed.map((h) => ({ url: h.url, status: h.status, secrets: h.findings.length })),
      total: findings.length,
      critical: findings.filter((f) => f.sev === 'critical').length,
      report: renderReport(scan),
    };
  }
  throw new Error('unknown tool ' + name);
}

function send(msg) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...msg }) + '\n');
}
let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let nl;
  while ((nl = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    if (!line) continue;
    let req;
    try { req = JSON.parse(line); } catch { continue; }
    handle(req);
  }
});
let pending = 0;
process.stdin.on('end', () => {
  const drain = () => (pending === 0 ? process.exit(0) : setTimeout(drain, 20));
  drain();
});

function handle(req) {
  const { id, method, params } = req;
  if (method === 'initialize') {
    send({ id, result: {
      protocolVersion: params?.protocolVersion || '2025-03-26',
      capabilities: { tools: {} },
      serverInfo: { name: 'vibe-locker', version: '0.2.0' },
    } });
  } else if (method === 'tools/list') {
    send({ id, result: { tools: TOOLS } });
  } else if (method === 'tools/call') {
    pending++;
    Promise.resolve(callTool(params.name, params.arguments || {}))
      .then((result) => send({ id, result: { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] } }))
      .catch((e) => send({ id, result: { content: [{ type: 'text', text: 'error: ' + e.message }], isError: true } }))
      .finally(() => pending--);
  } else if (method === 'ping') {
    send({ id, result: {} });
  } else if (id !== undefined) {
    send({ id, error: { code: -32601, message: 'method not found' } });
  }
}
