# vibe-locker

**Find leaked API keys in vibe-coded websites before strangers do.**

You built a site with AI at 2am. It works. You deployed it.
Did you just ship your OpenAI key inside the JavaScript bundle?

```
$ vibe-locker https://your-ai-site.com

  🚨 [CRITICAL] OpenRouter — sk-or-vi-Ab3…xY9 (len 46)
      where : https://your-ai-site.com/assets/app.js (line 1)
      fix   : Revoke at openrouter.ai → Keys. Attackers drain shared credits fast.

  📂 Exposed config/source files (usually 404, here served):
     - https://your-ai-site.com/.env [200, 176B] → contains 2 secret(s)
```

The AI era generates millions of pages per day, and a huge share of them
leak `sk-…` keys, Discord webhooks, Telegram tokens, and `.env` files into
public bundles. Resellers and attackers run scrapers 24/7 on certificate
transparency logs. **This is the same scan, pointed at your own site, before
them.**

## What it detects

- **20+ provider signatures**: OpenAI, OpenRouter, Anthropic, DeepSeek, Groq,
  Google/Gemini, Hugging Face, ElevenLabs, Telegram bots, Stripe, AWS, GitHub,
  Slack, Discord webhooks, private-key blocks, JWTs
- **Generic high-entropy catch** for reseller/proxy keys with unknown shapes
  (the `API_KEY=*** ones)
- **Base64 obfuscation**: decodes long base64 string literals and rescans
- **Placeholder immunity**: `YOUR_KEY_HERE` style values are not findings —
  entropy + repetition + pattern checks kill the noise
- **Per-line allowlist**: append `vibe-locker:ignore` to any line (tests,
  fixtures) to skip it
- **Web crawler**: page → inline scripts → referenced bundles → source maps
- **Config probes**: 17 paths (`/.env`, `/config.json`, `/.git/config`, …)
  with content-based verification so SPA "404 pages" don't false-positive
- **Severity-aware context**: a token-shaped secret *inside a JS bundle* is
  escalated — it was meant for the server

## Usage

```bash
npx vibe-locker https://your-ai-site.com     # crawl site + probe config files
npx vibe-locker ./my-project                 # scan a folder
npx vibe-locker --git                        # scan tracked files (CI gate)
npx vibe-locker <target> --json              # machine-readable
```

### For AI agents (MCP)

Claude Desktop, OpenCode, Cursor, Cline — anything MCP speaks:

```json
{ "mcpServers": { "vibe-locker": { "command": "npx", "args": ["-y", "vibe-locker", "mcp"] } } }
```

Tools: `vibe_locker_scan_text` (paste a config/code block),
`vibe_locker_scan_dir` (check a project before pushing),
`vibe_locker_scan_url` (crawl a site you own). Values come back masked —
an agent can be told "fix the findings" without ever seeing the secret.

Exit code `2` when critical findings exist — wire it into CI:

```yaml
- run: npx vibe-locker --git   # fails the build on leaked keys
```

Zero dependencies. Node ≥ 18. Single file, auditable in one sitting.

## Design notes

- Every check is **static and local**: no traffic to any third party except
  the target you point at it.
- Secrets are **masked in output** (`sk-proj-HS…Raju`); `--json` masks too.
- It never sends your files anywhere. It reads what you tell it to read.

## Limitations (honest)

- Detection is signature + entropy based. A secret in a weird format, an
  encrypted blob, or a key built at runtime will slip through.
- It checks the public web surface you give it. It cannot know which key is
  "real" — rotate anything it flags.
- False negatives are the nature of pattern scanning. That is a trade for
  very low false positives, which is what makes CI gates usable.

## Security & disclosure

Scanning sites you do not own may be illegal in your jurisdiction. Default
behavior is single-origin, polite, rate-light crawling with an identifying
User-Agent. Point it at your own deployments.

## Contributing

New provider signature = one entry in `lib/keys.js` + one test case in
`test.js` (fake keys are runtime-generated sequences — never commit literals
that look like real credentials). `node test.js` must stay green. 30 tests.

## License

MIT
