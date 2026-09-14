// Registry signatures: provider, regex, severity, advice.
// Ordering matters: longest prefix first (sk-or-vi- before sk-).
export const SIGNATURES = [
  {
    id: 'openrouter',
    re: /\bsk-or-vi-[A-Za-z0-9_-]{32,}\b/g,
    sev: 'critical',
    provider: 'OpenRouter',
    advice: 'Revoke at openrouter.ai → Keys. Attackers drain shared credits fast.',
  },
  {
    id: 'anthropic',
    re: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/g,
    sev: 'critical',
    provider: 'Anthropic',
    advice: 'Revoke at console.anthropic.com. Client-side use = anyone can spend your balance.',
  },
  {
    id: 'openai-project',
    re: /\bsk-proj-[A-Za-z0-9_-]{16,}\b/g,
    sev: 'critical',
    provider: 'OpenAI',
    advice: 'Rotate at platform.openai.com → API keys. Set hard limits on the new key.',
  },
  {
    id: 'openai',
    re: /\bsk-[A-Za-z0-9_-]{32,}\b/g,
    sev: 'critical',
    provider: 'OpenAI-style key',
    advice: 'If this is a real key: rotate immediately; reseller/other providers share this shape too.',
  },
  {
    id: 'deepseek',
    re: /\bsk-[0-9a-f]{32}\b/g,
    sev: 'critical',
    provider: 'DeepSeek',
    advice: 'Rotate at platform.deepseek.com.',
  },
  {
    id: 'google',
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    sev: 'high',
    provider: 'Google API (Gemini/Maps/Firebase)',
    advice: 'Restrict by HTTP referrer + API, or rotate at console.cloud.google.com → Credentials.',
  },
  {
    id: 'groq',
    re: /\bgsk_[A-Za-z0-9]{32,}\b/g,
    sev: 'critical',
    provider: 'Groq',
    advice: 'Rotate at console.groq.com.',
  },
  {
    id: 'huggingface',
    re: /\bhf_[A-Za-z0-9]{34,}\b/g,
    sev: 'critical',
    provider: 'Hugging Face',
    advice: 'Rotate at huggingface.co/settings/tokens.',
  },
  {
    id: 'telegram-bot',
    re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g,
    sev: 'high',
    provider: 'Telegram bot token',
    advice: 'Anyone holding it controls your bot. Revoke via @BotFather /revoke.',
  },
  {
    id: 'stripe-live',
    re: /\bsk_live_[0-9a-zA-Z]{16,}\b/g,
    sev: 'critical',
    provider: 'Stripe secret (live)',
    advice: 'This is payment access. Roll immediately at dashboard.stripe.com → API keys.',
  },
  {
    id: 'stripe-pub',
    re: /\bpk_live_[0-9a-zA-Z]{16,}\b/g,
    sev: 'info',
    provider: 'Stripe publishable',
    advice: 'Publishable keys are designed to be client-side — fine to ship, just scope with restrictions.',
  },
  {
    id: 'aws',
    re: /\bAKIA[0-9A-Z]{16}\b/g,
    sev: 'critical',
    provider: 'AWS access key ID',
    advice: 'Deactivate in IAM now; check CloudTrail for usage you did not make.',
  },
  {
    id: 'github',
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b/g,
    sev: 'critical',
    provider: 'GitHub token',
    advice: 'Revoke at github.com/settings/tokens. It can rewrite your repos.',
  },
  {
    id: 'slack',
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    sev: 'high',
    provider: 'Slack token',
    advice: 'Revoke in Slack → Your apps.',
  },
  {
    id: 'discord-webhook',
    re: /\bhttps?:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g,
    sev: 'high',
    provider: 'Discord webhook',
    advice: 'Anyone can post as your bot. Delete + recreate the webhook.',
  },
  {
    id: 'elevenlabs',
    re: /\bsk_[A-Za-z0-9]{40,}\b/g,
    sev: 'high',
    provider: 'ElevenLabs (likely)',
    advice: 'Rotate at elevenlabs.io → Profile → API Keys.',
  },
  {
    id: 'private-key',
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    sev: 'critical',
    provider: 'Private key file',
    advice: 'Treat as compromised: generate a new keypair, purge from git history (git filter-repo).',
  },
  {
    id: 'jwt',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/g,
    sev: 'high',
    provider: 'JWT (looks signed)',
    advice: 'If this is a service-role/admin JWT it is a master key — rotate the signing secret.',
  },
];

// Generic assignment: name hints a secret, value is high-entropy → catches
// reseller providers we do not have a signature for (the b.ai/cavoti shapes!).
export const GENERIC = {
  id: 'generic-secret',
  re: /(?:^|[^a-zA-Z0-9])(api[_-]?key|apikey|api[_-]?secret|auth[_-]?token|access[_-]?token|client[_-]?secret|secret[_-]?key|password|passwd|token)["']?\s*[:=]\s*(["']?)([A-Za-z0-9+/=.:\-_]{14,})\2/gi,
  sev: 'high',
  provider: 'generic secret',
};
