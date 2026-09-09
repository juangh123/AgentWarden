import type { Rule, Finding } from './types.ts';
import { scanPatterns } from './utils.ts';

export const credentialRules: Rule[] = [
  {
    id: 'SEC-CRED-001',
    title: 'Sensitive Credential File Access',
    category: 'credential',
    severity: 'critical',
    description: 'Code or prompt attempts to access sensitive system files like SSH keys, AWS credentials, or .env files.',
    suggestion: 'Remove hardcoded access to user credential directories (~/.ssh, ~/.aws, .env).',
    check: (parsed): Finding[] => {
      const sensitivePatterns = [
        /(~|\$HOME|\/root|\/home\/\w+)\/.ssh\/(id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts)/i,
        /(~|\$HOME|\/root|\/home\/\w+)\/.aws\/(credentials|config)/i,
        /(~|\$HOME|\/root|\/home\/\w+)\/.gnupg\//i,
        /(~|\$HOME|\/root|\/home\/\w+)\/.kube\/config/i,
        /(^|[\s/])\.env($|[\s'"])/i,
      ];
      return scanPatterns(parsed, sensitivePatterns, {
        ruleId: 'SEC-CRED-001',
        category: 'credential',
        severity: 'critical',
        codeTitle: 'Sensitive Credential File Access (Code)',
        promptTitle: 'Sensitive Credential File Access (Prompt)',
        suggestion: 'Do not instruct agents to extract or read private keys (~/.ssh, ~/.aws, .env) in prompts or code.',
        description: (line, inCode) =>
          inCode
            ? `Detected access to private credential paths: "${line.trim()}"`
            : `Natural language instruction asks agent to access sensitive credentials: "${line.trim()}"`,
      });
    },
  },
  {
    id: 'SEC-CRED-002',
    title: 'Direct API Key / Secret Environment Variable Extraction',
    category: 'credential',
    severity: 'critical',
    description: 'Attempts to read high-privilege API keys directly from environment variables.',
    suggestion: 'Avoid reading or exporting sensitive API Keys directly in unconstrained scripts or prompts.',
    check: (parsed): Finding[] => {
      const envSecretPatterns = [
        /\b(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|SLACK_BOT_TOKEN|STRIPE_SECRET_KEY)\b/,
        /process\.env\.(ANTHROPIC|OPENAI|AWS|GITHUB|TOKEN|SECRET|KEY)/i,
        /export\s+(ANTHROPIC|OPENAI|AWS|GITHUB|TOKEN|SECRET|KEY)/i,
      ];
      return scanPatterns(parsed, envSecretPatterns, {
        ruleId: 'SEC-CRED-002',
        category: 'credential',
        severity: 'critical',
        codeTitle: 'High-Privilege Secret Environment Variable Access (Code)',
        promptTitle: 'High-Privilege Secret Environment Variable Access (Prompt)',
        suggestion: 'Do not expose platform API keys or credentials directly.',
        description: (line, inCode) =>
          inCode
            ? `Script references secret environment variables: "${line.trim()}"`
            : `Prompt instructs reading sensitive environment variable secrets: "${line.trim()}"`,
      });
    },
  },
  {
    id: 'SEC-CRED-003',
    title: 'Hardcoded API Tokens / Secret Keys',
    category: 'credential',
    severity: 'high',
    description: 'The skill embeds realistic-looking API tokens or secret keys that could be stolen or reused.',
    suggestion: 'Never hardcode real tokens. Use placeholders or environment variables referenced at runtime.',
    check: (parsed): Finding[] => {
      const tokenPatterns = [
        /\bAKIA[0-9A-Z]{16}\b/,
        /\b(ghp|gho|ghs|github_pat)_[0-9A-Za-z_]{20,}\b/,
        /\bsk(-proj)?-[0-9A-Za-z_-]{20,}\b/,
        /\bsk_live_[0-9a-zA-Z]{20,}\b/,
        /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
        /\bAIza[0-9A-Za-z_-]{35}\b/,
        /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b/,
        /\b(sqat|sq0csp|sq0idb)_[0-9A-Za-z_-]{20,}\b/,
      ];
      return scanPatterns(parsed, tokenPatterns, {
        ruleId: 'SEC-CRED-003',
        category: 'credential',
        severity: 'high',
        codeTitle: 'Hardcoded API Token / Secret Key (Code)',
        promptTitle: 'Hardcoded API Token / Secret Key (Prompt)',
        suggestion: 'Replace embedded secrets with placeholders or secure secret management (e.g. env vars).',
        description: (line) => `Detected realistic secret key material: "${line.trim()}"`,
      });
    },
  },
  {
    id: 'SEC-CRED-004',
    title: 'Embedded Private Key Material',
    category: 'credential',
    severity: 'critical',
    description: 'The skill embeds a full private key block (SSH, RSA, EC, PGP).',
    suggestion: 'Remove private key material entirely; reference keys by path or secret store instead.',
    check: (parsed): Finding[] => {
      const keyPatterns = [
        /-{5}BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY-{5}/,
        /-{5}BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY BLOCK-{5}/i,
      ];
      return scanPatterns(parsed, keyPatterns, {
        ruleId: 'SEC-CRED-004',
        category: 'credential',
        severity: 'critical',
        codeTitle: 'Embedded Private Key Material (Code)',
        promptTitle: 'Embedded Private Key Material (Prompt)',
        suggestion: 'Embedding private keys is a critical leak risk. Remove the block and load keys from a safe store.',
        description: (line) => `Found inline private key material: "${line.trim().slice(0, 80)}"`,
      });
    },
  },
];
