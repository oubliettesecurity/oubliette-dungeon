# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | Yes                |

## Reporting a Vulnerability

If you discover a security vulnerability in oubliette-dungeon, please report it responsibly:

1. **Do NOT** open a public GitHub issue for security vulnerabilities.
2. Email security findings to: **security@oubliettesecurity.com**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Scope

This tool is designed for **authorized security testing** of LLM applications. It generates adversarial prompts intended to test AI safety guardrails.

**In scope:**
- Vulnerabilities in the oubliette-dungeon tool itself
- API authentication or authorization bypasses
- Injection vulnerabilities in the web dashboard or API
- Information disclosure in error messages or logs

**Out of scope:**
- The attack scenarios themselves (they are intentionally adversarial)
- Vulnerabilities in target systems being tested (report those to the target's maintainers)
- Social engineering of Oubliette Security staff

## Security Best Practices

When using oubliette-dungeon:

- Always set `DUNGEON_API_KEY` when exposing the API server
- Use HTTPS in production deployments
- Restrict network access to the API server
- Review results before sharing (they may contain sensitive prompts)
- Only test systems you have authorization to test
