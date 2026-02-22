# Security Policy

## Reporting a Vulnerability

We take security seriously at VulnForge. If you discover a security vulnerability, please follow these steps:

### 🔒 Private Disclosure

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please email the details to:
- **Email:** [Your email address]
- **Subject:** [SECURITY] Vulnerability in VulnForge

### What to Include

Please provide:
- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Potential impact** and severity assessment
- **Suggested fix** (if you have one)
- **Your contact information** for follow-up

### Response Timeline

- **Initial Response:** Within 48 hours
- **Status Update:** Within 7 days
- **Fix Timeline:** Depends on severity
  - Critical: 1-3 days
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Best effort

### Recognition

We believe in recognizing security researchers:
- Credit in the security advisory (if desired)
- Mention in release notes
- Our sincere gratitude 🙏

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | ✅ Yes             |
| < 1.0   | ❌ No              |

## Security Best Practices

When using VulnForge:

### For Users
- ✅ Only scan applications you own or have permission to test
- ✅ Keep API keys secure and never commit to version control
- ✅ Use environment variables for sensitive configuration
- ✅ Review findings before sharing reports
- ❌ Never scan production systems without authorization
- ❌ Don't share scan results publicly without permission

### For Developers
- Use `.env` files (gitignored) for secrets
- Validate all user inputs
- Keep dependencies updated
- Review security advisories regularly
- Run scans in isolated environments

## Known Security Considerations

### Browser Automation
- Playwright launches headless Chrome which can execute JavaScript
- Scans visit real URLs and may trigger side effects
- Consider using sandboxed environments for untrusted targets

### AI Integration
- Gemini API calls include discovered URLs and parameters
- Data is sent to Google's servers for processing
- Review Google's privacy policy for AI services

### Network Requests
- The tool makes HTTP requests with various payloads
- Some tests may trigger security systems (WAF, IDS)
- Use responsibly and with proper authorization

## Vulnerability Types We Test

VulnForge is designed to detect:
- SQL Injection
- Cross-Site Scripting (XSS)
- Broken Access Control
- Insecure Direct Object References (IDOR)
- Template Injection
- Remote Code Execution
- Configuration Leaks
- Authentication Issues

## Updates & Patches

Security updates are released as soon as possible after discovery.

To stay updated:
- Watch this repository for releases
- Subscribe to security advisories
- Check the changelog regularly

## Legal Notice

This tool is for **authorized security testing only**. Unauthorized use may violate:
- Computer Fraud and Abuse Act (CFAA) in the US
- Computer Misuse Act in the UK
- Similar laws in other jurisdictions

Always obtain written permission before testing.

---

**Last Updated:** February 22, 2026
