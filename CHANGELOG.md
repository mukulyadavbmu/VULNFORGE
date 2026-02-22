# Changelog

All notable changes to VulnForge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-22

### 🎉 Initial Release

#### Added
- **AI-Powered Security Scanning** with Google Gemini integration
- **Automated Web Crawling** using Playwright headless browser
- **Multi-Context Authentication** (guest, userA, userB) for access control testing
- **Vulnerability Detection** for 11+ attack types:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Broken Access Control (BAC/BOLA)
  - Insecure Direct Object References (IDOR)
  - Server-Side Template Injection (SSTI)
  - Client-Side Template Injection (CSTI)
  - Remote Code Execution (RCE)
  - Out-of-Band (OAST) vulnerabilities
  - Configuration leaks
  - Anomaly detection
  - Cross-role access issues
- **Real-Time Dashboard** with React + TypeScript
- **Attack Surface Mapping** with node and edge visualization
- **AI Decision Explanations** with risk scoring
- **Supabase Integration** for optional scan persistence
- **REST API** with Express.js backend
- **Environment Configuration** with Zod validation
- **Comprehensive Documentation** including:
  - README with quick start guide
  - CONTRIBUTING guidelines
  - SECURITY policy
  - CODE_OF_CONDUCT
  - MIT License

#### Technical Details
- TypeScript 5.7+ for type safety
- Node.js 18+ runtime
- Playwright for browser automation
- Google Gemini Pro for AI analysis
- Axios for HTTP requests
- Express.js REST API
- React 18 frontend
- Vite build system

---

## [Unreleased]

### Planned Features
- [ ] Database-backed scan history
- [ ] Custom payload library
- [ ] PDF/HTML report generation
- [ ] WebSocket real-time updates
- [ ] Plugin system for extensibility
- [ ] Docker containerization
- [ ] GraphQL endpoint testing
- [ ] YAML-based scan configurations
- [ ] Multiple AI provider support (OpenAI, Anthropic)
- [ ] Collaborative scanning features

---

## Version Notes

### Version Format
- **Major (1.x.x)**: Breaking changes, major features
- **Minor (x.1.x)**: New features, backwards compatible
- **Patch (x.x.1)**: Bug fixes, minor improvements

### Migration Guides
Migration guides for breaking changes will be provided in the releases section.

---

**Note:** For security updates and patches, see [SECURITY.md](SECURITY.md)
