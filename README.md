# 🔍 VulnForge

**AI-guided web attack surface explorer & access control tester**

VulnForge is an intelligent security scanning tool that combines AI-powered decision-making with automated vulnerability detection to identify security issues in web applications. Think of it as having a security expert that crawls your application, understands attack patterns, and tests for vulnerabilities automatically.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-5.7+-blue)
![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)

## ✨ Features

### 🤖 AI-Powered Intelligence
- **Gemini AI Integration** - Free Google AI analyzes attack surfaces and suggests high-value security tests
- **Smart Action Planning** - AI prioritizes endpoints based on risk factors (admin paths, IDs, parameters)
- **Explainable Decisions** - Every action includes reasoning and expected signals

### 🕷️ Automated Crawling
- **Headless Browser** - Real Chrome automation via Playwright
- **Dynamic Discovery** - Finds pages, APIs, and endpoints through navigation and network monitoring
- **Multi-Context Testing** - Supports guest, userA, and userB authentication contexts

### 🔐 Vulnerability Detection
Actively tests for:
- **SQL Injection (SQLi)** - Error patterns, timing attacks
- **Cross-Site Scripting (XSS)** - Reflection detection
- **Broken Access Control (BAC/BOLA)** - Cross-user and cross-role testing
- **Insecure Direct Object References (IDOR)** - ID manipulation
- **Template Injection (SSTI/CSTI)** - Server & client-side
- **Remote Code Execution (RCE)** - Command injection patterns
- **Configuration Leaks** - Sensitive data exposure
- **Out-of-Band Attacks (OAST)** - External callback detection

### 📊 Real-Time Dashboard
- Attack surface visualization
- AI decision tracking
- Live findings with severity ratings
- Auth session management

## 🚀 Quick Start

### Prerequisites
- **Node.js** >= 18.0.0
- **npm** or **yarn**
- **Google Gemini API Key** (free from [Google AI Studio](https://makersuite.google.com/app/apikey))

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/vulnforge.git
cd vulnforge

# Install backend dependencies
npm install

# Install frontend dependencies
cd frontend
npm install
cd ..

# Install Playwright browsers
npx playwright install chromium
```

### Configuration

1. **Create environment files:**

```bash
# Root directory
cp .env.example .env

# Frontend directory
cp frontend/.env.example frontend/.env
```

2. **Edit `.env` with your credentials:**

```env
GEMINI_API_KEY=your_gemini_api_key_here
PORT=4000
VULNFORGE_API_KEY=generate_random_key_here
FRONTEND_ORIGIN=http://localhost:5173
```

3. **Edit `frontend/.env`:**

```env
VITE_API_BASE_URL=http://localhost:4000
VITE_VULNFORGE_API_KEY=same_as_backend_key_here
```

### Running the Application

**Terminal 1 - Backend:**
```bash
npm run dev
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

Access the dashboard at **http://localhost:5173**

## 📖 Usage Guide

### 1. Start a Scan
- Enter target URL (e.g., `https://your-test-app.com`)
- Click **"Start Scan"**
- Crawler explores as guest user and builds attack surface map

### 2. Configure Authentication (Optional)
- Log into target app as different users in separate browser
- Copy Cookie header values from DevTools
- Paste into userA/userB fields
- Click **"Save Auth Headers"**

### 3. AI Planning
- Click **"AI Plan Next Steps"**
- Gemini analyzes discovered endpoints
- Suggests intelligent attack actions with reasoning

### 4. Execute Tests
- Review AI-suggested actions
- Click **"Execute"** on high-risk actions
- Watch findings appear with technical evidence

### 5. Review Findings
- View vulnerabilities by type and severity
- Read AI explanations for context
- Export or save to Supabase (optional)

## 🛠️ Architecture

```
vulnforge/
├── src/                      # Backend source
│   ├── index.ts             # Express server & API routes
│   ├── config.ts            # Environment configuration
│   ├── types.ts             # TypeScript types
│   ├── crawler.ts           # Playwright-based web crawler
│   ├── scanOrchestrator.ts  # Scan session management
│   ├── aiOrchestrator.ts    # Gemini AI integration
│   ├── detectionEngine.ts   # Vulnerability testing logic
│   └── supabaseClient.ts    # Optional persistence
├── frontend/                 # React frontend
│   └── src/
│       ├── App.tsx          # Main dashboard UI
│       ├── api.ts           # Backend API client
│       └── styles.css       # UI styling
├── package.json             # Backend dependencies
└── tsconfig.json            # TypeScript config
```

## 🔧 Development

### Project Scripts

**Backend:**
```bash
npm run dev      # Start with hot-reload
npm run build    # Compile TypeScript
npm start        # Run compiled code
```

**Frontend:**
```bash
npm run dev      # Vite dev server
npm run build    # Production build
npm run preview  # Preview production build
```

### Tech Stack

**Backend:**
- Node.js + TypeScript
- Express.js
- Playwright (browser automation)
- Google Gemini AI
- Axios (HTTP client)
- Supabase (optional storage)

**Frontend:**
- React 18
- TypeScript
- Vite
- CSS3

## ⚠️ Legal & Ethics

**IMPORTANT:** This tool is for authorized security testing only.

- ✅ **DO:** Test your own applications
- ✅ **DO:** Get written permission before testing
- ✅ **DO:** Follow responsible disclosure
- ❌ **DON'T:** Scan sites without authorization
- ❌ **DON'T:** Use for malicious purposes

Unauthorized security testing may be **illegal** in your jurisdiction.

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📝 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Playwright** - Browser automation framework
- **Google Gemini** - AI-powered decision making
- **OWASP** - Security testing methodology
- **Supabase** - Optional backend storage

## 📧 Contact & Support

- **Issues:** [GitHub Issues](https://github.com/yourusername/vulnforge/issues)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/vulnforge/discussions)

## 🔮 Roadmap

- [ ] Database-backed scan history
- [ ] Custom payload library
- [ ] Report generation (PDF/HTML)
- [ ] Plugin system for custom checks
- [ ] WebSocket support for real-time updates
- [ ] Docker containerization
- [ ] CI/CD integration
- [ ] GraphQL endpoint testing

---

**Made with ❤️ by security enthusiasts**

⚡ Powered by AI • 🛡️ Built for Security • 🚀 Open Source
