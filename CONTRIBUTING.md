# Contributing to VulnForge

Thank you for your interest in contributing to VulnForge! 🎉

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow ethical security practices

## How to Contribute

### Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Use the bug report template**
3. **Include:**
   - Clear description of the issue
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Node version, etc.)
   - Screenshots if applicable

### Suggesting Features

1. **Check if feature already exists or is planned**
2. **Open a discussion** before starting work
3. **Explain:**
   - The problem it solves
   - How it fits with existing features
   - Potential implementation approach

### Pull Requests

#### Before You Start

1. **Fork the repository**
2. **Create a feature branch** from `main`
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Keep changes focused** - one feature per PR

#### Development Guidelines

**Code Style:**
- Use TypeScript for type safety
- Follow existing code formatting
- Use meaningful variable names
- Add comments for complex logic

**Testing:**
- Test your changes thoroughly
- Ensure existing functionality still works
- Test with different scan targets

**Commits:**
- Write clear, descriptive commit messages
- Use conventional commits format:
  ```
  feat: add SSRF detection
  fix: resolve crawler timeout issue
  docs: update installation guide
  refactor: improve AI prompt handling
  ```

#### Submitting Your PR

1. **Update documentation** if needed
2. **Run the application** to verify it works
3. **Write a clear PR description:**
   - What changes were made
   - Why they were made
   - How to test them
4. **Link related issues** using keywords (fixes #123)
5. **Be responsive** to review feedback

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/vulnforge.git
cd vulnforge

# Install dependencies
npm install
cd frontend && npm install && cd ..

# Install browsers
npx playwright install chromium

# Set up environment
cp .env.example .env
cp frontend/.env.example frontend/.env

# Start development
npm run dev                # Terminal 1
cd frontend && npm run dev # Terminal 2
```

### Areas That Need Help

- 🐛 **Bug Fixes** - Check the issues tab
- 📝 **Documentation** - Improve guides and examples
- 🧪 **Testing** - Add test coverage
- 🎨 **UI/UX** - Enhance dashboard design
- 🔍 **Detection Logic** - Add new vulnerability checks
- 🌐 **Localization** - Translate to other languages

### Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email details privately to the maintainers
2. Include steps to reproduce
3. Allow time for a fix before disclosure
4. We'll credit you in the security advisory

### Questions?

- 💬 **Discussions:** Ask questions in GitHub Discussions
- 📚 **Documentation:** Check the README and docs
- 💡 **Ideas:** Share in Discussions before coding

## Recognition

Contributors will be:
- Listed in the README
- Credited in release notes
- Given a shoutout on social media (if desired)

Thank you for making VulnForge better! 🚀
