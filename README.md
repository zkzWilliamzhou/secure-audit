# SecureAudit - Browser Security Analyzer

[![npm version](https://img.shields.io/npm/v/secure-audit.svg)](https://npmjs.org/package/secure-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://img.shields.io/npm/dt/secure-audit.svg)](https://npmjs.com/package/secure-audit)

AI-powered AST security scanner for frontend JavaScript/TypeScript code. Zero config, privacy-preserving, CI/CD integrated.

## 🚀 Quick Start

```bash
npm install -g secure-audit
secure-audit scan ./src
```

## ✨ Features

- **AI-Driven AST Analysis**: Multi-layered security analysis
- **Supply Chain Protection**: Dependency risk detection
- **Privacy Audit**: PII leak prevention (GDPR/CCPA compliant)
- **CI/CD Native**: GitHub Actions, GitLab CI integration
- **Zero-Knowledge**: All analysis runs locally in browser sandbox

## 🛡️ Security Rules

| Category | Rules |
|----------|-------|
| XSS Prevention | 15 rules detecting unsafe DOM manipulation |
| Authentication | 8 rules for auth flow vulnerabilities |
| Data Privacy | 12 rules for PII detection and tracking |
| Supply Chain | 10 rules for dependency vulnerabilities |
| CSRF Protection | 5 rules for cross-site request forgery |

## 📊 Output Formats

- JSON (machine-readable)
- Markdown (developer-friendly)
- SARIF (CI/CD integration)
- HTML (interactive report)

## 🔧 CLI Usage

```bash
# Basic scan
secure-audit scan ./src

# With CI output
secure-audit scan ./src --format sarif --output report.sarif

# Fix auto-fixable issues
secure-audit fix ./src

# Custom rules
secure-audit scan ./src --rules ./custom-rules.json
```

## 🔄 GitHub Actions

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install -g secure-audit
      - run: secure-audit scan ./src --format sarif > audit.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: audit.sarif
```

## 🤖 AI Security Patterns

The tool uses locally-run WebAssembly models to learn:
- Project-specific security patterns
- Common vulnerability patterns
- False positive reduction

**Note**: All AI processing is done locally. No data leaves your machine.

## 📈 Performance

- **Speed**: 10,000+ lines/sec on modern hardware
- **Memory**: < 200MB peak usage
- **Cache**: Incremental analysis for fast CI

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐
│   CLI Entry     │────│  Rule Engine     │
│  (Commander)   │    │  (AST Walker)    │
└─────────────────┘    └──────────────────┘
         │                     │
         ▼                     ▼
┌─────────────────┐    ┌──────────────────┐
│   AST Parser    │────│  AI Analyzer     │
│  (Babel)        │    │  (WASM Model)    │
└─────────────────┘    └──────────────────┘
         │                     │
         ▼                     ▼
┌──────────────────────────────────────────┐
│           Output Generator               │
│  JSON | Markdown | SARIF | HTML         │
└──────────────────────────────────────────┘
```

## 🧪 Testing

```bash
npm test           # Run all tests
npm run test:unit  # Unit tests only
npm run test:security # Security rule tests
```

## 📦 Installation

```bash
# npm
npm install -g secure-audit

# Homebrew (macOS)
brew tap secure-audit/homebrew-secure-audit
brew install secure-audit

# Docker
docker run --rm -v $(pwd):/app secure-audit/scan /app/src
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Run tests: `npm test`
4. Submit a pull request

## 📄 License

MIT © 2026 SecureAudit Contributors

---

**Ready to secure your frontend code?**