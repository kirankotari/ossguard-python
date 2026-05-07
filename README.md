# OSSGuard

**One CLI to guard any OSS project with OpenSSF security best practices — bootstrap, scan, and monitor.**

[![CI](https://github.com/kirankotari/ossguard/actions/workflows/ci.yml/badge.svg)](https://github.com/kirankotari/ossguard/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)

> *OSSGuard implements OpenSSF best practices and is intended for future contribution to the OpenSSF community.*

---

## The Problem

The [OpenSSF](https://openssf.org/) ecosystem has 30+ excellent tools, frameworks, and guides for securing open source software — Scorecard, Sigstore, SLSA, SBOM, CodeQL, Dependabot, and more.

But setting them all up manually takes **hours**. And once set up, there's no unified way to monitor dependency health, track compliance, or assess supply-chain risk.

**OSSGuard** solves this with **26 commands** covering the full security lifecycle:

1. **Bootstrap** — set up all OpenSSF security configurations in one command
2. **Analyze** — audit security posture, dependencies, vulnerabilities, and compliance
3. **Remediate** — auto-fix issues, generate reports, and enforce policies

## Quick Start

```bash
# Install
pip install ossguard

# Bootstrap your project with all OpenSSF best practices
cd your-project
ossguard init

# Scan your project to see what's missing
ossguard scan

# Run a full security audit
ossguard audit

# Check OSPS Baseline compliance
ossguard baseline
```

## Commands

### Core

| Command | Description |
|---------|-------------|
| `ossguard init` | Bootstrap OpenSSF security configs (SECURITY.md, Scorecard, Dependabot, CodeQL, SBOM, Sigstore, branch protection) |
| `ossguard scan` | Read-only security posture scan |
| `ossguard version` | Show version |

### Dependency Analysis

| Command | Description |
|---------|-------------|
| `ossguard deps` | Dependency health analysis — vulns (OSV), outdated packages, risk scores (deps.dev) |
| `ossguard drift` | SBOM diff between releases — detect added, removed, and changed dependencies |
| `ossguard watch` | Continuous vulnerability monitoring from an SBOM (post-deployment watch) |
| `ossguard tpn` | Generate third-party notices from project dependencies |

### Security Analysis

| Command | Description |
|---------|-------------|
| `ossguard audit` | Comprehensive security audit (scan + deps + reachability combined) |
| `ossguard reach` | Filter vulnerabilities by runtime reachability (static import analysis) |
| `ossguard secrets` | Scan for leaked credentials and secrets (24 detection rules) |

### Compliance & Frameworks

| Command | Description |
|---------|-------------|
| `ossguard baseline` | Check against OSPS Security Baseline (34 controls, Levels 1-3) |
| `ossguard badge` | Assess readiness for the OpenSSF Best Practices Badge |
| `ossguard slsa` | Assess SLSA Build Level (Levels 1-4, 12 requirements) |
| `ossguard maturity` | S2C2F supply chain maturity assessment (22 practices, Levels 1-4) |
| `ossguard license` | Dependency license compliance and conflict detection |
| `ossguard policy` | Org-wide security policy enforcement (JSON config) |

### Supply Chain

| Command | Description |
|---------|-------------|
| `ossguard supply-chain` | Malicious package detection + typosquatting analysis |
| `ossguard pin` | Pin GitHub Actions to commit SHAs (resolve tags to full SHAs) |
| `ossguard update` | Security-prioritized dependency update suggestions |

### Generation

| Command | Description |
|---------|-------------|
| `ossguard insights` | Generate or validate SECURITY-INSIGHTS.yml |
| `ossguard sbom-gen` | Generate local SBOM (SPDX 2.3 or CycloneDX 1.5) |
| `ossguard ci` | Generate unified CI security pipeline (GitHub Actions) |
| `ossguard report` | Export HTML or JSON compliance report |
| `ossguard fuzz` | Fuzzing readiness check + starter harness generation (7 languages) |

### Container & Comparison

| Command | Description |
|---------|-------------|
| `ossguard container` | Dockerfile security linting (12 rules) |
| `ossguard compare` | Side-by-side security posture comparison of two projects |
| `ossguard fix` | Auto-remediate common security issues |

## Auto-Detection

OSSGuard automatically detects:

- **Languages**: Python, JavaScript/TypeScript, Go, Rust, Java, C/C++, Ruby, PHP, C#
- **Package Managers**: npm, yarn, pnpm, pip, poetry, cargo, go modules, maven, gradle
- **Frameworks**: React, Vue, Angular, Next.js, Django, Flask, FastAPI, Express
- **Existing Security Setup**: Won't overwrite existing configurations

## What `ossguard init` Generates

| File | Purpose | OpenSSF Reference |
|------|---------|-------------------|
| `SECURITY.md` | Vulnerability disclosure policy | [CVD Guide](https://github.com/ossf/oss-vulnerability-guide) |
| `.github/workflows/scorecard.yml` | Automated security scoring | [Scorecard](https://scorecard.dev/) |
| `.github/dependabot.yml` | Dependency update automation | [Best Practices](https://best.openssf.org/) |
| `.github/workflows/codeql.yml` | Code scanning for vulnerabilities | [Security Tooling WG](https://github.com/ossf/wg-security-tooling) |
| `.github/workflows/sbom.yml` | Software Bill of Materials generation | [SBOM Everywhere](https://github.com/ossf/sbom-everywhere) |
| `.github/workflows/sigstore.yml` | Cryptographic signing of releases | [Sigstore](https://sigstore.dev/) |
| `.github/BRANCH_PROTECTION.md` | Branch protection setup guide | [SCM Best Practices](https://best.openssf.org/SCM-BestPractices/) |

## How It Relates to OpenSSF

OSSGuard is **not** a replacement for any OpenSSF project. It's a **unifier** — it makes it trivially easy to adopt the best practices and tools that OpenSSF working groups have built:

- **Best Practices WG** — SECURITY.md template, Best Practices Badge assessment
- **Security Tooling WG** — CodeQL setup, SBOM generation, secret scanning
- **Supply Chain Integrity WG** — Sigstore signing, SLSA assessment, S2C2F maturity
- **Vulnerability Disclosures WG** — CVD-compliant SECURITY.md
- **Securing Software Repos WG** — Dependabot, branch protection, GitHub Actions pinning
- **OSPS Baseline** — Automated compliance checking across maturity levels

## Development

```bash
# Clone and install
git clone https://github.com/kirankotari/ossguard.git
cd ossguard
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/ tests/
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
