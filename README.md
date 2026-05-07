# ossguard

**One CLI to guard any OSS project with OpenSSF security best practices — bootstrap, scan, and monitor.**

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/0000/badge)](https://www.bestpractices.dev/)

> *ossguard implements OpenSSF best practices and is intended for future contribution to the OpenSSF community.*

---

## The Problem

The [OpenSSF](https://openssf.org/) ecosystem has 30+ excellent tools, frameworks, and guides for securing open source software — Scorecard, Sigstore, SLSA, SBOM, CodeQL, Dependabot, and more.

But setting them all up manually takes **hours**. And once set up, there's no unified way to monitor your dependency health or track security posture over time.

**ossguard** solves this with a single CLI:

1. **Bootstrap** — set up all OpenSSF security configurations in one command
2. **Scan** — audit your project's security posture
3. **Deps** *(coming soon)* — analyze dependency health across Scorecard, OSV, and deps.dev

## Quick Start

```bash
# Install
pip install ossguard

# Bootstrap your project with all OpenSSF best practices
cd your-project
ossguard init

# Scan your project to see what's missing
ossguard scan
```

## What It Does

`ossguard init` auto-detects your project and creates:

| File | Purpose | OpenSSF Reference |
|------|---------|-------------------|
| `SECURITY.md` | Vulnerability disclosure policy | [CVD Guide](https://github.com/ossf/oss-vulnerability-guide) |
| `.github/workflows/scorecard.yml` | Automated security scoring | [Scorecard](https://scorecard.dev/) |
| `.github/dependabot.yml` | Dependency update automation | [Best Practices](https://best.openssf.org/) |
| `.github/workflows/codeql.yml` | Code scanning for vulnerabilities | [Security Tooling WG](https://github.com/ossf/wg-security-tooling) |
| `.github/workflows/sbom.yml` | Software Bill of Materials generation | [SBOM Everywhere](https://github.com/ossf/sbom-everywhere) |
| `.github/workflows/sigstore.yml` | Cryptographic signing of releases | [Sigstore](https://sigstore.dev/) |
| `.github/BRANCH_PROTECTION.md` | Branch protection setup guide | [SCM Best Practices](https://best.openssf.org/SCM-BestPractices/) |

## Features

### Auto-Detection
Automatically detects:
- **Languages**: Python, JavaScript/TypeScript, Go, Rust, Java, C/C++, Ruby, PHP, C#, and more
- **Package Managers**: npm, yarn, pnpm, pip, poetry, cargo, go modules, maven, gradle, etc.
- **Frameworks**: React, Vue, Angular, Next.js, Django, Flask, FastAPI, Express, etc.
- **Existing Security Setup**: Won't overwrite existing configurations

### Smart Defaults
- Scorecard workflow with weekly schedule and SARIF upload
- Dependabot configured for your specific ecosystems
- CodeQL with language-specific analysis and security-extended queries
- SBOM in both SPDX and CycloneDX formats
- Sigstore with Python-specific or generic cosign signing
- SECURITY.md following OpenSSF CVD best practices

### Commands

```bash
# Initialize with all defaults
ossguard init

# Specify a project path
ossguard init /path/to/project

# Set security contact email
ossguard init --email security@example.com

# Skip specific components
ossguard init --skip-scorecard --skip-codeql

# Preview without writing files
ossguard init --dry-run

# Overwrite existing files
ossguard init --force

# Scan and report current security posture
ossguard scan
```

## Supported Languages

| Language | CodeQL | Dependabot | Sigstore |
|----------|--------|------------|----------|
| Python | Yes | pip | Python-specific |
| JavaScript/TypeScript | Yes | npm | Generic (cosign) |
| Go | Yes | gomod | Generic (cosign) |
| Java/Kotlin | Yes | maven/gradle | Generic (cosign) |
| Rust | No | cargo | Generic (cosign) |
| C/C++ | Yes | N/A | Generic (cosign) |
| Ruby | Yes | bundler | Generic (cosign) |
| C# | Yes | nuget | Generic (cosign) |

## Development

```bash
# Clone and install
git clone https://github.com/ossguard/ossguard.git
cd ossguard
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check src/
```

## How It Relates to OpenSSF

This tool is **not** a replacement for any OpenSSF project. It's a **unifier** — it makes it trivially easy to adopt the best practices and tools that OpenSSF working groups have built:

- **Best Practices WG** → SECURITY.md template, Best Practices Badge tracking
- **Security Tooling WG** → CodeQL setup, SBOM generation
- **Supply Chain Integrity WG** → Sigstore signing, SLSA provenance
- **Vulnerability Disclosures WG** → CVD-compliant SECURITY.md
- **Securing Software Repos WG** → Dependabot, branch protection

## Roadmap

- [ ] `ossguard deps` — unified dependency health dashboard (Scorecard + OSV + deps.dev)
- [ ] Interactive mode with questionary prompts
- [ ] GitLab CI/CD support (in addition to GitHub Actions)
- [ ] SLSA provenance workflow generation
- [ ] OpenSSF Best Practices Badge auto-application
- [ ] Allstar configuration generation
- [ ] Pre-commit hooks for security linting
- [ ] Language-specific security linters (bandit, eslint-plugin-security, gosec)
- [ ] Renovate as an alternative to Dependabot
- [ ] SBOM drift detection between releases

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
