# Security Policy

## Reporting a Vulnerability

The ossguard team takes security vulnerabilities seriously. We appreciate
your efforts to responsibly disclose your findings.

**Please DO NOT file a public issue for security vulnerabilities.**

### How to Report

- **Email**: [security@ossguard.dev](mailto:security@ossguard.dev)
- **GitHub Security Advisories**: Use [GitHub's private vulnerability reporting](https://github.com/OWNER/ossguard/security/advisories/new) to report a vulnerability directly.

### What to Include

Please include the following information in your report:

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Impact** assessment (what an attacker could achieve)
- **Affected versions**
- **Suggested fix** (if you have one)

### Response Timeline

- **Acknowledgment**: We will acknowledge receipt of your report within **48 hours**.
- **Assessment**: We will provide an initial assessment within **1 week**.
- **Fix & Disclosure**: We aim to release a fix within **90 days** of the report, following [coordinated vulnerability disclosure](https://github.com/ossf/oss-vulnerability-guide) practices.

### Coordinated Disclosure

We follow the [OpenSSF Vulnerability Disclosure Guide](https://github.com/ossf/oss-vulnerability-guide)
for coordinated disclosure. We request that you:

- Allow us reasonable time to fix the issue before public disclosure.
- Make a good faith effort to avoid privacy violations, data destruction, and
  service disruption.
- Do not exploit the vulnerability beyond what is necessary to confirm it.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Security Updates

Security updates will be released as patch versions and announced via:
- [GitHub Security Advisories](https://github.com/OWNER/ossguard/security/advisories)
- Release notes

## Security Best Practices

This project follows [OpenSSF Best Practices](https://www.bestpractices.dev/) and uses:
- [OpenSSF Scorecard](https://scorecard.dev/) for automated security assessment
- Dependency scanning via Dependabot/Renovate
- Code scanning via CodeQL or equivalent
- Signed releases via Sigstore

## Acknowledgments

We gratefully acknowledge security researchers who help keep ossguard safe.
Contributors will be credited in security advisories (unless anonymity is requested).
