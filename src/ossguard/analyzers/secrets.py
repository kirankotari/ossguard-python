"""Credential and secret scanner — detect leaked secrets in project files."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SecretFinding:
    """A single potential secret finding."""

    file: str
    line_number: int
    rule_id: str
    description: str
    severity: str  # "critical", "high", "medium", "low"
    match_preview: str = ""  # redacted preview of the match


@dataclass
class SecretsReport:
    """Report of secret scanning results."""

    findings: list[SecretFinding] = field(default_factory=list)
    files_scanned: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def clean(self) -> bool:
        return self.total == 0


# Secret detection rules: (id, description, pattern, severity)
_RULES: list[tuple[str, str, str, str]] = [
    # API Keys
    ("aws-access-key", "AWS Access Key ID",
     r'(?:AKIA)[0-9A-Z]{16}', "critical"),
    ("aws-secret-key", "AWS Secret Access Key",
     r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "critical"),
    ("gcp-api-key", "Google Cloud API Key",
     r'AIza[0-9A-Za-z\-_]{35}', "critical"),
    ("gcp-service-account", "Google Cloud Service Account Key",
     r'"type"\s*:\s*"service_account"', "critical"),
    ("azure-storage-key", "Azure Storage Account Key",
     r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}', "critical"),

    # Tokens
    ("github-token", "GitHub Personal Access Token",
     r'gh[ps]_[A-Za-z0-9_]{36,}', "critical"),
    ("github-fine-grained", "GitHub Fine-Grained Token",
     r'github_pat_[A-Za-z0-9_]{22,}', "critical"),
    ("gitlab-token", "GitLab Token",
     r'glpat-[A-Za-z0-9\-_]{20,}', "high"),
    ("slack-token", "Slack Token",
     r'xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}', "high"),
    ("slack-webhook", "Slack Webhook URL",
     r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24,}', "high"),
    ("npm-token", "npm Access Token",
     r'npm_[A-Za-z0-9]{36}', "critical"),
    ("pypi-token", "PyPI API Token",
     r'pypi-[A-Za-z0-9_\-]{100,}', "critical"),

    # Private Keys
    ("private-key-rsa", "RSA Private Key",
     r'-----BEGIN RSA PRIVATE KEY-----', "critical"),
    ("private-key-openssh", "OpenSSH Private Key",
     r'-----BEGIN OPENSSH PRIVATE KEY-----', "critical"),
    ("private-key-ec", "EC Private Key",
     r'-----BEGIN EC PRIVATE KEY-----', "critical"),
    ("private-key-pgp", "PGP Private Key Block",
     r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "high"),

    # Database / Connection strings
    ("database-url", "Database Connection String with Credentials",
     r'(?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^/\s]+', "high"),
    ("jdbc-password", "JDBC Connection with Password",
     r'jdbc:[a-z]+://[^\s]*password=[^\s&]+', "high"),

    # Generic patterns
    ("generic-secret-assignment", "Hardcoded Secret Assignment",
     r'(?:secret|password|passwd|token|api_key|apikey|api-key|access_key|auth_token|credentials)'
     r'\s*[=:]\s*["\'][A-Za-z0-9+/=_\-]{16,}["\']', "medium"),
    ("generic-bearer-token", "Hardcoded Bearer Token",
     r'[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*', "medium"),

    # Cloud / Infrastructure
    ("heroku-api-key", "Heroku API Key",
     r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', "low"),
    ("sendgrid-api-key", "SendGrid API Key",
     r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', "high"),
    ("stripe-key", "Stripe API Key",
     r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}', "critical"),
    ("twilio-key", "Twilio API Key",
     r'SK[0-9a-fA-F]{32}', "high"),
]

# File extensions to skip
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".pyc", ".pyo", ".class", ".o", ".obj",
    ".lock",  # lock files have hashes that trigger false positives
}

# Directories to skip
_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "venv", ".venv", "__pycache__",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".eggs", "*.egg-info", "target", ".gradle",
}

# Files to skip
_SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
    "go.sum", "poetry.lock", "Gemfile.lock", "composer.lock",
}


def scan_secrets(
    project_path: str | Path,
    include_low: bool = False,
) -> SecretsReport:
    """Scan project files for leaked secrets and credentials.

    Args:
        project_path: Path to the project.
        include_low: Include low-severity findings (may have more false positives).

    Returns:
        SecretsReport with all findings.
    """
    path = Path(project_path).resolve()
    findings: list[SecretFinding] = []
    files_scanned = 0

    # Compile rules
    compiled_rules = []
    for rule_id, desc, pattern, severity in _RULES:
        if not include_low and severity == "low":
            continue
        compiled_rules.append((rule_id, desc, re.compile(pattern), severity))

    # Load ignore file
    ignore_patterns = _load_ignore_file(path)

    for file_path in _walk_files(path):
        if file_path.name in _SKIP_FILES:
            continue
        if file_path.suffix.lower() in _SKIP_EXTENSIONS:
            continue

        rel_path = str(file_path.relative_to(path))

        # Check ignore patterns
        if any(re.search(p, rel_path) for p in ignore_patterns):
            continue

        try:
            content = file_path.read_text(errors="ignore")
        except Exception:
            continue

        files_scanned += 1

        for line_num, line in enumerate(content.splitlines(), 1):
            for rule_id, desc, pattern, severity in compiled_rules:
                if pattern.search(line):
                    # Redact the match for preview
                    preview = _redact_line(line.strip(), 80)
                    findings.append(SecretFinding(
                        file=rel_path,
                        line_number=line_num,
                        rule_id=rule_id,
                        description=desc,
                        severity=severity,
                        match_preview=preview,
                    ))

    # Deduplicate same rule on same file/line
    seen = set()
    deduped = []
    for f in findings:
        key = (f.file, f.line_number, f.rule_id)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    findings = deduped

    return SecretsReport(
        findings=findings,
        files_scanned=files_scanned,
        critical_count=sum(1 for f in findings if f.severity == "critical"),
        high_count=sum(1 for f in findings if f.severity == "high"),
        medium_count=sum(1 for f in findings if f.severity == "medium"),
        low_count=sum(1 for f in findings if f.severity == "low"),
    )


def _walk_files(path: Path) -> list[Path]:
    """Walk project files, skipping ignored directories."""
    files = []
    try:
        for item in sorted(path.iterdir()):
            if item.name in _SKIP_DIRS or item.name.startswith("."):
                if item.name in (".github", ".gitlab-ci.yml", ".env", ".npmrc"):
                    pass  # Still scan these
                else:
                    continue

            if item.is_file():
                files.append(item)
            elif item.is_dir():
                if item.name not in _SKIP_DIRS:
                    files.extend(_walk_files(item))
    except PermissionError:
        pass
    return files


def _redact_line(line: str, max_len: int = 80) -> str:
    """Redact sensitive portions of a line for display."""
    if len(line) > max_len:
        line = line[:max_len] + "..."

    # Replace long alphanumeric sequences (likely secrets) with redaction
    def redact_match(m: re.Match) -> str:
        s = m.group()
        if len(s) > 8:
            return s[:4] + "*" * (len(s) - 8) + s[-4:]
        return s

    return re.sub(r'[A-Za-z0-9+/=_\-]{16,}', redact_match, line)


def _load_ignore_file(path: Path) -> list[str]:
    """Load .ossguard-secrets-ignore patterns."""
    ignore_file = path / ".ossguard-secrets-ignore"
    if not ignore_file.exists():
        return []

    patterns = []
    for line in ignore_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns
