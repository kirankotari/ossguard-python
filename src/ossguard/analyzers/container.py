"""Dockerfile security linting — detect insecure patterns in container builds."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ContainerFinding:
    """A single Dockerfile security finding."""

    file: str
    line_number: int
    rule_id: str
    severity: str  # "critical", "high", "medium", "low"
    description: str
    recommendation: str = ""


@dataclass
class ContainerReport:
    """Dockerfile security scan report."""

    findings: list[ContainerFinding] = field(default_factory=list)
    files_scanned: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    clean: bool = True


# Dockerfile lint rules
_RULES: list[tuple[str, str, str, str, str]] = [
    # (rule_id, severity, pattern, description, recommendation)
    # Image pinning
    (
        "DL-001",
        "high",
        r"^FROM\s+\S+:latest\b",
        "Using ':latest' tag — image not pinned to specific version",
        "Pin base image to a specific version or SHA digest",
    ),
    (
        "DL-002",
        "medium",
        r"^FROM\s+\S+\s*$",
        "FROM without tag — image defaults to :latest",
        "Specify a version tag (e.g., FROM python:3.12-slim)",
    ),
    (
        "DL-003",
        "high",
        r"^FROM\s+(?!.*@sha256:)\S+:\S+",
        "Image not pinned to SHA digest",
        "Consider pinning to SHA: FROM image@sha256:...",
    ),
    # Running as root
    (
        "DL-010",
        "high",
        r"^\s*USER\s+root\s*$",
        "Container runs as root user",
        "Use a non-root user: USER nonroot or USER 1000",
    ),
    # Secrets in build
    (
        "DL-020",
        "critical",
        r"(?:ARG|ENV)\s+\w*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\w*\s*=",
        "Secret value hardcoded in build argument or environment variable",
        "Use Docker secrets or mount secrets at runtime, never bake into image",
    ),
    (
        "DL-021",
        "high",
        r"(?:ARG|ENV)\s+\w*(?:AWS_ACCESS|AWS_SECRET|DATABASE_URL|REDIS_URL)\w*\s*=",
        "Cloud credentials or connection string in Dockerfile",
        "Pass credentials at runtime via environment variables or secrets manager",
    ),
    # Insecure practices
    (
        "DL-030",
        "medium",
        r"RUN\s+.*apt-get\s+.*install.*(?!--no-install-recommends)",
        "apt-get install without --no-install-recommends",
        "Use --no-install-recommends to minimize attack surface",
    ),
    (
        "DL-031",
        "medium",
        r"RUN\s+.*pip\s+install\s+(?!.*--no-cache-dir)",
        "pip install without --no-cache-dir",
        "Use --no-cache-dir to avoid caching packages in the image",
    ),
    (
        "DL-032",
        "high",
        r"RUN\s+.*curl\s+.*\|\s*(?:sh|bash)",
        "Piping curl output to shell — insecure remote code execution",
        "Download scripts first, verify checksums, then execute",
    ),
    (
        "DL-033",
        "high",
        r"RUN\s+.*wget\s+.*\|\s*(?:sh|bash)",
        "Piping wget output to shell — insecure remote code execution",
        "Download scripts first, verify checksums, then execute",
    ),
    (
        "DL-034",
        "medium",
        r"RUN\s+.*chmod\s+777\b",
        "Setting world-writable permissions (777)",
        "Use least-privilege permissions (e.g., 755 or 644)",
    ),
    (
        "DL-035",
        "low",
        r"RUN\s+.*apt-get\s+upgrade",
        "Using apt-get upgrade in Dockerfile",
        "Pin packages to specific versions instead of upgrading",
    ),
    # ADD vs COPY
    (
        "DL-040",
        "medium",
        r"^\s*ADD\s+(?!https?://)\S",
        "Using ADD for local files — COPY is preferred",
        "Use COPY instead of ADD for local files (ADD auto-extracts archives)",
    ),
    # HEALTHCHECK
    (
        "DL-050",
        "low",
        None,  # Checked separately (absence check)
        "No HEALTHCHECK instruction found",
        "Add HEALTHCHECK to enable container health monitoring",
    ),
    # .dockerignore
    (
        "DL-060",
        "medium",
        None,  # Checked separately
        "No .dockerignore file found",
        "Create .dockerignore to exclude .git, node_modules, secrets, etc.",
    ),
]


def scan_containers(project_path: str | Path) -> ContainerReport:
    """Scan Dockerfiles for security issues.

    Args:
        project_path: Path to the project.

    Returns:
        ContainerReport with findings.
    """
    path = Path(project_path).resolve()
    findings: list[ContainerFinding] = []
    files_scanned = 0

    # Find Dockerfiles
    dockerfiles = _find_dockerfiles(path)

    for df_path in dockerfiles:
        files_scanned += 1
        rel_path = str(df_path.relative_to(path))
        content = df_path.read_text()
        lines = content.splitlines()

        # Check each rule
        for rule_id, severity, pattern, desc, rec in _RULES:
            if pattern is None:
                continue
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    findings.append(
                        ContainerFinding(
                            file=rel_path,
                            line_number=i,
                            rule_id=rule_id,
                            severity=severity,
                            description=desc,
                            recommendation=rec,
                        )
                    )

        # Check for absence of HEALTHCHECK
        if not re.search(r"^\s*HEALTHCHECK\b", content, re.MULTILINE):
            findings.append(
                ContainerFinding(
                    file=rel_path,
                    line_number=0,
                    rule_id="DL-050",
                    severity="low",
                    description="No HEALTHCHECK instruction found",
                    recommendation="Add HEALTHCHECK to enable container health monitoring",
                )
            )

        # Check if running as root (no USER instruction)
        if not re.search(r"^\s*USER\b", content, re.MULTILINE):
            findings.append(
                ContainerFinding(
                    file=rel_path,
                    line_number=0,
                    rule_id="DL-010",
                    severity="high",
                    description="No USER instruction — container runs as root by default",
                    recommendation="Add USER nonroot or USER 1000 before CMD/ENTRYPOINT",
                )
            )

        # Check for multi-stage build (good practice)
        from_count = len(re.findall(r"^\s*FROM\b", content, re.MULTILINE))
        if from_count == 1:
            findings.append(
                ContainerFinding(
                    file=rel_path,
                    line_number=0,
                    rule_id="DL-070",
                    severity="low",
                    description="Single-stage build — consider multi-stage for smaller images",
                    recommendation="Use multi-stage builds to separate build and runtime stages",
                )
            )

    # Check .dockerignore
    if files_scanned > 0 and not (path / ".dockerignore").exists():
        findings.append(
            ContainerFinding(
                file=".dockerignore",
                line_number=0,
                rule_id="DL-060",
                severity="medium",
                description="No .dockerignore file found",
                recommendation="Create .dockerignore to exclude .git, node_modules, secrets, etc.",
            )
        )

    return ContainerReport(
        findings=findings,
        files_scanned=files_scanned,
        critical_count=sum(1 for f in findings if f.severity == "critical"),
        high_count=sum(1 for f in findings if f.severity == "high"),
        medium_count=sum(1 for f in findings if f.severity == "medium"),
        low_count=sum(1 for f in findings if f.severity == "low"),
        clean=len(findings) == 0,
    )


def _find_dockerfiles(path: Path) -> list[Path]:
    """Find all Dockerfiles in the project."""
    found = []
    candidates = [
        "Dockerfile",
        "Dockerfile.dev",
        "Dockerfile.prod",
        "Dockerfile.build",
        "Dockerfile.test",
        "docker/Dockerfile",
        "build/Dockerfile",
        "Containerfile",
    ]
    for name in candidates:
        full = path / name
        if full.exists():
            found.append(full)

    # Also check for Dockerfile.* pattern
    for f in path.iterdir():
        if f.is_file() and f.name.startswith("Dockerfile") and f not in found:
            found.append(f)

    return sorted(found)
