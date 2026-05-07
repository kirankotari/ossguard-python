"""Malicious package detection — check deps against known malicious packages and typosquatting."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ossguard.apis.osv import OSVClient
from ossguard.parsers.dependencies import Dependency, parse_dependencies


@dataclass
class SupplyChainFinding:
    """A single supply-chain risk finding."""

    package: str
    version: str
    ecosystem: str
    finding_type: str  # "malicious", "typosquat", "deprecated", "empty", "install_script"
    severity: str  # "critical", "high", "medium", "low"
    description: str
    evidence: str = ""


@dataclass
class SupplyChainReport:
    """Supply-chain risk assessment report."""

    findings: list[SupplyChainFinding] = field(default_factory=list)
    total_deps: int = 0
    malicious_count: int = 0
    typosquat_count: int = 0
    risk_count: int = 0
    clean: bool = True


# Well-known popular packages (for typosquatting detection)
_POPULAR_PACKAGES = {
    "npm": [
        "lodash",
        "express",
        "react",
        "vue",
        "angular",
        "axios",
        "moment",
        "webpack",
        "babel",
        "eslint",
        "prettier",
        "typescript",
        "jquery",
        "commander",
        "chalk",
        "inquirer",
        "minimist",
        "yargs",
        "debug",
        "uuid",
        "dotenv",
        "cors",
        "helmet",
        "jsonwebtoken",
        "bcrypt",
        "mongoose",
        "sequelize",
        "next",
        "nuxt",
        "gatsby",
        "svelte",
    ],
    "pypi": [
        "requests",
        "flask",
        "django",
        "numpy",
        "pandas",
        "scipy",
        "matplotlib",
        "tensorflow",
        "torch",
        "scikit-learn",
        "boto3",
        "pillow",
        "sqlalchemy",
        "celery",
        "redis",
        "fastapi",
        "uvicorn",
        "pydantic",
        "pytest",
        "black",
        "mypy",
        "ruff",
        "httpx",
        "cryptography",
        "paramiko",
        "beautifulsoup4",
        "scrapy",
    ],
}

# Known malicious name patterns
_MALICIOUS_PATTERNS = [
    (r"^@[a-z]+-pay(?:ment)?s?/", "Suspicious scoped payment package"),
    (r"-exec$", "Package name ending in -exec (common malicious pattern)"),
    (r"colors?\d+", "Suspicious color package variant"),
]


def check_supply_chain(
    project_path: str | Path,
    check_typosquats: bool = True,
    check_malicious: bool = True,
) -> SupplyChainReport:
    """Check dependencies for supply-chain risks.

    Args:
        project_path: Path to the project.
        check_typosquats: Check for typosquatting risks.
        check_malicious: Check against known malicious packages via OSV.

    Returns:
        SupplyChainReport with findings.
    """
    path = Path(project_path).resolve()
    deps = parse_dependencies(path)

    if not deps:
        return SupplyChainReport()

    findings: list[SupplyChainFinding] = []

    # 1. Check OSV for MAL- prefixed vulnerabilities (malicious packages)
    if check_malicious:
        _check_osv_malicious(deps, findings)

    # 2. Check for typosquatting risks
    if check_typosquats:
        _check_typosquats(deps, findings)

    # 3. Check for suspicious patterns
    _check_suspicious_patterns(deps, findings)

    # 4. Check for empty/minimal packages (placeholder squatting)
    _check_empty_packages(deps, findings)

    malicious = sum(1 for f in findings if f.finding_type == "malicious")
    typosquat = sum(1 for f in findings if f.finding_type == "typosquat")
    risk = sum(1 for f in findings if f.finding_type not in ("malicious", "typosquat"))

    return SupplyChainReport(
        findings=findings,
        total_deps=len(deps),
        malicious_count=malicious,
        typosquat_count=typosquat,
        risk_count=risk,
        clean=len(findings) == 0,
    )


def _check_osv_malicious(deps: list[Dependency], findings: list[SupplyChainFinding]) -> None:
    """Check OSV for MAL- prefixed vulnerability IDs (malicious packages)."""
    with OSVClient() as client:
        for dep in deps:
            vulns = client.query(dep.name, dep.version or "", dep.ecosystem)
            for vuln in vulns:
                # MAL- prefix indicates known malicious package
                if (
                    vuln.id.startswith("MAL-")
                    or vuln.id.startswith("PYSEC-")
                    and "malicious" in vuln.summary.lower()
                ):
                    findings.append(
                        SupplyChainFinding(
                            package=dep.name,
                            version=dep.version,
                            ecosystem=dep.ecosystem,
                            finding_type="malicious",
                            severity="critical",
                            description=f"Known malicious package: {vuln.summary}",
                            evidence=f"OSV: {vuln.id}",
                        )
                    )


def _check_typosquats(deps: list[Dependency], findings: list[SupplyChainFinding]) -> None:
    """Check if any dependencies are potential typosquats of popular packages."""
    for dep in deps:
        popular = _POPULAR_PACKAGES.get(dep.ecosystem, [])
        for pop_name in popular:
            if dep.name == pop_name:
                continue
            distance = _levenshtein_distance(dep.name.lower(), pop_name.lower())
            if 0 < distance <= 1 and len(dep.name) > 4:
                findings.append(
                    SupplyChainFinding(
                        package=dep.name,
                        version=dep.version,
                        ecosystem=dep.ecosystem,
                        finding_type="typosquat",
                        severity="high",
                        description=f"Name is similar to popular package '{pop_name}' (edit distance: {distance})",
                        evidence=f"Levenshtein distance to '{pop_name}': {distance}",
                    )
                )
                break  # Only report the closest match


def _check_suspicious_patterns(deps: list[Dependency], findings: list[SupplyChainFinding]) -> None:
    """Check for known suspicious naming patterns."""
    for dep in deps:
        for pattern, desc in _MALICIOUS_PATTERNS:
            if re.search(pattern, dep.name, re.IGNORECASE):
                findings.append(
                    SupplyChainFinding(
                        package=dep.name,
                        version=dep.version,
                        ecosystem=dep.ecosystem,
                        finding_type="suspicious",
                        severity="medium",
                        description=desc,
                        evidence=f"Matched pattern: {pattern}",
                    )
                )


def _check_empty_packages(deps: list[Dependency], findings: list[SupplyChainFinding]) -> None:
    """Flag packages with install scripts (potential for malicious post-install hooks)."""
    # This is a heuristic — we can't check package contents locally,
    # but we can flag npm packages with known risky patterns
    for dep in deps:
        if dep.ecosystem == "npm" and dep.name.startswith("@"):
            # Scoped packages from unknown orgs
            org = dep.name.split("/")[0]
            if len(org) <= 3:  # Very short org names are suspicious
                findings.append(
                    SupplyChainFinding(
                        package=dep.name,
                        version=dep.version,
                        ecosystem=dep.ecosystem,
                        finding_type="suspicious",
                        severity="low",
                        description=f"Very short scoped package org name: {org}",
                        evidence="Short org names may indicate placeholder squatting",
                    )
                )


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein (edit) distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]
