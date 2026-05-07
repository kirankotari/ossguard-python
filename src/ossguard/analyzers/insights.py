"""Generate and validate SECURITY-INSIGHTS.yml per the OpenSSF Security Insights spec."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ossguard.detector import ProjectInfo, detect_project


@dataclass
class InsightsReport:
    """Result of insights generation or validation."""

    generated: bool = False
    valid: bool = False
    file_path: str = ""
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def generate_insights(project_path: str | Path) -> str:
    """Generate a SECURITY-INSIGHTS.yml file from auto-detected project data.

    Args:
        project_path: Path to the project.

    Returns:
        YAML string of the security-insights file.
    """
    path = Path(project_path).resolve()
    info = detect_project(path)

    # Build the insights structure
    insights: dict = {
        "header": {
            "schema-version": "1.0.0",
            "expiry-date": _one_year_from_now(),
            "last-updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "last-reviewed": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "commit-hash": _get_git_head(path),
            "project-url": f"https://github.com/{info.repo_name}" if info.repo_name != path.name else "",
            "changelog": _find_changelog_url(info, path),
        },
        "project-lifecycle": {
            "status": "active",
            "bug-fixes-only": False,
        },
        "contribution-policy": {
            "accepts-pull-requests": True,
            "accepts-automated-pull-requests": info.has_dependabot,
            "contributing-policy": _find_file_url(path, info, [
                "CONTRIBUTING.md", ".github/CONTRIBUTING.md"
            ]),
        },
        "documentation": {
            "README": _find_file_url(path, info, ["README.md"]),
        },
        "distribution-points": [],
        "security-artifacts": {},
        "security-assessments": [],
        "security-contacts": [],
        "security-testing": [],
        "vulnerability-reporting": {
            "accepts-vulnerability-reports": info.has_security_md,
            "security-policy": _find_file_url(path, info, [
                "SECURITY.md", ".github/SECURITY.md"
            ]),
        },
        "dependencies": {
            "third-party-packages": True,
            "dependencies-lists": _find_dep_files(path),
            "automated-dependency-management": {
                "enabled": info.has_dependabot,
            },
            "sbom": [],
        },
    }

    # Security testing
    testing = []
    if info.has_codeql:
        testing.append({
            "tool-type": "sast",
            "tool-name": "CodeQL",
            "tool-url": "https://codeql.github.com/",
            "integration": {"ci": True, "before-release": False},
        })
    if info.has_scorecard:
        testing.append({
            "tool-type": "scorecard",
            "tool-name": "OpenSSF Scorecard",
            "tool-url": "https://securityscorecards.dev/",
            "integration": {"ci": True, "before-release": False},
        })
    insights["security-testing"] = testing

    # Security artifacts
    artifacts = {}
    if info.has_security_md:
        artifacts["security-policy"] = _find_file_url(path, info, [
            "SECURITY.md", ".github/SECURITY.md"
        ])
    if info.has_sigstore:
        artifacts["signing"] = {"enabled": True, "tool": "Sigstore"}
    insights["security-artifacts"] = artifacts

    # SBOM
    if info.has_sbom_workflow:
        insights["dependencies"]["sbom"] = [{"sbom-type": "build", "sbom-format": "spdx"}]

    # Clean up empty values
    insights = _clean_dict(insights)

    return yaml.dump(insights, default_flow_style=False, sort_keys=False, allow_unicode=True)


def validate_insights(project_path: str | Path) -> InsightsReport:
    """Validate an existing SECURITY-INSIGHTS.yml file.

    Args:
        project_path: Path to the project.

    Returns:
        InsightsReport with validation results.
    """
    path = Path(project_path).resolve()
    report = InsightsReport()

    # Find the file
    candidates = [
        "SECURITY-INSIGHTS.yml", "security-insights.yml",
        ".github/SECURITY-INSIGHTS.yml", ".github/security-insights.yml",
    ]
    found = None
    for name in candidates:
        candidate = path / name
        if candidate.exists():
            found = candidate
            report.file_path = name
            break

    if not found:
        report.errors.append("No SECURITY-INSIGHTS.yml file found")
        return report

    # Parse YAML
    try:
        content = found.read_text()
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            report.errors.append("File does not contain a valid YAML mapping")
            return report
    except yaml.YAMLError as e:
        report.errors.append(f"YAML parse error: {e}")
        return report

    # Required fields
    required_sections = ["header", "project-lifecycle", "vulnerability-reporting"]
    for section in required_sections:
        if section not in data:
            report.errors.append(f"Missing required section: {section}")

    # Header validation
    header = data.get("header", {})
    if "schema-version" not in header:
        report.errors.append("Missing header.schema-version")
    if "expiry-date" not in header:
        report.warnings.append("Missing header.expiry-date")
    if "last-updated" not in header:
        report.warnings.append("Missing header.last-updated")

    # Vulnerability reporting
    vuln = data.get("vulnerability-reporting", {})
    if "accepts-vulnerability-reports" not in vuln:
        report.errors.append("Missing vulnerability-reporting.accepts-vulnerability-reports")

    # Project lifecycle
    lifecycle = data.get("project-lifecycle", {})
    if "status" not in lifecycle:
        report.warnings.append("Missing project-lifecycle.status")

    report.valid = len(report.errors) == 0
    return report


def _one_year_from_now() -> str:
    now = datetime.now(timezone.utc)
    try:
        expiry = now.replace(year=now.year + 1)
    except ValueError:
        expiry = now.replace(year=now.year + 1, day=28)
    return expiry.strftime("%Y-%m-%dT%H:%M:%SZ")


def _get_git_head(path: Path) -> str:
    head_file = path / ".git" / "HEAD"
    if head_file.exists():
        content = head_file.read_text().strip()
        if content.startswith("ref:"):
            ref_path = path / ".git" / content[5:].strip()
            if ref_path.exists():
                return ref_path.read_text().strip()[:40]
        elif len(content) == 40:
            return content
    return ""


def _find_changelog_url(info: ProjectInfo, path: Path) -> str:
    for name in ["CHANGELOG.md", "CHANGES.md", "HISTORY.md"]:
        if (path / name).exists():
            return name
    return ""


def _find_file_url(path: Path, info: ProjectInfo, candidates: list[str]) -> str:
    for name in candidates:
        if (path / name).exists():
            return name
    return ""


def _find_dep_files(path: Path) -> list[str]:
    dep_files = []
    candidates = [
        "package.json", "requirements.txt", "pyproject.toml", "go.mod",
        "Cargo.toml", "pom.xml", "composer.json", "Gemfile",
    ]
    for name in candidates:
        if (path / name).exists():
            dep_files.append(name)
    return dep_files


def _clean_dict(d: dict) -> dict:
    """Remove empty values recursively."""
    cleaned = {}
    for k, v in d.items():
        if isinstance(v, dict):
            v = _clean_dict(v)
            if v:
                cleaned[k] = v
        elif isinstance(v, list):
            if v:
                cleaned[k] = v
        elif v is not None and v != "":
            cleaned[k] = v
    return cleaned
