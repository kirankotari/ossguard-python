"""OpenSSF Best Practices Badge helper — assess readiness and pre-fill answers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ossguard.detector import ProjectInfo, detect_project


@dataclass
class BadgeCriterion:
    """A single Best Practices Badge criterion."""

    id: str
    category: str
    question: str
    status: str = "unknown"  # "met", "unmet", "unknown", "not_applicable"
    evidence: str = ""
    suggestion: str = ""


@dataclass
class BadgeReport:
    """Best Practices Badge readiness assessment."""

    criteria: list[BadgeCriterion] = field(default_factory=list)
    met_count: int = 0
    unmet_count: int = 0
    unknown_count: int = 0
    readiness_pct: float = 0.0
    badge_url: str = "https://www.bestpractices.dev/"

    @property
    def is_ready(self) -> bool:
        return self.readiness_pct >= 100.0


# Best Practices Badge criteria we can auto-assess (subset of full criteria)
_CRITERIA = [
    # Basics
    ("basics_description", "Basics", "The project MUST have a description of what it does."),
    (
        "basics_interact",
        "Basics",
        "The project MUST provide a way for users to interact with developers.",
    ),
    ("basics_contribution", "Basics", "The project MUST have a contribution guide."),
    (
        "basics_license",
        "Basics",
        "The project MUST be released under an OSI-approved open source license.",
    ),
    # Change control
    (
        "change_public_repo",
        "Change Control",
        "The project MUST have a public version-controlled repository.",
    ),
    ("change_version_semver", "Change Control", "The project MUST use semantic versioning."),
    # Reporting
    (
        "report_vulnerability_process",
        "Reporting",
        "The project MUST have a vulnerability reporting process (SECURITY.md).",
    ),
    (
        "report_vulnerability_private",
        "Reporting",
        "The project MUST support private vulnerability reporting.",
    ),
    # Quality
    ("quality_tests", "Quality", "The project MUST have an automated test suite."),
    ("quality_ci", "Quality", "The project MUST use CI to run tests automatically."),
    # Security
    (
        "security_static_analysis",
        "Security",
        "The project MUST use at least one static analysis tool (e.g. CodeQL).",
    ),
    (
        "security_dependency_monitoring",
        "Security",
        "The project MUST monitor dependencies for known vulnerabilities.",
    ),
    (
        "security_hardened_dependencies",
        "Security",
        "Dependencies MUST be updated when vulnerabilities are found.",
    ),
    # Analysis
    ("analysis_scorecard", "Analysis", "The project SHOULD use OpenSSF Scorecard."),
    ("analysis_sbom", "Analysis", "The project SHOULD generate SBOMs."),
    ("analysis_signing", "Analysis", "The project SHOULD sign releases."),
]


def assess_badge_readiness(project_path: str | Path) -> BadgeReport:
    """Assess a project's readiness for the OpenSSF Best Practices Badge.

    Checks what can be auto-detected and provides suggestions for the rest.
    """
    path = Path(project_path).resolve()
    info = detect_project(path)
    criteria: list[BadgeCriterion] = []

    # Assess each criterion
    for crit_id, category, question in _CRITERIA:
        status, evidence, suggestion = _assess_criterion(crit_id, info, path)
        criteria.append(
            BadgeCriterion(
                id=crit_id,
                category=category,
                question=question,
                status=status,
                evidence=evidence,
                suggestion=suggestion,
            )
        )

    met = sum(1 for c in criteria if c.status == "met")
    unmet = sum(1 for c in criteria if c.status == "unmet")
    unknown = sum(1 for c in criteria if c.status == "unknown")
    readiness = (met / len(criteria) * 100) if criteria else 0.0

    return BadgeReport(
        criteria=criteria,
        met_count=met,
        unmet_count=unmet,
        unknown_count=unknown,
        readiness_pct=round(readiness, 1),
    )


def _assess_criterion(crit_id: str, info: ProjectInfo, path: Path) -> tuple[str, str, str]:
    """Assess a single criterion. Returns (status, evidence, suggestion)."""

    if crit_id == "basics_description":
        readme = path / "README.md"
        if readme.exists() and readme.stat().st_size > 100:
            return "met", "README.md exists with content", ""
        return "unmet", "", "Create a detailed README.md describing the project"

    elif crit_id == "basics_interact":
        # Check for issues URL, discussion, or contributing guide
        has_github = (path / ".github").is_dir()
        if has_github or (path / ".git").is_dir():
            return "met", "Git repository with potential issue tracking", ""
        return "unknown", "", "Ensure issue tracking is enabled on your repository"

    elif crit_id == "basics_contribution":
        for name in ["CONTRIBUTING.md", "CONTRIBUTING", ".github/CONTRIBUTING.md"]:
            if (path / name).exists():
                return "met", f"Found {name}", ""
        return "unmet", "", "Create a CONTRIBUTING.md with contribution guidelines"

    elif crit_id == "basics_license":
        for name in ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"]:
            if (path / name).exists():
                return "met", f"Found {name}", ""
        return "unmet", "", "Add a LICENSE file with an OSI-approved license"

    elif crit_id == "change_public_repo":
        if info.has_git:
            return "met", "Git repository detected", ""
        return "unmet", "", "Initialize a git repository: git init"

    elif crit_id == "change_version_semver":
        # Check pyproject.toml or package.json for version
        pyproject = path / "pyproject.toml"
        pkg_json = path / "package.json"
        if pyproject.exists():
            content = pyproject.read_text()
            if 'version = "' in content:
                return "met", "Version found in pyproject.toml", ""
        if pkg_json.exists():
            import json

            data = json.loads(pkg_json.read_text())
            if "version" in data:
                return "met", f"Version {data['version']} in package.json", ""
        return "unknown", "", "Ensure your project uses semantic versioning"

    elif crit_id == "report_vulnerability_process":
        if info.has_security_md:
            return "met", "SECURITY.md found", ""
        return "unmet", "", "Run `ossguard init` to create SECURITY.md"

    elif crit_id == "report_vulnerability_private":
        if info.has_security_md:
            return "met", "SECURITY.md includes private reporting instructions", ""
        return "unmet", "", "Enable GitHub Security Advisories for private reporting"

    elif crit_id == "quality_tests":
        test_dirs = ["tests", "test", "spec", "__tests__"]
        for td in test_dirs:
            if (path / td).is_dir():
                return "met", f"Test directory '{td}' found", ""
        if (path / "pytest.ini").exists() or (path / "jest.config.js").exists():
            return "met", "Test configuration found", ""
        return "unknown", "", "Add automated tests for your project"

    elif crit_id == "quality_ci":
        if info.has_github_actions:
            return "met", "GitHub Actions workflows found", ""
        for ci_file in [".travis.yml", ".circleci/config.yml", "Jenkinsfile", ".gitlab-ci.yml"]:
            if (path / ci_file).exists():
                return "met", f"CI config found: {ci_file}", ""
        return "unmet", "", "Set up CI (GitHub Actions recommended). Run `ossguard ci`"

    elif crit_id == "security_static_analysis":
        if info.has_codeql:
            return "met", "CodeQL workflow found", ""
        return "unmet", "", "Run `ossguard init` to add CodeQL workflow"

    elif crit_id == "security_dependency_monitoring":
        if info.has_dependabot:
            return "met", "Dependabot configuration found", ""
        return "unmet", "", "Run `ossguard init` to add Dependabot"

    elif crit_id == "security_hardened_dependencies":
        if info.has_dependabot:
            return "met", "Automated dependency updates configured", ""
        return "unmet", "", "Enable Dependabot or Renovate for automatic updates"

    elif crit_id == "analysis_scorecard":
        if info.has_scorecard:
            return "met", "Scorecard workflow found", ""
        return "unmet", "", "Run `ossguard init` to add Scorecard"

    elif crit_id == "analysis_sbom":
        if info.has_sbom_workflow:
            return "met", "SBOM workflow found", ""
        return "unmet", "", "Run `ossguard init` to add SBOM generation"

    elif crit_id == "analysis_signing":
        if info.has_sigstore:
            return "met", "Sigstore signing workflow found", ""
        return "unmet", "", "Run `ossguard init` to add Sigstore signing"

    return "unknown", "", ""
