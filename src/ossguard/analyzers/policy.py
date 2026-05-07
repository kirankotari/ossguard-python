"""Org-wide security policy enforcement — define and check compliance rules."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ossguard.analyzers.dep_health import analyze_dependencies
from ossguard.detector import detect_project
from ossguard.parsers.dependencies import parse_dependencies


@dataclass
class PolicyRule:
    """A single policy rule to enforce."""

    id: str
    description: str
    severity: str = "error"  # "error", "warning", "info"
    passed: bool = False
    details: str = ""


@dataclass
class PolicyReport:
    """Policy compliance report."""

    policy_file: str = ""
    rules: list[PolicyRule] = field(default_factory=list)
    passed: int = 0
    failed: int = 0
    warnings: int = 0
    compliant: bool = False

    def to_json(self) -> str:
        return json.dumps(
            {
                "policy_file": self.policy_file,
                "compliant": self.compliant,
                "passed": self.passed,
                "failed": self.failed,
                "warnings": self.warnings,
                "rules": [
                    {
                        "id": r.id,
                        "description": r.description,
                        "severity": r.severity,
                        "passed": r.passed,
                        "details": r.details,
                    }
                    for r in self.rules
                ],
            },
            indent=2,
        )


# Default policy rules (used when no policy file is provided)
DEFAULT_POLICY = {
    "name": "OSSGuard Default Security Policy",
    "rules": {
        "require_security_md": {"severity": "error", "description": "SECURITY.md must exist"},
        "require_scorecard": {
            "severity": "warning",
            "description": "Scorecard workflow should be configured",
        },
        "require_dependabot": {"severity": "error", "description": "Dependabot must be configured"},
        "require_codeql": {"severity": "warning", "description": "CodeQL should be configured"},
        "require_sbom": {
            "severity": "warning",
            "description": "SBOM generation should be configured",
        },
        "require_sigstore": {"severity": "info", "description": "Release signing recommended"},
        "require_license": {"severity": "error", "description": "LICENSE file must exist"},
        "require_readme": {"severity": "error", "description": "README.md must exist"},
        "max_critical_vulns": {
            "severity": "error",
            "value": 0,
            "description": "No critical vulnerabilities allowed",
        },
        "max_high_vulns": {
            "severity": "warning",
            "value": 3,
            "description": "At most 3 high-severity vulnerabilities",
        },
        "min_health_score": {
            "severity": "warning",
            "value": 6.0,
            "description": "Minimum dependency health score of 6.0",
        },
    },
}


def check_policy(
    project_path: str | Path,
    policy_file: str | Path | None = None,
) -> PolicyReport:
    """Check a project against a security policy.

    Args:
        project_path: Path to the project.
        policy_file: Optional path to a JSON policy file. Uses defaults if not provided.

    Returns:
        PolicyReport with pass/fail for each rule.
    """
    path = Path(project_path).resolve()

    # Load policy
    if policy_file and Path(policy_file).exists():
        with open(policy_file) as f:
            policy = json.load(f)
        policy_path = str(policy_file)
    else:
        policy = DEFAULT_POLICY
        policy_path = "(default)"

    rules_config = policy.get("rules", {})

    # Gather project data
    info = detect_project(path)
    deps = parse_dependencies(path)
    dep_report = None
    if deps:
        dep_report = analyze_dependencies(deps, include_dev=False)

    # Check each rule
    rules: list[PolicyRule] = []

    for rule_id, config in rules_config.items():
        severity = config.get("severity", "error")
        description = config.get("description", rule_id)
        passed, details = _check_rule(rule_id, config, info, dep_report, path)

        rules.append(
            PolicyRule(
                id=rule_id,
                description=description,
                severity=severity,
                passed=passed,
                details=details,
            )
        )

    # Tally results
    passed_count = sum(1 for r in rules if r.passed)
    failed_errors = sum(1 for r in rules if not r.passed and r.severity == "error")
    warnings = sum(1 for r in rules if not r.passed and r.severity == "warning")
    compliant = failed_errors == 0

    return PolicyReport(
        policy_file=policy_path,
        rules=rules,
        passed=passed_count,
        failed=failed_errors + warnings,
        warnings=warnings,
        compliant=compliant,
    )


def generate_policy_template() -> str:
    """Generate a policy template file that users can customize."""
    return json.dumps(DEFAULT_POLICY, indent=2) + "\n"


def _check_rule(
    rule_id: str,
    config: dict,
    info,
    dep_report,
    path: Path,
) -> tuple[bool, str]:
    """Check a single policy rule. Returns (passed, details)."""

    if rule_id == "require_security_md":
        if info.has_security_md:
            return True, "SECURITY.md found"
        return False, "SECURITY.md not found"

    elif rule_id == "require_scorecard":
        if info.has_scorecard:
            return True, "Scorecard workflow found"
        return False, "Scorecard workflow not found"

    elif rule_id == "require_dependabot":
        if info.has_dependabot:
            return True, "Dependabot configured"
        return False, "Dependabot not configured"

    elif rule_id == "require_codeql":
        if info.has_codeql:
            return True, "CodeQL workflow found"
        return False, "CodeQL not configured"

    elif rule_id == "require_sbom":
        if info.has_sbom_workflow:
            return True, "SBOM workflow found"
        return False, "SBOM workflow not configured"

    elif rule_id == "require_sigstore":
        if info.has_sigstore:
            return True, "Sigstore signing configured"
        return False, "Sigstore signing not configured"

    elif rule_id == "require_license":
        for name in ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"]:
            if (path / name).exists():
                return True, f"Found {name}"
        return False, "No LICENSE file found"

    elif rule_id == "require_readme":
        for name in ["README.md", "README.rst", "README.txt", "README"]:
            if (path / name).exists():
                return True, f"Found {name}"
        return False, "No README found"

    elif rule_id == "max_critical_vulns":
        max_val = config.get("value", 0)
        if dep_report is None:
            return True, "No dependencies to check"
        actual = dep_report.critical_vulns
        if actual <= max_val:
            return True, f"{actual} critical vulns (max: {max_val})"
        return False, f"{actual} critical vulns exceed limit of {max_val}"

    elif rule_id == "max_high_vulns":
        max_val = config.get("value", 3)
        if dep_report is None:
            return True, "No dependencies to check"
        actual = dep_report.high_vulns
        if actual <= max_val:
            return True, f"{actual} high vulns (max: {max_val})"
        return False, f"{actual} high vulns exceed limit of {max_val}"

    elif rule_id == "min_health_score":
        min_val = config.get("value", 6.0)
        if dep_report is None:
            return True, "No dependencies to check"
        actual = dep_report.aggregate_score
        if actual >= min_val:
            return True, f"Health score {actual} (min: {min_val})"
        return False, f"Health score {actual} below minimum {min_val}"

    return True, "Rule not implemented"
