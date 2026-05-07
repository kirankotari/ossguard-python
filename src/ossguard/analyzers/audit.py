"""Comprehensive security audit — combines scan + deps + reach into one report."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ossguard.analyzers.dep_health import DepHealthReport, analyze_dependencies
from ossguard.analyzers.reach import ReachReport, analyze_reachability
from ossguard.detector import ProjectInfo, detect_project
from ossguard.parsers.dependencies import parse_dependencies


@dataclass
class AuditReport:
    """Full security audit combining all available analysis."""

    project_info: ProjectInfo | None = None
    dep_health: DepHealthReport | None = None
    reachability: ReachReport | None = None
    config_score: int = 0
    config_total: int = 6
    overall_grade: str = "F"
    findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    audit_time: str = ""

    @property
    def config_pct(self) -> int:
        if self.config_total == 0:
            return 0
        return int((self.config_score / self.config_total) * 100)

    def to_json(self) -> str:
        return json.dumps(
            {
                "audit_time": self.audit_time,
                "overall_grade": self.overall_grade,
                "config_score": f"{self.config_score}/{self.config_total}",
                "dep_health_score": self.dep_health.aggregate_score if self.dep_health else None,
                "total_vulns": self.dep_health.total_vulns if self.dep_health else 0,
                "reachable_vulns": self.reachability.reachable_vulns if self.reachability else 0,
                "noise_reduction": self.reachability.noise_reduction_pct
                if self.reachability
                else 0,
                "findings": self.findings,
                "recommendations": self.recommendations,
            },
            indent=2,
        )


def run_audit(project_path: str | Path) -> AuditReport:
    """Run a comprehensive security audit on a project.

    Combines:
    1. Configuration scan (SECURITY.md, Scorecard, Dependabot, CodeQL, SBOM, Sigstore)
    2. Dependency health analysis (OSV vulns + deps.dev metadata)
    3. Reachability filtering (static import analysis)

    Returns an AuditReport with findings, grade, and recommendations.
    """
    path = Path(project_path).resolve()
    report = AuditReport(audit_time=datetime.now(timezone.utc).isoformat())

    findings: list[str] = []
    recommendations: list[str] = []

    # Phase 1: Configuration scan
    info = detect_project(path)
    report.project_info = info

    checks = [
        info.has_security_md,
        info.has_scorecard,
        info.has_dependabot,
        info.has_codeql,
        info.has_sbom_workflow,
        info.has_sigstore,
    ]
    report.config_score = sum(checks)
    report.config_total = len(checks)

    if not info.has_security_md:
        findings.append("Missing SECURITY.md — no vulnerability disclosure policy")
        recommendations.append("Run `ossguard init` to add SECURITY.md")
    if not info.has_scorecard:
        findings.append("Missing Scorecard workflow — no automated security scoring")
        recommendations.append("Run `ossguard init` to add Scorecard CI")
    if not info.has_dependabot:
        findings.append("Missing Dependabot — no automated dependency updates")
        recommendations.append("Run `ossguard init` to add Dependabot config")
    if not info.has_codeql:
        findings.append("Missing CodeQL — no automated code scanning")
        recommendations.append("Run `ossguard init` to add CodeQL workflow")
    if not info.has_sbom_workflow:
        findings.append("Missing SBOM workflow — no bill of materials generation")
        recommendations.append("Run `ossguard init` to add SBOM workflow")
    if not info.has_sigstore:
        findings.append("Missing Sigstore — releases are not cryptographically signed")
        recommendations.append("Run `ossguard init` to add Sigstore signing")

    # Phase 2: Dependency health
    deps = parse_dependencies(path)
    if deps:
        dep_report = analyze_dependencies(deps, include_dev=False)
        report.dep_health = dep_report

        if dep_report.critical_vulns > 0:
            findings.append(f"{dep_report.critical_vulns} CRITICAL vulnerabilities in dependencies")
            recommendations.append("Immediately update packages with critical vulns")
        if dep_report.high_vulns > 0:
            findings.append(f"{dep_report.high_vulns} HIGH severity vulnerabilities")
            recommendations.append("Run `ossguard deps` for details and remediation")
        if dep_report.outdated_count > 0:
            findings.append(f"{dep_report.outdated_count} outdated dependencies")
            recommendations.append("Update outdated packages to latest versions")

        # Phase 3: Reachability
        reach_report = analyze_reachability(deps, path)
        report.reachability = reach_report

        if reach_report.filtered_vulns > 0:
            findings.append(
                f"{reach_report.filtered_vulns} vulnerabilities filtered (not imported)"
            )
    else:
        findings.append("No dependencies detected — skipping dependency analysis")

    # Calculate grade
    report.findings = findings
    report.recommendations = recommendations
    report.overall_grade = _calculate_grade(report)

    return report


def _calculate_grade(report: AuditReport) -> str:
    """Calculate overall security grade A-F."""
    score = 100.0

    # Config: up to 30 points
    config_pct = report.config_pct
    score -= (100 - config_pct) * 0.3

    # Vulns: up to 50 points
    if report.dep_health:
        if report.dep_health.critical_vulns > 0:
            score -= 30
        if report.dep_health.high_vulns > 0:
            score -= 15
        if report.dep_health.total_vulns > 5:
            score -= 5

        # Health score contribution
        health_deduction = (10 - report.dep_health.aggregate_score) * 2
        score -= health_deduction

    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    return "F"
