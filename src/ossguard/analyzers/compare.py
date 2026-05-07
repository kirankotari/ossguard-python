"""Cross-project security comparison — compare security posture of two projects."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ossguard.analyzers.audit import AuditReport, run_audit


@dataclass
class CompareMetric:
    """A single comparison metric."""

    name: str
    project_a_value: str
    project_b_value: str
    winner: str = ""  # "a", "b", "tie", ""


@dataclass
class CompareReport:
    """Side-by-side comparison of two projects."""

    project_a_name: str = ""
    project_b_name: str = ""
    project_a_grade: str = "F"
    project_b_grade: str = "F"
    metrics: list[CompareMetric] = field(default_factory=list)
    winner: str = ""  # "a", "b", "tie"
    audit_a: AuditReport | None = None
    audit_b: AuditReport | None = None


def compare_projects(
    path_a: str | Path,
    path_b: str | Path,
) -> CompareReport:
    """Compare the security posture of two projects.

    Args:
        path_a: Path to the first project.
        path_b: Path to the second project.

    Returns:
        CompareReport with side-by-side metrics.
    """
    a_path = Path(path_a).resolve()
    b_path = Path(path_b).resolve()

    audit_a = run_audit(a_path)
    audit_b = run_audit(b_path)

    name_a = audit_a.project_info.repo_name if audit_a.project_info else a_path.name
    name_b = audit_b.project_info.repo_name if audit_b.project_info else b_path.name

    metrics: list[CompareMetric] = []

    # Overall Grade
    metrics.append(
        _compare_grades(
            "Overall Grade",
            audit_a.overall_grade,
            audit_b.overall_grade,
        )
    )

    # Config Score
    metrics.append(
        _compare_numeric(
            "Config Score",
            audit_a.config_score,
            audit_a.config_total,
            audit_b.config_score,
            audit_b.config_total,
            higher_is_better=True,
        )
    )

    # Dependency Health
    if audit_a.dep_health or audit_b.dep_health:
        a_score = audit_a.dep_health.aggregate_score if audit_a.dep_health else 0
        b_score = audit_b.dep_health.aggregate_score if audit_b.dep_health else 0
        metrics.append(
            CompareMetric(
                name="Dep Health Score",
                project_a_value=f"{a_score}/10",
                project_b_value=f"{b_score}/10",
                winner="a" if a_score > b_score else "b" if b_score > a_score else "tie",
            )
        )

        a_vulns = audit_a.dep_health.total_vulns if audit_a.dep_health else 0
        b_vulns = audit_b.dep_health.total_vulns if audit_b.dep_health else 0
        metrics.append(
            CompareMetric(
                name="Total Vulnerabilities",
                project_a_value=str(a_vulns),
                project_b_value=str(b_vulns),
                winner="a" if a_vulns < b_vulns else "b" if b_vulns < a_vulns else "tie",
            )
        )

        a_crit = audit_a.dep_health.critical_vulns if audit_a.dep_health else 0
        b_crit = audit_b.dep_health.critical_vulns if audit_b.dep_health else 0
        metrics.append(
            CompareMetric(
                name="Critical Vulns",
                project_a_value=str(a_crit),
                project_b_value=str(b_crit),
                winner="a" if a_crit < b_crit else "b" if b_crit < a_crit else "tie",
            )
        )

        a_deps = audit_a.dep_health.total_deps if audit_a.dep_health else 0
        b_deps = audit_b.dep_health.total_deps if audit_b.dep_health else 0
        metrics.append(
            CompareMetric(
                name="Total Dependencies",
                project_a_value=str(a_deps),
                project_b_value=str(b_deps),
                winner="",  # Neutral — fewer isn't necessarily better
            )
        )

    # Reachability
    if audit_a.reachability or audit_b.reachability:
        a_rv = audit_a.reachability.reachable_vulns if audit_a.reachability else 0
        b_rv = audit_b.reachability.reachable_vulns if audit_b.reachability else 0
        metrics.append(
            CompareMetric(
                name="Reachable Vulns",
                project_a_value=str(a_rv),
                project_b_value=str(b_rv),
                winner="a" if a_rv < b_rv else "b" if b_rv < a_rv else "tie",
            )
        )

    # Findings count
    a_findings = len(audit_a.findings)
    b_findings = len(audit_b.findings)
    metrics.append(
        CompareMetric(
            name="Findings",
            project_a_value=str(a_findings),
            project_b_value=str(b_findings),
            winner="a" if a_findings < b_findings else "b" if b_findings < a_findings else "tie",
        )
    )

    # Determine overall winner
    a_wins = sum(1 for m in metrics if m.winner == "a")
    b_wins = sum(1 for m in metrics if m.winner == "b")
    winner = "a" if a_wins > b_wins else "b" if b_wins > a_wins else "tie"

    return CompareReport(
        project_a_name=name_a,
        project_b_name=name_b,
        project_a_grade=audit_a.overall_grade,
        project_b_grade=audit_b.overall_grade,
        metrics=metrics,
        winner=winner,
        audit_a=audit_a,
        audit_b=audit_b,
    )


def _compare_grades(name: str, grade_a: str, grade_b: str) -> CompareMetric:
    """Compare letter grades."""
    grade_values = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
    va = grade_values.get(grade_a, 0)
    vb = grade_values.get(grade_b, 0)
    return CompareMetric(
        name=name,
        project_a_value=grade_a,
        project_b_value=grade_b,
        winner="a" if va > vb else "b" if vb > va else "tie",
    )


def _compare_numeric(
    name: str,
    a_val: int,
    a_total: int,
    b_val: int,
    b_total: int,
    higher_is_better: bool = True,
) -> CompareMetric:
    """Compare numeric scores."""
    a_pct = a_val / a_total * 100 if a_total else 0
    b_pct = b_val / b_total * 100 if b_total else 0

    if higher_is_better:
        winner = "a" if a_pct > b_pct else "b" if b_pct > a_pct else "tie"
    else:
        winner = "a" if a_pct < b_pct else "b" if b_pct < a_pct else "tie"

    return CompareMetric(
        name=name,
        project_a_value=f"{a_val}/{a_total} ({a_pct:.0f}%)",
        project_b_value=f"{b_val}/{b_total} ({b_pct:.0f}%)",
        winner=winner,
    )
